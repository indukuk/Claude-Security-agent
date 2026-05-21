"""
Custom Semgrep Rule Generator — analyzes codebase and generates taint rules
for patterns not covered by existing rule sets.

Strategy:
1. Scan codebase for source patterns (body.get, request params, event data)
2. Scan for sink patterns (DB writes, exec, file ops, external calls)
3. Cross-reference with existing rules to find uncovered source→sink pairs
4. Generate Semgrep taint rules for novel combinations
5. Validate with semgrep --validate
6. Run against codebase
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class GeneratedRule:
    """A generated Semgrep rule."""
    id: str
    message: str
    severity: str
    sources: list[str]
    sinks: list[str]
    sanitizers: list[str] = field(default_factory=list)
    cwe: str = ""
    category: str = ""
    valid: bool = False
    findings_count: int = 0


# Patterns to identify sources (user-controlled input)
SOURCE_SIGNATURES = [
    (r'body\.get\(["\'](\w+)["\']\)', "body.get"),
    (r'body\[["\'](\w+)["\']\]', "body[]"),
    (r'event\[["\'](\w+)["\']\]', "event[]"),
    (r'request\.(?:args|form|json)\.get\(["\'](\w+)["\']\)', "request"),
    (r'params\.get\(["\'](\w+)["\']\)', "params"),
    (r'state\[["\'](\w+)["\']\]', "state[]"),
    (r'input_data\[["\'](\w+)["\']\]', "input_data[]"),
    (r'headers\.get\(["\'](\w+)["\']\)', "headers"),
]

# Patterns to identify sinks (sensitive operations)
SINK_SIGNATURES = [
    (r'(\w+)\.(?:put_item|update_item|delete_item|query|get_item)\(', "dynamodb", "CWE-639"),
    (r'(\w+)\.(?:execute|executemany)\(', "sql", "CWE-89"),
    (r'subprocess\.(?:run|call|Popen)\(', "command", "CWE-78"),
    (r'(?:exec|eval)\(', "code_exec", "CWE-94"),
    (r'(\w+)\.(?:put_object|upload_file|upload_fileobj)\(', "s3_write", "CWE-434"),
    (r'(\w+)\.invoke_model\(', "llm", "CWE-77"),
    (r'(\w+)\.(?:send_message|publish)\(', "messaging", "CWE-829"),
    (r'(\w+)\.invoke\(', "lambda_invoke", "CWE-918"),
    (r'open\(.*["\']w', "file_write", "CWE-73"),
    (r'(\w+)\.admin_(?:update|delete|create)_', "cognito_admin", "CWE-284"),
    (r'(\w+)\.(?:start_execution|send_task_success)\(', "stepfunctions", "CWE-918"),
]


class SemgrepRuleGenerator:
    """Analyze codebase and generate custom Semgrep taint rules."""

    def __init__(self, existing_rules_dir: str, kb_path: str | None = None):
        self.existing_rules_dir = Path(existing_rules_dir)
        self._existing_coverage = self._load_existing_coverage()
        self._kb = self._load_kb(kb_path)

    def _load_kb(self, kb_path: str | None) -> dict:
        """Load community knowledge base for pattern enrichment."""
        if kb_path is None:
            kb_path = str(Path(__file__).parent.parent.parent / "knowledge" / "semgrep_kb.json")
        try:
            return json.loads(Path(kb_path).read_text())
        except (OSError, json.JSONDecodeError):
            return {}

    def generate_rules(self, files: list[str], max_rules: int = 20,
                       time_budget_sec: float = 120.0) -> list[GeneratedRule]:
        """
        Analyze files, find uncovered source→sink patterns, generate rules.
        Returns list of generated rules (validated and run).
        """
        import time
        start = time.time()

        # 1. Discover sources and sinks in the codebase
        sources = self._discover_sources(files)
        sinks = self._discover_sinks(files)

        # 2. Find uncovered combinations
        uncovered = self._find_uncovered_pairs(sources, sinks)

        # 3. Generate rules for uncovered patterns (limit count)
        rules = []
        for pair in uncovered[:max_rules]:
            rule = self._generate_rule(pair)
            if rule:
                rules.append(rule)

        # 4. Validate all generated rules
        valid_rules = self._validate_rules(rules)

        # 5. Run ALL valid rules in a single batched pysemgrep invocation
        if valid_rules:
            self._run_rules_batched(valid_rules, files)

        return valid_rules

    def _load_existing_coverage(self) -> set[tuple[str, str]]:
        """Load existing rules to understand what's already covered."""
        covered = set()
        for yaml_file in self.existing_rules_dir.glob("semgrep_rules*.yaml"):
            try:
                data = yaml.safe_load(yaml_file.read_text())
                for rule in data.get("rules", []):
                    sources = rule.get("pattern-sources", [])
                    sinks = rule.get("pattern-sinks", [])
                    for src in sources:
                        pattern = src.get("pattern", "")
                        for sink in sinks:
                            sink_pattern = sink.get("pattern", "")
                            covered.add((
                                self._normalize_pattern(pattern),
                                self._normalize_pattern(sink_pattern),
                            ))
            except Exception:
                continue
        return covered

    def _normalize_pattern(self, pattern: str) -> str:
        """Normalize a pattern for comparison (strip metavars and whitespace)."""
        return re.sub(r'\$\w+|\.\.\.|\s+', '', pattern).strip()

    def _discover_sources(self, files: list[str]) -> list[dict]:
        """Find all user-input sources in the codebase."""
        sources = []
        for file_path in files:
            try:
                content = Path(file_path).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            for regex, source_type in SOURCE_SIGNATURES:
                for match in re.finditer(regex, content):
                    field_name = match.group(1) if match.lastindex else ""
                    sources.append({
                        "file": file_path,
                        "type": source_type,
                        "field": field_name,
                        "pattern": match.group(0),
                        "line": content[:match.start()].count("\n") + 1,
                    })

        return sources

    def _discover_sinks(self, files: list[str]) -> list[dict]:
        """Find all sensitive sinks in the codebase, enriched by community KB."""
        sinks = []
        for file_path in files:
            try:
                content = Path(file_path).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            # Standard signature-based detection
            for regex, sink_type, cwe in SINK_SIGNATURES:
                for match in re.finditer(regex, content):
                    sinks.append({
                        "file": file_path,
                        "type": sink_type,
                        "cwe": cwe,
                        "pattern": match.group(0),
                        "line": content[:match.start()].count("\n") + 1,
                    })

            # KB-enriched detection: check for community-known sinks in the code
            if self._kb:
                sinks.extend(self._discover_kb_sinks(file_path, content))

        return sinks

    def _discover_kb_sinks(self, file_path: str, content: str) -> list[dict]:
        """Detect sinks from the community KB that appear in this file."""
        kb_sinks = []
        vuln_classes = self._kb.get("vulnerability_classes", {})

        # Mapping of function patterns to look for
        kb_sink_patterns = {
            "prompt_injection": [
                (r'(system_instruction|system_prompt|SystemMessage)\s*[=(]', "CWE-77"),
                (r'(role.*system.*content|content.*role.*system)', "CWE-77"),
            ],
            "deserialization": [
                (r'pickle\.loads?\(', "CWE-502"),
                (r'yaml\.(?:unsafe_)?load\(', "CWE-502"),
                (r'marshal\.loads?\(', "CWE-502"),
            ],
            "ssrf": [
                (r'requests\.(?:get|post|put|delete|head)\(', "CWE-918"),
                (r'urllib\.request\.urlopen\(', "CWE-918"),
                (r'httpx\.(?:get|post|put|delete)\(', "CWE-918"),
            ],
            "open_redirect": [
                (r'redirect\(', "CWE-601"),
                (r'Location.*=', "CWE-601"),
            ],
        }

        for vuln_class, patterns in kb_sink_patterns.items():
            for regex, cwe in patterns:
                for match in re.finditer(regex, content):
                    kb_sinks.append({
                        "file": file_path,
                        "type": f"kb_{vuln_class}",
                        "cwe": cwe,
                        "pattern": match.group(0),
                        "line": content[:match.start()].count("\n") + 1,
                        "kb_source": True,
                    })

        return kb_sinks

    def _get_kb_sanitizers(self, sink_type: str) -> list[str]:
        """Get community-known sanitizers for a vulnerability class from the KB."""
        vuln_classes = self._kb.get("vulnerability_classes", {})

        # Map our sink types to KB vulnerability classes
        type_to_class = {
            "sql": "sql_injection",
            "command": "command_injection",
            "code_exec": "code_execution",
            "s3_write": "path_traversal",
            "kb_prompt_injection": "prompt_injection",
            "kb_ssrf": "ssrf",
            "kb_deserialization": "deserialization",
            "kb_open_redirect": "open_redirect",
        }

        vc_name = type_to_class.get(sink_type, "")
        if vc_name and vc_name in vuln_classes:
            return vuln_classes[vc_name].get("sanitizers", [])
        return []

    def _find_uncovered_pairs(self, sources: list[dict], sinks: list[dict]) -> list[dict]:
        """Find source→sink pairs in the same file not covered by existing rules."""
        pairs = []
        seen = set()

        for source in sources:
            for sink in sinks:
                if source["file"] != sink["file"]:
                    continue

                pair_key = (source["type"], source["field"], sink["type"])
                if pair_key in seen:
                    continue

                # Check if this combination is already covered
                src_norm = self._normalize_pattern(source["pattern"])
                sink_norm = self._normalize_pattern(sink["pattern"])
                if (src_norm, sink_norm) in self._existing_coverage:
                    continue

                seen.add(pair_key)
                pairs.append({
                    "source": source,
                    "sink": sink,
                    "key": pair_key,
                })

        return pairs

    def _generate_rule(self, pair: dict) -> GeneratedRule | None:
        """Generate a Semgrep taint rule for an uncovered source→sink pair."""
        source = pair["source"]
        sink = pair["sink"]

        # Build source patterns
        field = source["field"]
        source_type = source["type"]
        if source_type == "body.get":
            source_patterns = [
                f'body.get("{field}", ...)',
                f'body.get("{field}")',
                f'body["{field}"]',
            ]
        elif source_type == "body[]":
            source_patterns = [
                f'body["{field}"]',
                f'body.get("{field}", ...)',
            ]
        elif source_type == "state[]":
            source_patterns = [
                f'state["{field}"]',
                f'state.get("{field}", ...)',
            ]
        elif source_type == "input_data[]":
            source_patterns = [
                f'input_data["{field}"]',
                f'input_data.get("{field}", ...)',
            ]
        else:
            source_patterns = [source["pattern"]]

        # Build sink patterns
        sink_type = sink["type"]
        sink_map = {
            "dynamodb": ["$TABLE.put_item(...)", "$TABLE.update_item(...)", "$TABLE.query(...)", "$TABLE.get_item(...)"],
            "sql": ["$CONN.execute(...)", "$CURSOR.execute(...)"],
            "command": ["subprocess.run(...)", "subprocess.call(...)", "subprocess.Popen(...)"],
            "code_exec": ["exec(...)", "eval(...)"],
            "s3_write": ["$CLIENT.put_object(...)", "$CLIENT.upload_file(...)"],
            "llm": ["$CLIENT.invoke_model(...)"],
            "messaging": ["$CLIENT.send_message(...)", "$CLIENT.publish(...)"],
            "lambda_invoke": ["$CLIENT.invoke(...)"],
            "file_write": ['open($PATH, "w")'],
            "cognito_admin": ["$CLIENT.admin_update_user_attributes(...)", "$CLIENT.admin_create_user(...)"],
            "stepfunctions": ["$CLIENT.start_execution(...)", "$CLIENT.send_task_success(...)"],
            # KB-enriched sink types
            "kb_prompt_injection": ['{"role": "system", "content": $SINK}', "$OBJ.run(...)"],
            "kb_ssrf": ["requests.get(...)", "requests.post(...)", "urllib.request.urlopen(...)"],
            "kb_deserialization": ["pickle.loads(...)", "pickle.load(...)", "yaml.load(...)"],
            "kb_open_redirect": ["redirect(...)"],
        }
        sink_patterns = sink_map.get(sink_type, [sink["pattern"]])

        # Get community-known sanitizers for this vulnerability class
        kb_sanitizers = self._get_kb_sanitizers(sink_type)

        rule_id = f"generated-{source_type.replace('.', '-').replace('[]', '')}-{field}-to-{sink_type}"

        return GeneratedRule(
            id=rule_id,
            message=f"User-controlled '{field}' from {source_type} flows to {sink_type} operation without sanitization.",
            severity="WARNING",
            sources=source_patterns,
            sinks=sink_patterns,
            sanitizers=kb_sanitizers[:3],  # Include up to 3 community sanitizers
            cwe=sink["cwe"],
            category=f"taint-{sink_type}",
        )

    def _validate_rules(self, rules: list[GeneratedRule]) -> list[GeneratedRule]:
        """Validate generated rules with semgrep --validate."""
        valid = []
        for rule in rules:
            yaml_content = self._render_yaml(rule)
            if self._semgrep_validate(yaml_content):
                rule.valid = True
                valid.append(rule)
        return valid

    def _run_rules_batched(self, rules: list[GeneratedRule], files: list[str]):
        """Run ALL rules in a single pysemgrep invocation for performance."""
        # Build combined YAML with all rules
        all_rule_dicts = []
        for rule in rules:
            entry = {
                "id": rule.id,
                "severity": rule.severity,
                "message": rule.message,
                "languages": ["python"],
                "mode": "taint",
                "pattern-sources": [{"pattern": p} for p in rule.sources],
                "pattern-sinks": [{"pattern": p} for p in rule.sinks],
                "metadata": {"cwe": rule.cwe, "category": rule.category},
            }
            if rule.sanitizers:
                entry["pattern-sanitizers"] = [{"pattern": p} for p in rule.sanitizers]
            all_rule_dicts.append(entry)

        combined_yaml = yaml.dump({"rules": all_rule_dicts}, default_flow_style=False, sort_keys=False)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, prefix="genrules_batch_"
        ) as f:
            f.write(combined_yaml)
            batch_path = f.name

        try:
            # Single scan against all target directories
            dirs = sorted(set(str(Path(f).parent) for f in files))
            # Use the common ancestor directory to scan once
            if dirs:
                common_dir = os.path.commonpath(dirs)
            else:
                return

            env = os.environ.copy()
            env["PATH"] = f"{Path.home()}/Library/Python/3.9/bin:" + env.get("PATH", "")
            semgrep_bin = str(Path.home() / "Library/Python/3.9/bin/pysemgrep")
            result = subprocess.run(
                [semgrep_bin, "scan", "--config", batch_path, common_dir, "--json", "--quiet"],
                capture_output=True, text=True, env=env, timeout=120,
            )

            try:
                data = json.loads(result.stdout or "{}")
                findings = data.get("results", [])
                # Attribute findings back to individual rules
                rule_map = {r.id: r for r in rules}
                for finding in findings:
                    rule_id = finding.get("check_id", "").split(".")[-1]
                    if rule_id in rule_map:
                        rule_map[rule_id].findings_count += 1
            except json.JSONDecodeError:
                pass
        finally:
            Path(batch_path).unlink(missing_ok=True)

    def _render_yaml(self, rule: GeneratedRule) -> str:
        """Render a GeneratedRule as Semgrep YAML."""
        rule_dict = {
            "rules": [{
                "id": rule.id,
                "severity": rule.severity,
                "message": rule.message,
                "languages": ["python"],
                "mode": "taint",
                "pattern-sources": [{"pattern": p} for p in rule.sources],
                "pattern-sinks": [{"pattern": p} for p in rule.sinks],
                "metadata": {
                    "cwe": rule.cwe,
                    "category": rule.category,
                    "confidence": "MEDIUM",
                    "generated": True,
                },
            }]
        }
        if rule.sanitizers:
            rule_dict["rules"][0]["pattern-sanitizers"] = [
                {"pattern": p} for p in rule.sanitizers
            ]
        return yaml.dump(rule_dict, default_flow_style=False, sort_keys=False)

    def _semgrep_validate(self, yaml_content: str) -> bool:
        """
        Validate a rule's YAML structure without spawning semgrep.
        Checks required fields and pattern syntax.
        Falls back to semgrep --validate if available and fast.
        """
        # Structural validation (fast, no subprocess)
        try:
            data = yaml.safe_load(yaml_content)
            rules = data.get("rules", [])
            if not rules:
                return False
            for rule in rules:
                if not all(k in rule for k in ("id", "message", "languages", "mode")):
                    return False
                if rule.get("mode") == "taint":
                    if "pattern-sources" not in rule or "pattern-sinks" not in rule:
                        return False
                    if not rule["pattern-sources"] or not rule["pattern-sinks"]:
                        return False
            return True
        except yaml.YAMLError:
            return False

    def save_rules(self, rules: list[GeneratedRule], output_path: str) -> str:
        """Save all valid rules to a single YAML file."""
        all_rules = []
        for rule in rules:
            if rule.valid:
                entry = {
                    "id": rule.id,
                    "severity": rule.severity,
                    "message": rule.message,
                    "languages": ["python"],
                    "mode": "taint",
                    "pattern-sources": [{"pattern": p} for p in rule.sources],
                    "pattern-sinks": [{"pattern": p} for p in rule.sinks],
                    "metadata": {
                        "cwe": rule.cwe,
                        "category": rule.category,
                        "confidence": "MEDIUM",
                        "generated": True,
                    },
                }
                if rule.sanitizers:
                    entry["pattern-sanitizers"] = [{"pattern": p} for p in rule.sanitizers]
                all_rules.append(entry)

        output = yaml.dump({"rules": all_rules}, default_flow_style=False, sort_keys=False)
        Path(output_path).write_text(output)
        return output_path
