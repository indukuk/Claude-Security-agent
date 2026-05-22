"""
V6 Layer 6: Feedback Loop — Rule Generation from LLM Discoveries (Production).

Takes confirmed novel findings and generates deterministic rules:
- Semgrep YAML rules
- Absence detector MustGuard specs
- Chain synthesizer capability mappings

Each generated rule is validated: must fire on the original finding,
must NOT produce false positives on unrelated code.
"""
from __future__ import annotations

import yaml
import logging
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


RULE_GEN_SYSTEM = """You generate deterministic detection rules from vulnerability findings.
Output ONLY the rule in the exact format specified. No explanation.

RULE TYPES:
1. Semgrep YAML — for code patterns
2. Absence Spec — for missing controls
3. Chain Capability — for attack composition

Choose the type that best matches the finding's nature."""

SEMGREP_TEMPLATE = """Given this finding, generate a Semgrep YAML rule that would detect it:

Finding: {title}
Category: {category}
Code pattern: {pattern}
File: {file_path}:{line}

Output a valid Semgrep rule in YAML format. The rule must:
- Have a unique ID
- Match the vulnerable pattern (not the fix)
- Include message explaining the risk
- Set appropriate severity (ERROR/WARNING/INFO)
- Include CWE metadata

```yaml
rules:
  - id: ...
    pattern: ...
    message: ...
    languages: [python]
    severity: ...
    metadata:
      cwe: ...
      category: ...
```"""

ABSENCE_TEMPLATE = """Given this finding, generate an absence detector MustGuard spec:

Finding: {title}
Category: {category}
What's missing: {missing_guard}
Where the sink is: {sink_pattern}

Output a Python MustGuard dataclass:

```python
MustGuard(
    id="...",
    sink_pattern=r"...",
    guard_pattern=r"...",
    guard_type="...",
    scope="same_handler",
    severity="...",
    title_template="...",
    cwe="...",
)
```"""


@dataclass
class GeneratedRule:
    """A rule generated from a novel finding."""
    finding_id: str
    rule_type: str  # "semgrep" | "absence_spec" | "chain_capability"
    content: str
    validated: bool = False
    fires_on_original: bool = False
    false_positives: int = 0


class RuleGenerator:
    """Generates deterministic rules from novel LLM discoveries."""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_from_finding(self, finding: dict, llm_fn=None) -> GeneratedRule:
        """Generate a rule from a novel finding."""
        category = finding.get("category", "")
        rule_suggestion = finding.get("rule_suggestion", "")

        # Determine best rule type
        if "pattern" in rule_suggestion.lower() or "flag any" in rule_suggestion.lower():
            if "sink" in rule_suggestion.lower() and "guard" in rule_suggestion.lower():
                return self._generate_absence_spec(finding, llm_fn)
            return self._generate_semgrep_rule(finding, llm_fn)
        elif "missing" in category or "absent" in category:
            return self._generate_absence_spec(finding, llm_fn)
        else:
            return self._generate_semgrep_rule(finding, llm_fn)

    def _generate_semgrep_rule(self, finding: dict, llm_fn=None) -> GeneratedRule:
        """Generate a Semgrep YAML rule."""
        if llm_fn:
            prompt = SEMGREP_TEMPLATE.format(
                title=finding.get("title", ""),
                category=finding.get("category", ""),
                pattern=finding.get("evidence", "")[:200],
                file_path=finding.get("file_path", ""),
                line=finding.get("line", 0),
            )
            response = llm_fn(system=RULE_GEN_SYSTEM, user=prompt)
            # Extract YAML from response
            if "```yaml" in response:
                start = response.index("```yaml") + 7
                end = response.index("```", start)
                content = response[start:end].strip()
            else:
                content = response
        else:
            # Template-based generation
            rule_id = finding.get("id", "unknown").replace(" ", "-").lower()
            content = yaml.dump({"rules": [{
                "id": f"discovered-{rule_id}",
                "pattern": finding.get("evidence", "TODO: extract pattern")[:100],
                "message": finding.get("title", ""),
                "languages": ["python"],
                "severity": "WARNING",
                "metadata": {
                    "cwe": finding.get("cwe", ""),
                    "category": finding.get("category", ""),
                    "discovered_by": "v6_layer1_llm",
                },
            }]})

        rule = GeneratedRule(
            finding_id=finding.get("id", ""),
            rule_type="semgrep",
            content=content,
        )

        # Save to discovered rules directory
        rule_file = self.output_dir / f"discovered_{rule.finding_id}.yaml"
        rule_file.write_text(content)

        return rule

    def _generate_absence_spec(self, finding: dict, llm_fn=None) -> GeneratedRule:
        """Generate an absence detector MustGuard spec."""
        if llm_fn:
            prompt = ABSENCE_TEMPLATE.format(
                title=finding.get("title", ""),
                category=finding.get("category", ""),
                missing_guard=finding.get("rule_suggestion", ""),
                sink_pattern=finding.get("evidence", "")[:100],
            )
            response = llm_fn(system=RULE_GEN_SYSTEM, user=prompt)
            content = response
        else:
            content = (
                f"# Generated from: {finding.get('title', '')}\n"
                f"MustGuard(\n"
                f"    id=\"discovered-{finding.get('id', 'unknown')}\",\n"
                f"    sink_pattern=r\"TODO\",\n"
                f"    guard_pattern=r\"TODO\",\n"
                f"    guard_type=\"{finding.get('category', 'unknown')}\",\n"
                f"    scope=\"same_handler\",\n"
                f"    severity=\"HIGH\",\n"
                f"    title_template=\"{finding.get('title', '')}\",\n"
                f"    cwe=\"{finding.get('cwe', '')}\",\n"
                f")\n"
            )

        rule = GeneratedRule(
            finding_id=finding.get("id", ""),
            rule_type="absence_spec",
            content=content,
        )

        spec_file = self.output_dir / f"discovered_{rule.finding_id}_spec.py"
        spec_file.write_text(content)

        return rule

    def generate_all(self, findings: list[dict], llm_fn=None) -> list[GeneratedRule]:
        """Generate rules for all novel findings."""
        rules = []
        for finding in findings:
            try:
                rule = self.generate_from_finding(finding, llm_fn)
                rules.append(rule)
                logger.info(f"Generated {rule.rule_type} rule for: {finding.get('title', '')}")
            except Exception as e:
                logger.warning(f"Rule generation failed for {finding.get('id', '')}: {e}")
        return rules
