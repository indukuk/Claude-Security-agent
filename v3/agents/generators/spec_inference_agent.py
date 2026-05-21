"""
Spec Inference Agent — discovers novel sources/sinks via static analysis
and feeds them back into CPG for delta path detection.

Two-pass protocol:
1. Build CPG with hardcoded specs → baseline taint paths
2. Run spec inference → discover new sources/sinks → rebuild CPG → new paths
3. Delta: paths in pass 2 but not pass 1 = newly discovered vulnerabilities

This agent does NOT require LLM calls — it uses AST-based pattern detection
to find framework-specific sources/sinks that hardcoded patterns miss.
"""
from __future__ import annotations

import ast
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from src.common.graph import CodePropertyGraph
from src.agents.python.cpg_builder import PythonCPGBuilder

logger = logging.getLogger(__name__)


@dataclass
class InferredSpec:
    """A newly discovered source, sink, or sanitizer."""
    function: str
    role: str  # "source" | "sink" | "sanitizer" | "propagator"
    reason: str
    file_path: str = ""
    confidence: float = 0.7


@dataclass
class SpecInferenceResult:
    """Result of spec inference with delta analysis."""
    inferred_specs: dict  # {"sources": [...], "sinks": [...], ...}
    baseline_paths: int
    enhanced_paths: int
    delta_paths: list[tuple[str, str, list[str]]]  # New paths not in baseline
    new_findings: list[dict]


class SpecInferenceAgent:
    """
    Discovers novel taint specifications via static pattern analysis.

    Detects:
    - LangGraph @tool decorated functions as sinks (execute actions based on state)
    - AgentState field access as sources (LLM-influenced state)
    - Custom framework entry points (FastAPI deps, Flask before_request)
    - Callback/hook patterns that propagate taint
    """

    # Framework-specific patterns to detect
    DECORATOR_SOURCES = {
        "tool": "LangGraph tool function receives LLM-driven input",
        "app.route": "HTTP endpoint receives user input",
        "router.get": "FastAPI endpoint receives user input",
        "router.post": "FastAPI endpoint receives user input",
    }

    DECORATOR_SINKS = {
        "tool": "LangGraph tool executes actions based on LLM output",
    }

    STATE_ACCESS_PATTERNS = [
        "state['messages']",
        "state.get('messages'",
        "state['input']",
        "AgentState",
    ]

    PROPAGATOR_PATTERNS = [
        ("invoke", "Chain/agent invocation propagates taint through LLM"),
        ("run", "Agent run propagates taint"),
        ("acall", "Async chain call propagates taint"),
    ]

    # Community KB sink patterns (function calls the community considers dangerous)
    KB_SINK_FUNCTIONS = [
        "pickle.loads", "pickle.load", "yaml.unsafe_load", "marshal.loads",
        "subprocess.run", "subprocess.call", "subprocess.Popen",
        "os.system", "os.popen", "os.exec",
        "eval", "exec", "compile",
        "requests.get", "requests.post", "urllib.request.urlopen",
        "redirect",
    ]

    KB_SOURCE_FUNCTIONS = [
        "request.args.get", "request.form.get", "request.json.get",
        "request.data", "request.files",
    ]

    def __init__(self, kb_path: str | None = None):
        self._kb = self._load_kb(kb_path)

    def _load_kb(self, kb_path: str | None) -> dict:
        """Load community KB for pattern seeding."""
        if kb_path is None:
            kb_path = str(Path(__file__).parent.parent.parent / "knowledge" / "semgrep_kb.json")
        try:
            return json.loads(Path(kb_path).read_text())
        except (OSError, json.JSONDecodeError):
            return {}

    def run(self, files: list[str]) -> SpecInferenceResult:
        """
        Execute two-pass analysis: baseline CPG → infer specs → enhanced CPG → delta.
        """
        # Pass 1: baseline CPG with hardcoded specs only
        builder = PythonCPGBuilder()
        baseline_cpg = builder.build(files, inferred_specs={})
        baseline_paths = baseline_cpg.find_taint_paths()
        logger.info(f"Pass 1 (baseline): {len(baseline_paths)} taint paths")

        # Infer new specs from AST analysis
        inferred = self._infer_specs(files)

        if not any(inferred.values()):
            return SpecInferenceResult(
                inferred_specs=inferred,
                baseline_paths=len(baseline_paths),
                enhanced_paths=len(baseline_paths),
                delta_paths=[],
                new_findings=[],
            )

        # Pass 2: rebuild CPG with inferred specs
        enhanced_cpg = builder.build(files, inferred_specs=inferred)
        enhanced_paths = enhanced_cpg.find_taint_paths()
        logger.info(f"Pass 2 (enhanced): {len(enhanced_paths)} taint paths")

        # Compute delta
        baseline_set = {(s, t) for s, t, _ in baseline_paths}
        delta = [(s, t, p) for s, t, p in enhanced_paths if (s, t) not in baseline_set]
        logger.info(f"Delta: {len(delta)} new taint paths discovered")

        # Convert delta paths to findings
        new_findings = []
        for source_id, sink_id, path_nodes in delta:
            source_text = enhanced_cpg.get_text(source_id)
            sink_text = enhanced_cpg.get_text(sink_id)
            source_file, source_line = enhanced_cpg.get_file_line(source_id)
            sink_file, sink_line = enhanced_cpg.get_file_line(sink_id)

            new_findings.append({
                "title": f"Inferred taint: {Path(source_file).name}:{source_line} → {Path(sink_file).name}:{sink_line}",
                "severity": "MEDIUM",
                "category": "inferred_taint_path",
                "source": {"file": source_file, "line": source_line, "text": source_text[:100]},
                "sink": {"file": sink_file, "line": sink_line, "text": sink_text[:100]},
                "path_length": len(path_nodes),
                "confidence": 0.7,
            })

        return SpecInferenceResult(
            inferred_specs=inferred,
            baseline_paths=len(baseline_paths),
            enhanced_paths=len(enhanced_paths),
            delta_paths=delta,
            new_findings=new_findings,
        )

    def _infer_specs(self, files: list[str]) -> dict:
        """Infer sources, sinks, sanitizers, and propagators from AST patterns."""
        specs: dict[str, list[dict]] = {
            "sources": [],
            "sinks": [],
            "sanitizers": [],
            "propagators": [],
        }

        for file_path in files:
            try:
                content = Path(file_path).read_text(encoding="utf-8")
                tree = ast.parse(content)
                self._analyze_file(tree, file_path, content, specs)
                self._check_kb_patterns(tree, file_path, content, specs)
            except (SyntaxError, OSError):
                continue

        # Deduplicate
        for category in specs:
            seen = set()
            unique = []
            for spec in specs[category]:
                key = spec["function"]
                if key not in seen:
                    seen.add(key)
                    unique.append(spec)
            specs[category] = unique

        logger.info(
            f"Inferred: {len(specs['sources'])} sources, {len(specs['sinks'])} sinks, "
            f"{len(specs['sanitizers'])} sanitizers, {len(specs['propagators'])} propagators"
        )
        return specs

    def _analyze_file(self, tree: ast.AST, file_path: str, content: str, specs: dict):
        """Analyze a single file's AST for inferrable specs."""
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                self._check_decorated_function(node, file_path, specs)
                self._check_function_body_patterns(node, file_path, specs)

            elif isinstance(node, ast.Subscript):
                self._check_state_access(node, file_path, content, specs)

            elif isinstance(node, ast.Call):
                self._check_propagator_calls(node, file_path, specs)

    def _check_kb_patterns(self, tree: ast.AST, file_path: str, content: str, specs: dict):
        """Detect community-known sink/source function calls in this file."""
        # Build set of exact function names to match (no partial matching)
        kb_sink_set = set(self.KB_SINK_FUNCTIONS)
        kb_source_set = set(self.KB_SOURCE_FUNCTIONS)
        # Also match on the "module.func" form exactly
        kb_sink_exact = {s.split(".")[-1] for s in self.KB_SINK_FUNCTIONS if "." in s}
        # Exclude generic names that cause false positives
        generic_names = {"get", "run", "load", "loads", "call", "open"}
        kb_sink_exact -= generic_names

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            # Resolve full qualified function name
            func_name = ""
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    func_name = f"{node.func.value.id}.{node.func.attr}"
                elif isinstance(node.func.value, ast.Attribute):
                    # e.g., os.path.basename → just get last two parts
                    func_name = f"{node.func.value.attr}.{node.func.attr}"
            elif isinstance(node.func, ast.Name):
                func_name = node.func.id

            if not func_name:
                continue

            # Check against KB sinks — exact match on full name
            if func_name in kb_sink_set:
                specs["sinks"].append({
                    "function": func_name,
                    "reason": f"Community KB: {func_name} is a known dangerous sink",
                    "file": file_path,
                    "confidence": 0.8,
                })
            # Also match "module.func" patterns like subprocess.run
            elif "." in func_name and func_name.split(".")[1] in kb_sink_exact:
                full_match = func_name.split(".")[1]
                specs["sinks"].append({
                    "function": func_name,
                    "reason": f"Community KB: *.{full_match} is a known dangerous sink",
                    "file": file_path,
                    "confidence": 0.7,
                })

    def _check_decorated_function(self, node: ast.FunctionDef, file_path: str, specs: dict):
        """Check if function decorators indicate source/sink roles."""
        for decorator in node.decorator_list:
            dec_name = ""
            if isinstance(decorator, ast.Name):
                dec_name = decorator.id
            elif isinstance(decorator, ast.Attribute):
                dec_name = decorator.attr
            elif isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Name):
                    dec_name = decorator.func.id
                elif isinstance(decorator.func, ast.Attribute):
                    dec_name = decorator.func.attr

            # LangGraph @tool functions are both sources (receive LLM input) and sinks (execute actions)
            if dec_name in self.DECORATOR_SINKS:
                specs["sinks"].append({
                    "function": node.name,
                    "reason": self.DECORATOR_SINKS[dec_name],
                    "file": file_path,
                    "confidence": 0.8,
                })

            if dec_name in self.DECORATOR_SOURCES:
                # Check if function params include state-like objects
                for arg in node.args.args:
                    if arg.arg in ("state", "input", "request", "event"):
                        specs["sources"].append({
                            "function": node.name,
                            "reason": f"{self.DECORATOR_SOURCES[dec_name]} (param: {arg.arg})",
                            "file": file_path,
                            "confidence": 0.75,
                        })
                        break

    def _check_function_body_patterns(self, node: ast.FunctionDef, file_path: str, specs: dict):
        """Check function bodies for patterns that indicate security roles."""
        body_source = ast.dump(node)

        # Functions that validate/sanitize
        sanitizer_indicators = [
            "validate", "sanitize", "check_permission", "verify",
            "authenticate", "authorize", "escape", "clean",
        ]
        if any(ind in node.name.lower() for ind in sanitizer_indicators):
            specs["sanitizers"].append({
                "function": node.name,
                "reason": f"Function name '{node.name}' indicates sanitization/validation",
                "file": file_path,
                "confidence": 0.6,
            })

    def _check_state_access(self, node: ast.Subscript, file_path: str, content: str, specs: dict):
        """Check for AgentState/state subscript access patterns."""
        if isinstance(node.value, ast.Name) and node.value.id in ("state", "agent_state"):
            if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                field_name = node.slice.value
                if field_name in ("messages", "input", "query", "user_input"):
                    specs["sources"].append({
                        "function": f"state['{field_name}']",
                        "reason": f"AgentState field '{field_name}' carries LLM-influenced data",
                        "file": file_path,
                        "confidence": 0.8,
                    })

    def _check_propagator_calls(self, node: ast.Call, file_path: str, specs: dict):
        """Check for chain/agent invocation patterns that propagate taint."""
        if isinstance(node.func, ast.Attribute):
            method_name = node.func.attr
            for pattern, reason in self.PROPAGATOR_PATTERNS:
                if method_name == pattern:
                    # Get the object being called on
                    if isinstance(node.func.value, ast.Name):
                        obj_name = node.func.value.id
                        specs["propagators"].append({
                            "function": f"{obj_name}.{method_name}",
                            "reason": reason,
                            "file": file_path,
                            "confidence": 0.65,
                        })
                    break
