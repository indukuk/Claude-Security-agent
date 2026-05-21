"""
V6 Layer 0, Track 1: Code Analysis.

Wraps V4's CPG + semgrep + evidence walks + absence + differential
into a single callable that produces the code portion of the evidence package.
"""
from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from dataclasses import dataclass, field

from v4.cpg.enhanced_builder import EnhancedCPGBuilder
from v4.analysis.evidence_walker import EvidenceWalker
from v4.analysis.absence_detector import AbsenceDetector, AbsenceFinding
from v4.analysis.differential_analyzer import DifferentialAnalyzer, DifferentialFinding
from src.common.graph import CodePropertyGraph

logger = logging.getLogger(__name__)


@dataclass
class CodeAnalysisResult:
    """Output of Layer 0 code analysis track."""
    cpg: CodePropertyGraph
    builder: EnhancedCPGBuilder
    semgrep_findings: list[dict] = field(default_factory=list)
    evidence_walks: list[tuple[dict, object]] = field(default_factory=list)
    absence_findings: list[AbsenceFinding] = field(default_factory=list)
    differential_findings: list[DifferentialFinding] = field(default_factory=list)
    file_contents: dict[str, str] = field(default_factory=dict)
    handler_files: list[str] = field(default_factory=list)


INFRA_AUTH_MAP = {
    "lambda_handler": "authorizer",
    "handler": "authorizer",
}


def run_code_analysis(repo_path: str) -> CodeAnalysisResult:
    """Run the full code analysis track."""
    repo = Path(repo_path)

    # Discover Python files
    py_files = [
        str(f) for f in repo.rglob("*.py")
        if "__pycache__" not in str(f) and ".venv" not in str(f)
        and "cdk.out" not in str(f) and "node_modules" not in str(f)
        and "test" not in str(f).lower()
    ]
    py_files = [f for f in py_files if "/src/" in f or "/infra/" in f]

    # Build enhanced CPG
    builder = EnhancedCPGBuilder()
    cpg = builder.build(py_files, infra_auth_map=INFRA_AUTH_MAP)
    logger.info(f"CPG: {cpg.node_count()} nodes, {cpg.edge_count()} edges")

    # Run semgrep
    semgrep_findings = _run_semgrep(repo)
    logger.info(f"Semgrep: {len(semgrep_findings)} findings")

    # Evidence walks
    walker = EvidenceWalker(cpg, builder)
    evidence_walks = []
    for finding in semgrep_findings:
        walk = walker.generate_walk(finding)
        if walk:
            evidence_walks.append((finding, walk))
    logger.info(f"Evidence walks: {len(evidence_walks)}")

    # Absence detection
    absence_findings = AbsenceDetector(cpg, builder).detect()
    logger.info(f"Absence: {len(absence_findings)}")

    # Differential analysis
    differential_findings = DifferentialAnalyzer(cpg, builder).analyze()
    logger.info(f"Differential: {len(differential_findings)}")

    # Collect handler file contents for LLM agents
    handler_files = [f for f in py_files if "handler" in Path(f).stem]
    file_contents = {}
    for f in handler_files[:20]:
        try:
            file_contents[f] = Path(f).read_text()
        except (OSError, UnicodeDecodeError):
            pass

    return CodeAnalysisResult(
        cpg=cpg,
        builder=builder,
        semgrep_findings=semgrep_findings,
        evidence_walks=evidence_walks,
        absence_findings=absence_findings,
        differential_findings=differential_findings,
        file_contents=file_contents,
        handler_files=handler_files,
    )


def _run_semgrep(repo: Path) -> list[dict]:
    """Run all semgrep rule sets."""
    rules_dir = Path(__file__).parent.parent.parent / "v2"
    v4_rules = Path(__file__).parent.parent.parent / "v4" / "rules"
    findings = []

    rule_targets = [
        (rules_dir / "semgrep_rules.yaml", repo / "src"),
        (rules_dir / "semgrep_rules_gaps.yaml", repo / "src"),
        (rules_dir / "semgrep_rules_frontend.yaml", repo / "frontend"),
        (v4_rules / "crypto_auth.yaml", repo / "src"),
        (v4_rules / "frontend_secrets.yaml", repo / "frontend"),
    ]

    for rule_path, target_path in rule_targets:
        if not rule_path.exists() or not target_path.exists():
            continue
        try:
            result = subprocess.run(
                ["semgrep", "--config", str(rule_path), str(target_path),
                 "--json", "--quiet", "--no-git-ignore"],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode in (0, 1):
                data = json.loads(result.stdout) if result.stdout else {}
                for r in data.get("results", []):
                    sev_map = {"ERROR": "CRITICAL", "WARNING": "HIGH", "INFO": "MEDIUM"}
                    findings.append({
                        "id": f"semgrep-{len(findings)}",
                        "title": r.get("check_id", "").split(".")[-1],
                        "severity": sev_map.get(r.get("extra", {}).get("severity", ""), "MEDIUM"),
                        "confidence": 0.8,
                        "file_path": r.get("path", ""),
                        "line": r.get("start", {}).get("line", 0),
                        "cwe": str(r.get("extra", {}).get("metadata", {}).get("cwe", "")),
                        "category": r.get("extra", {}).get("metadata", {}).get("category", ""),
                    })
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning(f"Semgrep: {e}")

    return findings
