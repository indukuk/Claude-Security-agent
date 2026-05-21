"""
Business Logic Agent — detects vulnerabilities that no rule can catch.

Finds IDORs, missing authorization, and cross-service trust violations
by combining CPG taint analysis with auth context and IAM permission data.

Research basis: VulAgent (+6.6% accuracy, -36% FP), Neo (24 zero-days)
"""
from __future__ import annotations

import logging
from pathlib import Path
from dataclasses import dataclass, field

from v3.agents.generators.auth_pattern_analyzer import AuthPatternAnalyzer
from v3.agents.base import CandidateFinding

logger = logging.getLogger(__name__)


class BusinessLogicAgent:
    """
    Detects business logic vulnerabilities that symbolic rules cannot catch:
    - IDOR: user-controlled IDs flow to data operations without auth validation
    - Missing auth transitions: state mutations without permission gates
    - Cross-service trust: Lambda A trusts input from Lambda B without re-validation
    """

    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.analyzer = AuthPatternAnalyzer()

    def execute(self, input_data: dict) -> dict:
        """DAGNode-compatible execution. Returns candidates dict."""
        repo = Path(input_data.get("repo_path", str(self.repo_path)))

        # Find handler files (Lambda entry points)
        handler_files = self._find_handler_files(repo)
        logger.info(f"Business logic agent: scanning {len(handler_files)} handler files")

        candidates = []
        candidates.extend(self.detect_idor(handler_files))
        candidates.extend(self.detect_missing_auth_transitions(handler_files))

        logger.info(f"Business logic agent: {len(candidates)} findings")
        return {
            "candidates": [
                {
                    "title": c.title,
                    "severity": c.severity,
                    "confidence": c.confidence,
                    "evidence": c.evidence,
                    "file_path": c.file_path,
                    "line": c.line,
                    "cwe": c.cwe,
                    "category": c.category,
                }
                for c in candidates
            ]
        }

    def detect_idor(self, files: list[str]) -> list[CandidateFinding]:
        """
        Detect Insecure Direct Object References (IDOR / CWE-639).

        Pattern: handler reads customer_id/tenant_id from request body
        and uses it for data operations WITHOUT comparing against the
        authenticated tenant identity from the authorizer context.
        """
        findings = []

        for file_path in files:
            idor_candidates = self.analyzer.find_idor_candidates(file_path)

            for candidate in idor_candidates:
                body_id = candidate["body_id"]
                sinks = candidate["sinks"]
                rel_path = str(Path(file_path).relative_to(self.repo_path)) if self.repo_path in Path(file_path).parents else Path(file_path).name

                sink_lines = ", ".join(f"L{s['line']}" for s in sinks[:3])

                findings.append(CandidateFinding(
                    id=f"BIZLOGIC-IDOR-{len(findings)}",
                    scanner="business_logic",
                    title=(
                        f"IDOR: {body_id['id_name']} from request body used for data access "
                        f"without authorizer validation in {rel_path}"
                    ),
                    severity="CRITICAL",
                    confidence=0.95,
                    evidence=(
                        f"Source: {body_id['text']} (line {body_id['line']})\n"
                        f"Sinks: {sink_lines}\n"
                        f"Auth context accessed: {candidate['auth_context_accessed']}\n"
                        f"Auth validation: {candidate['auth_validation']}\n"
                        f"Reason: {candidate['reason']}"
                    ),
                    file_path=file_path,
                    line=body_id["line"],
                    cwe="CWE-639",
                    category="cross_tenant_idor",
                ))

        return findings

    def detect_missing_auth_transitions(self, files: list[str]) -> list[CandidateFinding]:
        """
        Detect state mutations without authorization gates.

        Pattern: DynamoDB write/Cognito admin calls occur in a handler
        that has NO check_permission() call and NO authorizer context access.
        """
        findings = []

        for file_path in files:
            unguarded = self.analyzer.find_unguarded_state_mutations(file_path)

            for candidate in unguarded:
                mutations = candidate["mutations"]
                rel_path = str(Path(file_path).relative_to(self.repo_path)) if self.repo_path in Path(file_path).parents else Path(file_path).name

                findings.append(CandidateFinding(
                    id=f"BIZLOGIC-NOAUTH-{len(findings)}",
                    scanner="business_logic",
                    title=f"State mutations without authorization in {rel_path}",
                    severity="HIGH",
                    confidence=0.8,
                    evidence=(
                        f"Mutations: {len(mutations)} data operations\n"
                        f"First mutation: {mutations[0]['text']} (line {mutations[0]['line']})\n"
                        f"Reason: {candidate['reason']}"
                    ),
                    file_path=file_path,
                    line=mutations[0]["line"],
                    cwe="CWE-285",
                    category="missing_authorization",
                ))

        return findings

    def _find_handler_files(self, repo: Path) -> list[str]:
        """Find Lambda handler files in the repository."""
        handler_files = []

        # Look for common handler patterns
        for py_file in repo.rglob("*.py"):
            rel = str(py_file.relative_to(repo))
            # Skip tests, venvs, node_modules, cdk.out
            if any(skip in rel for skip in ("test", "venv", ".venv", "node_modules", "cdk.out", "__pycache__")):
                continue
            # Include files likely to be Lambda handlers
            name = py_file.name.lower()
            if any(pattern in name for pattern in ("handler", "api", "endpoint", "lambda")):
                handler_files.append(str(py_file))
            # Also include files in src/ that handle events
            elif "src/" in rel and py_file.suffix == ".py":
                try:
                    content = py_file.read_text()
                    if "event" in content and ("body" in content or "json.loads" in content):
                        if any(sink in content for sink in ("table.", "cognito", "s3_client", "s3.")):
                            handler_files.append(str(py_file))
                except (PermissionError, UnicodeDecodeError):
                    continue

        return handler_files
