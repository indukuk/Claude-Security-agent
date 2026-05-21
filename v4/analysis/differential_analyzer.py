"""
Differential Path Analyzer — finds security control inconsistencies.

Detects when the same sensitive operation is reachable via multiple code paths
but with different security guards. The path with fewer guards is a bypass.

Example detection:
- agent_chat/handler.py has check_permission() + check_approval() + _safe_id()
- agent_proxy/handler.py has NONE of these → bypass path

Algorithm:
1. Cluster operations by semantic equivalence (same backend call/sink)
2. For each cluster, extract the guard set on each reaching path
3. Report paths with strictly fewer guards than siblings
"""
from __future__ import annotations

import re
import logging
from pathlib import Path
from dataclasses import dataclass, field

from src.common.graph import CodePropertyGraph
from v4.cpg.enhanced_builder import EnhancedCPGBuilder, FunctionInfo

logger = logging.getLogger(__name__)


@dataclass
class GuardInfo:
    """A security guard found on a code path."""
    guard_type: str  # auth_check, input_validation, role_check, approval_workflow, sanitization
    pattern_matched: str
    file_path: str
    line: int


@dataclass
class CodePath:
    """A path from an entry point to a sensitive operation."""
    entry_handler: str
    entry_file: str
    sink_operation: str
    sink_file: str
    sink_line: int
    guards: list[GuardInfo] = field(default_factory=list)
    guard_types: set[str] = field(default_factory=set)


@dataclass
class DifferentialFinding:
    """A finding where one path has fewer guards than another."""
    id: str
    title: str
    description: str
    severity: str
    confidence: float
    weaker_path: CodePath
    stronger_path: CodePath
    missing_guards: list[str]
    category: str = "security_bypass"
    cwe: str = "CWE-638"


# Guard detection patterns organized by type
GUARD_PATTERNS = {
    "auth_check": [
        r"check_permission\(",
        r"verify_token\(",
        r"@requires_auth",
        r"authorizer\[",
        r"requestContext.*authorizer",
    ],
    "role_check": [
        r"role\s*(not\s+)?in\s*[\[\({\"]",
        r"role\s*[!=]=",
        r"WRITE_ROLES|ADMIN_ROLES|_EVIDENCE_WRITE_ROLES",
        r"if.*role.*admin",
    ],
    "input_sanitization": [
        r"_safe_id\(",
        r"\.replace\(['\"][/\\\\]",
        r"sanitize|validate_input",
        r"os\.path\.basename\(",
        r"re\.sub\(",
    ],
    "approval_workflow": [
        r"check_approval\(",
        r"require_confirmation",
        r"__confirm__",
    ],
    "ownership_check": [
        r"customer_id.*!=|tenant_id.*!=",
        r"session.*customer_id.*!=",
        r"verify_owner",
    ],
    "rate_limit": [
        r"rate_limit|throttle|token_bucket",
    ],
}

# Patterns that identify sensitive operations (to cluster by)
SENSITIVE_OPERATIONS = {
    "tool_execution": [
        r"execute_tool\(",
        r"_call_auth_api\(",
        r"_call\(",
    ],
    "data_write": [
        r"table\.(put_item|update_item|delete_item)\(",
    ],
    "data_read": [
        r"table\.get_item\(",
        r"table\.query\(",
    ],
    "s3_access": [
        r"generate_presigned_url\(",
        r"s3_client\.(put_object|get_object)\(",
    ],
    "user_management": [
        r"admin_create_user\(",
        r"admin_update_user",
        r"invite_user",
    ],
}


class DifferentialAnalyzer:
    """
    Finds inconsistent security controls across code paths to the same operation.
    """

    def __init__(self, cpg: CodePropertyGraph, builder: EnhancedCPGBuilder):
        self.cpg = cpg
        self.builder = builder
        self._file_contents: dict[str, str] = {}

    def analyze(self) -> list[DifferentialFinding]:
        """Run differential analysis across all handler modules."""
        findings = []

        # Step 1: Build paths from each handler module to sensitive operations
        paths_by_operation = self._cluster_paths_by_operation()

        # Step 2: For each cluster with 2+ paths, compare guard sets
        for operation, paths in paths_by_operation.items():
            if len(paths) < 2:
                continue

            cluster_findings = self._compare_guard_sets(operation, paths)
            findings.extend(cluster_findings)

        logger.info(f"Differential analyzer: {len(findings)} findings")
        return findings

    def _cluster_paths_by_operation(self) -> dict[str, list[CodePath]]:
        """Group code paths by the sensitive operation they reach."""
        clusters: dict[str, list[CodePath]] = {}

        for func_key, func_info in self.builder.functions.items():
            if not func_info.is_handler:
                continue

            file_text = self._get_file_text(func_info.file_path)
            if not file_text:
                continue

            # Check which sensitive operations this handler's file reaches
            for op_name, op_patterns in SENSITIVE_OPERATIONS.items():
                for pattern in op_patterns:
                    matches = list(re.finditer(pattern, file_text))
                    if matches:
                        # Extract guards in this file
                        guards = self._extract_guards(file_text, func_info.file_path)

                        for match in matches[:1]:
                            sink_line = file_text[:match.start()].count("\n") + 1
                            path = CodePath(
                                entry_handler=func_info.name,
                                entry_file=func_info.file_path,
                                sink_operation=match.group(0),
                                sink_file=func_info.file_path,
                                sink_line=sink_line,
                                guards=guards,
                                guard_types={g.guard_type for g in guards},
                            )
                            clusters.setdefault(op_name, []).append(path)
                        break  # One match per operation type per handler

        return clusters

    def _extract_guards(self, file_text: str, file_path: str) -> list[GuardInfo]:
        """Extract all security guards found in a file."""
        guards = []
        lines = file_text.split("\n")

        for guard_type, patterns in GUARD_PATTERNS.items():
            for pattern in patterns:
                for match in re.finditer(pattern, file_text):
                    line_num = file_text[:match.start()].count("\n") + 1
                    guards.append(GuardInfo(
                        guard_type=guard_type,
                        pattern_matched=match.group(0),
                        file_path=file_path,
                        line=line_num,
                    ))
                    break  # One match per pattern is enough

        return guards

    def _compare_guard_sets(self, operation: str, paths: list[CodePath]) -> list[DifferentialFinding]:
        """Compare guard sets across paths to the same operation."""
        findings = []

        # Find the path with the MOST guards (strongest)
        strongest = max(paths, key=lambda p: len(p.guard_types))

        # Compare each weaker path against the strongest
        for path in paths:
            if path is strongest:
                continue

            missing = strongest.guard_types - path.guard_types
            if not missing:
                continue

            # Only report if there are meaningful missing guards
            # (not just rate_limit which is often optional)
            critical_missing = missing - {"rate_limit"}
            if not critical_missing:
                continue

            severity = "HIGH" if len(critical_missing) >= 2 else "MEDIUM"
            if "auth_check" in critical_missing or "role_check" in critical_missing:
                severity = "HIGH"

            stronger_file = Path(strongest.entry_file).name
            weaker_file = Path(path.entry_file).name

            title = (
                f"{weaker_file}::{path.entry_handler} bypasses "
                f"{', '.join(sorted(critical_missing))} "
                f"that {stronger_file}::{strongest.entry_handler} enforces"
            )

            description = (
                f"The {operation} operation is accessible via {path.entry_handler} "
                f"({weaker_file}) WITHOUT {', '.join(sorted(critical_missing))} guards. "
                f"In contrast, {strongest.entry_handler} ({stronger_file}) enforces "
                f"{', '.join(sorted(strongest.guard_types))} before the same operation."
            )

            # Build evidence text
            stronger_guards_text = ", ".join(
                f"{g.pattern_matched} ({Path(g.file_path).name}:{g.line})"
                for g in strongest.guards
                if g.guard_type in critical_missing
            )

            findings.append(DifferentialFinding(
                id=f"diff-{operation}-{path.entry_handler}",
                title=title,
                description=description,
                severity=severity,
                confidence=0.8,
                weaker_path=path,
                stronger_path=strongest,
                missing_guards=sorted(critical_missing),
            ))

        return findings

    def _get_file_text(self, file_path: str) -> str:
        if file_path not in self._file_contents:
            try:
                self._file_contents[file_path] = Path(file_path).read_text()
            except (OSError, UnicodeDecodeError):
                self._file_contents[file_path] = ""
        return self._file_contents[file_path]
