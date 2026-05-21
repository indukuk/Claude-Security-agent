"""
Absence Detector — finds security controls that SHOULD exist but don't.

Detects:
- Missing audit logging for data modifications
- Missing ownership verification after database reads
- Missing role checks before write/delete operations
- Missing rate limiting on auth endpoints
- Missing input sanitization before specific sinks

Uses two approaches:
1. Specification-driven: declarative must-guard rules checked against CPG paths
2. Pattern-mining: if >70% of paths to a sink have a guard, flag paths without it
"""
from __future__ import annotations

import re
import logging
from pathlib import Path
from dataclasses import dataclass, field

import networkx as nx

from src.common.graph import CodePropertyGraph
from v4.cpg.enhanced_builder import EnhancedCPGBuilder, FunctionInfo

logger = logging.getLogger(__name__)


@dataclass
class MustGuard:
    """A specification that a guard MUST exist on paths to a sink."""
    id: str
    sink_pattern: str
    guard_pattern: str
    guard_type: str
    scope: str  # "same_handler" | "before_sink" | "between_load_and_return"
    severity: str = "HIGH"
    title_template: str = ""
    description_template: str = ""
    cwe: str = ""


@dataclass
class AbsenceFinding:
    """A finding where a required control is absent."""
    id: str
    title: str
    description: str
    severity: str
    confidence: float
    file_path: str
    line: int
    handler_name: str
    sink_text: str
    missing_guard: str
    category: str
    cwe: str = ""
    evidence: str = ""


# Must-guard specifications
MUST_GUARD_SPECS = [
    MustGuard(
        id="audit-on-write",
        sink_pattern=r"table\.(put_item|update_item|delete_item)\(",
        guard_pattern=r"(audit|log_event|log_action|logger\.info.*action|logger\.info.*method)",
        guard_type="audit_log",
        scope="same_handler",
        severity="MEDIUM",
        title_template="No audit logging for {operation} in {handler}",
        description_template="Handler {handler} performs {operation} without logging who performed the action, what changed, or when.",
        cwe="CWE-778",
    ),
    MustGuard(
        id="ownership-after-load",
        sink_pattern=r"table\.get_item\(",
        guard_pattern=r"(customer_id.*!=|tenant_id.*!=|session.*\[.customer_id.\].*!=|ownership|verify_owner)",
        guard_type="ownership_check",
        scope="between_load_and_return",
        severity="HIGH",
        title_template="No ownership verification after data load in {handler}",
        description_template="Handler {handler} loads data from DynamoDB but does not verify the requester owns the record before returning it.",
        cwe="CWE-639",
    ),
    MustGuard(
        id="role-check-on-write",
        sink_pattern=r"table\.(put_item|update_item|delete_item)\(",
        guard_pattern=r"(role.*not in|role.*!=|check_permission|WRITE_ROLES|ADMIN_ROLES|_EVIDENCE_WRITE_ROLES)",
        guard_type="role_check",
        scope="same_handler",
        severity="HIGH",
        title_template="No role-based authorization for {operation} in {handler}",
        description_template="Handler {handler} performs {operation} without checking if the user's role permits this action. Any authenticated user can perform this operation.",
        cwe="CWE-862",
    ),
    MustGuard(
        id="role-check-on-cognito",
        sink_pattern=r"admin_create_user\(|admin_update_user|admin_confirm_sign_up",
        guard_pattern=r"(role.*not in|role.*!=|check_permission|admin|ADMIN)",
        guard_type="role_check",
        scope="same_handler",
        severity="HIGH",
        title_template="No role check before Cognito admin operation in {handler}",
        description_template="Handler {handler} performs Cognito admin operations without verifying the caller has admin privileges.",
        cwe="CWE-862",
    ),
    MustGuard(
        id="sanitize-before-s3-key",
        sink_pattern=r"generate_presigned_url\(|s3.*Key.*=.*f['\"]",
        guard_pattern=r"(replace.*[/\\]|_safe_id|sanitize|basename|path_clean)",
        guard_type="input_sanitization",
        scope="before_sink",
        severity="HIGH",
        title_template="No path sanitization before S3 key construction in {handler}",
        description_template="Handler {handler} constructs an S3 key using user-controlled input without sanitizing path traversal characters (/, .., \\\\).",
        cwe="CWE-22",
    ),
    MustGuard(
        id="rate-limit-on-auth",
        sink_pattern=r"(cognito.*initiate_auth|sign_up|sign_in|authenticate)",
        guard_pattern=r"(rate_limit|throttle|token_bucket|attempt.*count|max_attempts)",
        guard_type="rate_limit",
        scope="same_handler",
        severity="MEDIUM",
        title_template="No rate limiting on authentication endpoint {handler}",
        description_template="Authentication handler {handler} has no rate limiting, allowing unlimited brute-force attempts.",
        cwe="CWE-307",
    ),
    MustGuard(
        id="jwt-verify-before-use",
        sink_pattern=r"base64\.(b64decode|urlsafe_b64decode).*split.*\.",
        guard_pattern=r"(jwt\.decode|verify_token|jose\.|cryptography\.)",
        guard_type="jwt_verify",
        scope="same_handler",
        severity="HIGH",
        title_template="JWT decoded without signature verification in {handler}",
        description_template="Handler {handler} decodes a JWT using base64 without first verifying its signature, allowing token forgery.",
        cwe="CWE-345",
    ),
]


class AbsenceDetector:
    """
    Detects missing security controls by checking must-guard specifications
    against CPG paths.
    """

    def __init__(self, cpg: CodePropertyGraph, builder: EnhancedCPGBuilder):
        self.cpg = cpg
        self.builder = builder
        self._file_contents: dict[str, str] = {}

    def detect(self, specs: list[MustGuard] | None = None) -> list[AbsenceFinding]:
        """Run all absence detection specs and return findings."""
        specs = specs or MUST_GUARD_SPECS
        findings = []

        for spec in specs:
            spec_findings = self._check_spec(spec)
            findings.extend(spec_findings)

        # Deduplicate by (handler, spec_id)
        seen = set()
        deduped = []
        for f in findings:
            key = (f.handler_name, f.missing_guard, f.file_path)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        # Also run pattern mining
        mined = self._mine_missing_patterns()
        for m in mined:
            key = (m.handler_name, m.missing_guard, m.file_path)
            if key not in seen:
                seen.add(key)
                deduped.append(m)

        logger.info(f"Absence detector: {len(deduped)} findings ({len(findings)} raw, {len(mined)} mined)")
        return deduped

    def _check_spec(self, spec: MustGuard) -> list[AbsenceFinding]:
        """Check a single must-guard spec against all handlers and their called functions."""
        findings = []

        # Check handler-scoped functions
        for func_key, func_info in self.builder.functions.items():
            if not func_info.is_handler:
                continue

            # Get the FULL file text — handlers often dispatch to helper functions
            # in the same file that contain the actual sinks
            file_text = self._get_file_text(func_info.file_path)
            handler_text = self._get_handler_text(func_info)
            if not file_text:
                continue

            # Check if the entire file contains the sink pattern
            # (handler dispatches to sub-functions in same file)
            sink_matches = list(re.finditer(spec.sink_pattern, file_text))
            if not sink_matches:
                continue

            # Check if the file also contains the guard pattern
            has_guard = bool(re.search(spec.guard_pattern, file_text))

            if not has_guard:
                for match in sink_matches[:2]:
                    lines_before = file_text[:match.start()].count("\n")
                    sink_line = lines_before + 1

                    operation = match.group(0).rstrip("(")
                    title = spec.title_template.format(
                        operation=operation,
                        handler=func_info.name,
                    )
                    description = spec.description_template.format(
                        operation=operation,
                        handler=func_info.name,
                    )

                    findings.append(AbsenceFinding(
                        id=f"absence-{spec.id}-{func_info.name}",
                        title=title,
                        description=description,
                        severity=spec.severity,
                        confidence=0.85,
                        file_path=func_info.file_path,
                        line=sink_line,
                        handler_name=func_info.name,
                        sink_text=match.group(0),
                        missing_guard=spec.guard_type,
                        category=f"missing_{spec.guard_type}",
                        cwe=spec.cwe,
                        evidence=f"File contains {operation} but no pattern matching /{spec.guard_pattern}/ found in any function",
                    ))

        return findings

    def _get_file_text(self, file_path: str) -> str:
        """Get the full file text (cached)."""
        if file_path not in self._file_contents:
            try:
                self._file_contents[file_path] = Path(file_path).read_text()
            except (OSError, UnicodeDecodeError):
                self._file_contents[file_path] = ""
        return self._file_contents[file_path]

    def _mine_missing_patterns(self) -> list[AbsenceFinding]:
        """
        Statistical pattern mining: if >70% of handlers that call a sink
        also have a specific guard, flag handlers missing that guard.
        """
        findings = []

        # Group handlers by which sinks they contain
        sink_to_handlers: dict[str, list[tuple[FunctionInfo, bool]]] = {}

        for func_key, func_info in self.builder.functions.items():
            if not func_info.is_handler:
                continue

            handler_text = self._get_handler_text(func_info)
            if not handler_text:
                continue

            # Check for common sink → guard pairs
            patterns_to_mine = [
                ("table.get_item", r"customer_id.*!=|session.*customer_id|verify_owner"),
                ("table.delete_item", r"audit|log_event|logger\.info"),
                ("table.put_item", r"audit|log_event|logger\.info"),
            ]

            for sink_pat, guard_pat in patterns_to_mine:
                if sink_pat in handler_text:
                    has_guard = bool(re.search(guard_pat, handler_text))
                    sink_to_handlers.setdefault(sink_pat, []).append(
                        (func_info, has_guard)
                    )

        # Report handlers that deviate from the majority
        for sink_pat, handlers in sink_to_handlers.items():
            if len(handlers) < 3:
                continue

            guard_count = sum(1 for _, has in handlers if has)
            guard_rate = guard_count / len(handlers)

            if guard_rate >= 0.5:  # At least half have it
                for func_info, has_guard in handlers:
                    if not has_guard:
                        findings.append(AbsenceFinding(
                            id=f"mined-{sink_pat.replace('.', '_')}-{func_info.name}",
                            title=f"Deviates from common pattern: {func_info.name} missing guard before {sink_pat}",
                            description=(
                                f"{guard_count}/{len(handlers)} handlers that call {sink_pat} "
                                f"have a guard pattern, but {func_info.name} does not."
                            ),
                            severity="MEDIUM",
                            confidence=0.6,
                            file_path=func_info.file_path,
                            line=func_info.line,
                            handler_name=func_info.name,
                            sink_text=sink_pat,
                            missing_guard="deviant_pattern",
                            category="deviant_behavior",
                            evidence=f"Pattern adherence: {guard_count}/{len(handlers)} ({guard_rate:.0%})",
                        ))

        return findings

    def _get_handler_text(self, func_info: FunctionInfo) -> str:
        """Get the full text of a handler function."""
        if func_info.file_path not in self._file_contents:
            try:
                self._file_contents[func_info.file_path] = Path(func_info.file_path).read_text()
            except (OSError, UnicodeDecodeError):
                return ""

        content = self._file_contents[func_info.file_path]
        lines = content.split("\n")

        # Extract function body (from def line to next def at same/lower indent or EOF)
        start_line = func_info.line - 1  # 0-indexed
        if start_line >= len(lines):
            return ""

        # Find indent of the def line
        def_indent = len(lines[start_line]) - len(lines[start_line].lstrip())

        end_line = start_line + 1
        while end_line < len(lines):
            line = lines[end_line]
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                line_indent = len(line) - len(line.lstrip())
                if line_indent <= def_indent and (stripped.startswith("def ") or stripped.startswith("class ")):
                    break
            end_line += 1

        return "\n".join(lines[start_line:end_line])
