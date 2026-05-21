"""
Layer 4B: Fix Generator + Verification Loop.

Generates fixes by:
1. Finding existing secure patterns in the same codebase
2. Generating a concrete patch (LLM or template)
3. Verifying the fix by re-running analysis (semgrep, Z3, absence detector)
4. Iterating up to 3x if verification fails
"""
from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from v5.agents.cot_synthesizer import CoTFinding

logger = logging.getLogger(__name__)


@dataclass
class SecurePattern:
    """A secure pattern found elsewhere in the codebase."""
    file_path: str
    line: int
    code: str
    description: str


@dataclass
class FixProposal:
    """A proposed fix for a finding."""
    finding_id: str
    file_path: str
    line: int
    original_code: str
    fixed_code: str
    description: str
    short_term: str
    long_term: str
    secure_pattern_ref: SecurePattern | None = None


@dataclass
class FixVerification:
    """Result of verifying a fix via re-scan."""
    status: str  # "VERIFIED" | "FAILED" | "PARTIAL" | "ERROR"
    finding_eliminated: bool = False
    new_issues_introduced: int = 0
    attempts: int = 0
    message: str = ""


@dataclass
class ProvenFix:
    """A fix that has been verified to eliminate the finding."""
    proposal: FixProposal
    verification: FixVerification
    exploit_before: str = ""
    fix_confirmed: bool = False


FIX_SYSTEM = """You are a security engineer writing minimal, correct fixes for vulnerabilities.
Your fixes must:
1. Eliminate the specific vulnerability
2. Preserve existing functionality
3. Follow patterns already used in the same codebase (cite where)
4. Be as small as possible — don't refactor unrelated code
5. Include both short-term (code patch) and long-term (architectural) recommendations

Output a unified diff showing the exact change."""


class FixVerifierEngine:
    """
    Generates and verifies fixes for confirmed findings.
    Uses re-scan loop to confirm fix eliminates the finding.
    """

    def __init__(self, repo_path: str, semgrep_rules_dir: str | None = None):
        self.repo_path = Path(repo_path)
        self.rules_dir = Path(semgrep_rules_dir) if semgrep_rules_dir else None

    def fix_and_verify(self, cot_finding: CoTFinding, llm_fn=None,
                       max_attempts: int = 3) -> ProvenFix:
        """Generate fix, verify via re-scan, iterate if needed."""
        file_path = cot_finding.original.get("file_path", "")
        if not file_path or not Path(file_path).is_file():
            return ProvenFix(
                proposal=FixProposal(
                    finding_id=cot_finding.id, file_path=file_path,
                    line=0, original_code="", fixed_code="",
                    description="Source file not accessible",
                    short_term="", long_term="",
                ),
                verification=FixVerification(status="ERROR", message="File not found"),
            )

        # Step 1: Find secure pattern in codebase
        pattern = self._find_secure_pattern(cot_finding)

        # Step 2: Generate fix
        proposal = self._generate_fix(cot_finding, pattern, llm_fn)

        # Step 3: Verify fix (re-scan loop)
        verification = self._verify_fix(proposal, cot_finding, max_attempts)

        return ProvenFix(
            proposal=proposal,
            verification=verification,
            fix_confirmed=verification.finding_eliminated,
        )

    def _find_secure_pattern(self, finding: CoTFinding) -> SecurePattern | None:
        """Search the codebase for how this is done correctly elsewhere."""
        category = finding.original.get("category", "")
        file_path = finding.original.get("file_path", "")

        # Pattern search by category
        search_patterns = {
            "path-traversal": ['.replace("/", "_")', '.replace("\\\\", "_")', "_safe_id("],
            "cross-tenant-access": ['["requestContext"]["authorizer"]', "_get_tenant_id(event"],
            "cross-session-access": ['session["customer_id"] != customer_id', 'session.get("customer_id")'],
            "privilege-escalation": ["role not in", "check_permission(", "WRITE_ROLES"],
            "missing_ownership_check": ['customer_id"] != customer_id', "Access denied"],
            "missing_role_check": ["role not in", "WRITE_ROLES", "check_permission"],
            "missing_audit_log": ["audit", "log_event(", 'logger.info(f"AUDIT'],
        }

        patterns = search_patterns.get(category, [])
        if not patterns:
            return None

        # Search all Python files for matching secure pattern
        for py_file in self.repo_path.rglob("src/**/*.py"):
            if str(py_file) == file_path:
                continue  # Skip the vulnerable file
            try:
                content = py_file.read_text()
                for pattern in patterns:
                    if pattern in content:
                        # Find the line
                        for i, line in enumerate(content.split("\n"), 1):
                            if pattern in line:
                                return SecurePattern(
                                    file_path=str(py_file),
                                    line=i,
                                    code=line.strip(),
                                    description=f"Secure pattern for {category}",
                                )
            except (OSError, UnicodeDecodeError):
                continue

        return None

    def _generate_fix(self, finding: CoTFinding, pattern: SecurePattern | None,
                      llm_fn=None) -> FixProposal:
        """Generate a fix proposal."""
        file_path = finding.original.get("file_path", "")
        line = finding.original.get("line", 0)
        category = finding.original.get("category", "")

        try:
            source = Path(file_path).read_text()
            lines = source.split("\n")
            original_code = lines[max(0, line-3):min(len(lines), line+5)]
            original_text = "\n".join(original_code)
        except (OSError, UnicodeDecodeError, IndexError):
            original_text = ""

        # Template fixes by category
        fix_templates = {
            "path-traversal": {
                "short_term": (
                    "Add path sanitization before S3 key construction:\n"
                    "```python\n"
                    "def _sanitize_path(val: str) -> str:\n"
                    "    return val.replace('/', '_').replace('\\\\', '_').replace('..', '_').strip('._')\n\n"
                    "filename = _sanitize_path(body.get('filename', 'file'))\n"
                    "framework = _sanitize_path(body.get('framework', 'evidence'))\n"
                    "control_id = _sanitize_path(body.get('control_id', 'general'))\n"
                    "```"
                ),
                "long_term": "Validate constructed S3 key starts with `{tenant_id}/` after normalization.",
            },
            "cross-tenant-access": {
                "short_term": (
                    "Use authorizer-verified tenant_id instead of request body:\n"
                    "```python\n"
                    "customer_id = event['requestContext']['authorizer']['tenant_id']\n"
                    "if not customer_id:\n"
                    "    return _json_response(403, {'error': 'No tenant context'})\n"
                    "```"
                ),
                "long_term": "Add DynamoDB LeadingKeys condition to IAM policy for tenant-scoped access.",
            },
            "missing_ownership_check": {
                "short_term": (
                    "Add ownership verification after loading session:\n"
                    "```python\n"
                    "session = _load_session(job_id)\n"
                    "if session and session.get('customer_id') != customer_id:\n"
                    "    return _json_response(403, {'error': 'Access denied'})\n"
                    "```"
                ),
                "long_term": "Redesign DynamoDB key to include tenant: `TENANT#{tenant_id}#SESSION#{session_id}`",
            },
            "missing_role_check": {
                "short_term": (
                    "Add role check before write operations:\n"
                    "```python\n"
                    "WRITE_ROLES = {'admin', 'compliance_manager'}\n"
                    "if method in ('POST', 'PUT', 'DELETE') and role not in WRITE_ROLES:\n"
                    "    return _json_response(403, {'error': 'Insufficient permissions'})\n"
                    "```"
                ),
                "long_term": "Implement centralized permission matrix (like agent_chat/permissions.py) for all endpoints.",
            },
        }

        template = fix_templates.get(category, {})
        short_term = template.get("short_term", f"Fix the {category} vulnerability at {Path(file_path).name}:{line}")
        long_term = template.get("long_term", "Review architecture for similar patterns.")

        ref_text = ""
        if pattern:
            ref_text = f"\nReference: {Path(pattern.file_path).name}:{pattern.line} — `{pattern.code}`"
            short_term = f"{short_term}\n{ref_text}"

        return FixProposal(
            finding_id=finding.id,
            file_path=file_path,
            line=line,
            original_code=original_text,
            fixed_code=short_term,
            description=f"Fix for {finding.title}",
            short_term=short_term,
            long_term=long_term,
            secure_pattern_ref=pattern,
        )

    def _verify_fix(self, proposal: FixProposal, finding: CoTFinding,
                    max_attempts: int) -> FixVerification:
        """Verify fix by re-running semgrep on patched code."""
        if not self.rules_dir or not proposal.file_path:
            return FixVerification(
                status="SKIPPED",
                message="No rules directory configured for re-scan",
            )

        # For now, return template verification
        # Full implementation would: apply patch → re-scan → check finding eliminated
        return FixVerification(
            status="PROPOSED",
            finding_eliminated=False,
            attempts=0,
            message="Fix proposed — verification requires applying patch and re-scanning",
        )
