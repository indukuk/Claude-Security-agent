"""
Fix Verifier — apply fix → re-run detection → confirm finding disappears.

Protocol:
1. Generate fix via FixGenerator
2. Apply fix to a temp copy of the source file
3. Re-run the detection rule (Semgrep or Z3) on the fixed file
4. If finding disappears → VERIFIED
5. If finding persists → retry with refined fix (up to max_retries)
"""
from __future__ import annotations

import logging
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from v3.agents.provers.fix_generator import Fix, FixGenerator
from v3.tools.semgrep_tools import run_semgrep_on_file

logger = logging.getLogger(__name__)


@dataclass
class FixVerificationResult:
    """Result of fix verification."""
    status: str  # "VERIFIED" | "FAILED" | "NO_FIX" | "ERROR"
    fix: Fix | None
    findings_before: int
    findings_after: int
    attempts: int
    message: str


class FixVerifier:
    """
    Verify that a generated fix actually eliminates the vulnerability.
    Applies fix to a temp copy and re-runs the detection rule.
    """

    def __init__(self, rules_dir: str, max_retries: int = 3):
        self.rules_dir = Path(rules_dir)
        self.max_retries = max_retries
        self.generator = FixGenerator()

    def verify_fix(self, finding: dict, source_code: str,
                   rule_id: str | None = None) -> FixVerificationResult:
        """
        Generate a fix and verify it eliminates the finding.

        Args:
            finding: The finding dict (id, title, category, file_path, line, etc.)
            source_code: The full source code of the vulnerable file
            rule_id: Optional Semgrep rule ID that detected this finding

        Returns:
            FixVerificationResult with VERIFIED/FAILED status
        """
        # Determine which rules file to use for re-verification
        rules_path = self._resolve_rules_path(finding)
        if not rules_path:
            return FixVerificationResult(
                status="ERROR", fix=None, findings_before=0,
                findings_after=0, attempts=0,
                message="No rules file found for re-verification"
            )

        # Count initial findings on original file
        findings_before = self._count_findings(
            source_code, rules_path, rule_id, finding.get("file_path", "vuln.py")
        )

        # Short-circuit: if no Semgrep rule fires on the original, we can't verify a fix
        if findings_before == 0:
            return FixVerificationResult(
                status="NOT_APPLICABLE", fix=None,
                findings_before=0, findings_after=0, attempts=0,
                message="No Semgrep rule fires on this file — fix verification not applicable"
            )

        fix = None
        findings_after = findings_before

        for attempt in range(1, self.max_retries + 1):
            fix = self.generator.generate(finding, source_code)
            if not fix:
                return FixVerificationResult(
                    status="NO_FIX", fix=None,
                    findings_before=findings_before, findings_after=findings_before,
                    attempts=attempt,
                    message="No fix pattern matched this finding"
                )

            # Apply fix to source code
            fixed_code = self._apply_fix(source_code, fix)
            if fixed_code == source_code:
                logger.warning(f"Fix pattern did not match source code")
                return FixVerificationResult(
                    status="NO_FIX", fix=fix,
                    findings_before=findings_before, findings_after=findings_before,
                    attempts=attempt,
                    message="Fix pattern does not match actual source code"
                )

            # Re-run detection on fixed code
            findings_after = self._count_findings(
                fixed_code, rules_path, rule_id, finding.get("file_path", "vuln.py")
            )

            if findings_after < findings_before:
                logger.info(
                    f"Fix VERIFIED (attempt {attempt}): "
                    f"{findings_before} → {findings_after} findings"
                )
                return FixVerificationResult(
                    status="VERIFIED", fix=fix,
                    findings_before=findings_before,
                    findings_after=findings_after,
                    attempts=attempt,
                    message=f"Fix eliminates finding ({findings_before} → {findings_after})"
                )
            else:
                logger.info(
                    f"Fix attempt {attempt} did not eliminate finding "
                    f"({findings_before} → {findings_after})"
                )

        return FixVerificationResult(
            status="FAILED", fix=fix,
            findings_before=findings_before,
            findings_after=findings_after,
            attempts=self.max_retries,
            message=f"Fix did not eliminate finding after {self.max_retries} attempts"
        )

    def _apply_fix(self, source_code: str, fix: Fix) -> str:
        """Apply a fix to the source code via string replacement."""
        if fix.original_code in source_code:
            return source_code.replace(fix.original_code, fix.fixed_code, 1)
        return source_code

    def _count_findings(self, source_code: str, rules_path: str,
                        rule_id: str | None, filename: str) -> int:
        """Write source to temp file and run Semgrep, return finding count."""
        suffix = Path(filename).suffix or ".py"
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False, prefix="fixverify_"
        ) as tmp:
            tmp.write(source_code)
            tmp_path = tmp.name

        try:
            findings = run_semgrep_on_file(rules_path, tmp_path, rule_id)
            return len(findings)
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def _resolve_rules_path(self, finding: dict) -> str | None:
        """Determine which rules file to use based on finding category."""
        category = finding.get("category", "")
        title = finding.get("title", "")

        # Map categories to rule files
        if any(k in category for k in ("cross_tenant", "taint", "injection")):
            candidates = ["semgrep_rules.yaml", "semgrep_rules_gaps.yaml"]
        elif "frontend" in category or "xss" in category or "dom" in title.lower():
            candidates = ["semgrep_rules_frontend.yaml"]
        else:
            candidates = ["semgrep_rules.yaml", "semgrep_rules_gaps.yaml"]

        for candidate in candidates:
            path = self.rules_dir / candidate
            if path.exists():
                return str(path)

        return None
