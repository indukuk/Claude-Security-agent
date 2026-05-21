"""
Validation Agent — adversarial false positive filtering.
Separate persona from detection agents (skeptic, not detective).
"""
from __future__ import annotations


import logging

from src.common.findings import (
    Finding, Severity, Confidence, ValidationVerdict,
)
from src.common.llm_client import LLMClient
from src.skills.validation_skills import (
    ADVERSARIAL_TEMPLATE, KNOWN_SAFE_PATTERNS,
    FRAMEWORK_PROTECTIONS, SEVERITY_ADJUSTMENTS,
)

logger = logging.getLogger(__name__)


class ValidationAgent:
    """
    Adversarial false positive filter.
    Operates with a different persona: skeptic and defense counsel.
    """

    SYSTEM_PROMPT = (
        "You are a senior security engineer acting as a skeptic and defense counsel. "
        "Your role is to critically evaluate security findings and determine whether they "
        "represent real, exploitable vulnerabilities or false positives.\n\n"
        "You approach each finding with skepticism — looking for reasons it might NOT be "
        "exploitable. You protect development teams from alert fatigue by ensuring only "
        "genuine vulnerabilities reach them.\n\n"
        "However, you must be intellectually honest. If you cannot find a valid reason "
        "a finding is safe, you must confirm it."
    )

    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client

    def validate_batch(self, findings: list[Finding]) -> list[Finding]:
        """
        Validate a batch of findings. Returns findings with validation verdicts.
        LOW severity passes without LLM validation (not worth the cost).
        """
        validated = []

        # Sort: CRITICAL first (most important to confirm)
        to_validate = sorted(
            [f for f in findings if f.severity != Severity.LOW],
            key=lambda f: f.severity.value,
            reverse=True,
        )

        for finding in to_validate:
            # Check known safe patterns first (free, no LLM)
            if self._is_known_safe(finding):
                finding.validation_verdict = ValidationVerdict.DISMISSED
                finding.confidence = Confidence.LOW
                logger.info(f"Dismissed (known safe): {finding.title}")
                continue

            # LLM adversarial validation
            verdict = self._validate_with_llm(finding)
            finding.validation_verdict = verdict

            if verdict == ValidationVerdict.DISMISSED:
                logger.info(f"Dismissed (LLM): {finding.title}")
            elif verdict == ValidationVerdict.CONFIRMED:
                logger.info(f"Confirmed: {finding.title}")
                validated.append(finding)
            else:  # UNCERTAIN
                finding.confidence = Confidence.LOW
                validated.append(finding)

        # LOW severity passes through without validation
        low_findings = [f for f in findings if f.severity == Severity.LOW]
        for f in low_findings:
            f.validation_verdict = ValidationVerdict.CONFIRMED
        validated.extend(low_findings)

        dismissed_count = len(findings) - len(validated)
        logger.info(
            f"Validation complete: {len(validated)} confirmed, "
            f"{dismissed_count} dismissed ({dismissed_count / max(len(findings), 1) * 100:.0f}% FP rate)"
        )

        return validated

    def _is_known_safe(self, finding: Finding) -> bool:
        """Check against known false positive patterns (no LLM needed)."""
        for pattern in KNOWN_SAFE_PATTERNS:
            pattern_text = pattern.get("finding_pattern", "").lower()
            if pattern_text and pattern_text in finding.title.lower():
                # Check dismiss condition
                dismiss_if = pattern.get("dismiss_if", "")
                if dismiss_if and dismiss_if.lower() in finding.evidence.snippet.lower():
                    return True
                # Check keep condition
                keep_if = pattern.get("keep_if", "")
                if keep_if and keep_if.lower() in finding.evidence.snippet.lower():
                    return False
                # No specific condition — apply the pattern
                if not pattern.get("keep_if"):
                    return True
        return False

    def _validate_with_llm(self, finding: Finding) -> ValidationVerdict:
        """Use LLM to argue why a finding is NOT exploitable."""
        # Get applicable framework protections
        protections = self._get_applicable_protections(finding)

        prompt = ADVERSARIAL_TEMPLATE.format(
            category=finding.category,
            severity=finding.severity.name,
            title=finding.title,
            description=finding.description,
            evidence=finding.evidence.snippet[:500],
            applicable_protections=protections,
        )

        try:
            response = self.llm.analyze(
                system_prompt=self.SYSTEM_PROMPT,
                user_prompt=prompt,
                task_type="validation",
                temperature=0.2,  # Slightly higher for creative counter-arguments
            )
            return self._parse_verdict(response)

        except Exception as e:
            logger.warning(f"Validation LLM call failed: {e}")
            return ValidationVerdict.UNCERTAIN

    def _parse_verdict(self, response: str) -> ValidationVerdict:
        """Parse LLM response into a verdict."""
        lower = response.lower()

        if "confirmed" in lower and "dismissed" not in lower.split("confirmed")[0][-50:]:
            return ValidationVerdict.CONFIRMED
        if "dismissed" in lower:
            return ValidationVerdict.DISMISSED
        if "uncertain" in lower:
            return ValidationVerdict.UNCERTAIN

        # Fallback: if response argues it's safe, dismiss; otherwise confirm
        safe_indicators = ["not exploitable", "mitigated by", "prevented by", "false positive"]
        if any(indicator in lower for indicator in safe_indicators):
            return ValidationVerdict.DISMISSED

        return ValidationVerdict.CONFIRMED

    def _get_applicable_protections(self, finding: Finding) -> str:
        """Get framework protections relevant to this finding type."""
        relevant = []

        if finding.agent in ("python", "javascript"):
            if "auth" in finding.category or "tenant" in finding.category:
                relevant.append(FRAMEWORK_PROTECTIONS.get("api_gateway_authorizer", {}))
                relevant.append(FRAMEWORK_PROTECTIONS.get("cognito_token_validation", {}))
            if "injection" in finding.category or "nosql" in finding.category:
                relevant.append(FRAMEWORK_PROTECTIONS.get("dynamodb_expression_attributes", {}))
            if "validation" in finding.category:
                relevant.append(FRAMEWORK_PROTECTIONS.get("pydantic_validation", {}))

        if finding.agent == "infrastructure":
            if "s3" in finding.category or "public" in finding.category:
                relevant.append(FRAMEWORK_PROTECTIONS.get("s3_block_public_access", {}))

        # Format for LLM
        lines = []
        for prot in relevant:
            if prot:
                name = prot.get("protection", "")
                prevents = prot.get("what_it_prevents", [])
                doesnt = prot.get("what_it_does_not_prevent", [])
                lines.append(f"Protection: {name}")
                lines.append(f"  Prevents: {', '.join(prevents[:3])}")
                lines.append(f"  Does NOT prevent: {', '.join(doesnt[:3])}")

        return "\n".join(lines) if lines else "No specific framework protections identified."
