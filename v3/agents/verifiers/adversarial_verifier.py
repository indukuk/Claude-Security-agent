"""
Adversarial Verifier — 3+1 Game-Theoretic pattern.

After the grounded debate confirms a finding, a CHEAP model (Haiku)
independently tries to dismiss it. If even a weak model can construct
a valid dismissal, the finding is likely a false positive.

From research (Apr 2026): adds +10.3pp precision at ~$0.001/finding.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from v3.agents.verifiers.evidence_bundle import EvidenceBundle
from v3.agents.verifiers.grounded_debate import Verdict

logger = logging.getLogger(__name__)


@dataclass
class ChallengeResult:
    """Result of adversarial challenge."""
    challenged: bool  # Did the verifier attempt a challenge?
    dismissed: bool  # Did the challenge succeed (finding should be downgraded)?
    argument: str  # The dismissal argument
    cited_evidence_ids: list[int]  # Evidence cited in dismissal
    confidence: float = 0.0


class AdversarialVerifier:
    """
    A cheap model attempts to dismiss each confirmed finding.

    If it constructs a valid argument citing evidence from the bundle,
    the finding is flagged for human review or downgraded.

    Design rationale: if even a weak model can dismiss it,
    the prosecution's case was probably weak.
    """

    def generate_challenge_prompt(self, verdict: Verdict,
                                   bundle: EvidenceBundle) -> str:
        """Generate the adversarial challenge prompt."""
        evidence_text = bundle.render_for_debate()

        return f"""You are an ADVERSARIAL VERIFIER. Your ONLY goal is to find reasons to DISMISS this finding.

## CONFIRMED FINDING
Title: {bundle.finding_title}
Verdict: {verdict.decision} at {verdict.severity}
Judge's reasoning: {verdict.reasoning}

## EVIDENCE BUNDLE
{evidence_text}

## YOUR TASK
Try to DISMISS this finding. Look for ANY reason it might be a false positive.

STRATEGY:
1. Check if cited sanitizers were overlooked by the judge
2. Check if IAM conditions actually restrict the attack
3. Check if the attack requires preconditions that are unlikely in practice
4. Check if the "source" is actually attacker-controllable
5. Check if framework protections (Pydantic validation, parameterized queries) block exploitation

RULES:
- You MUST cite evidence [EX] for any claim
- If you cannot find a valid reason to dismiss → output "CHALLENGE FAILED"
- Be aggressive — try hard to find a dismissal reason

## OUTPUT FORMAT
**Challenge:** DISMISSED | FAILED
**Argument:** [your dismissal reason citing evidence]
**Confidence:** 0.0-1.0
**Cited Evidence:** [EX, EY, ...]
"""

    def evaluate_challenge(self, challenge_response: str,
                           bundle: EvidenceBundle) -> ChallengeResult:
        """
        Parse and validate an adversarial challenge response.

        Verifies that cited evidence actually exists in the bundle.
        """
        dismissed = "DISMISSED" in challenge_response.upper().split("CHALLENGE:")[0] if "CHALLENGE:" in challenge_response.upper() else False

        # Extract cited evidence IDs
        import re
        cited_ids = [int(x) for x in re.findall(r'\[E(\d+)\]', challenge_response)]

        # Validate citations exist
        valid_citations = [eid for eid in cited_ids if bundle.get_item(eid) is not None]

        # A dismissal is only valid if it cites at least one real evidence item
        if dismissed and not valid_citations:
            logger.info(f"Challenge dismissed but no valid citations — rejecting")
            dismissed = False

        return ChallengeResult(
            challenged=True,
            dismissed=dismissed,
            argument=challenge_response[:500],
            cited_evidence_ids=valid_citations,
            confidence=len(valid_citations) / max(len(cited_ids), 1),
        )
