"""
V6 Layer 3: Adversarial Grounded Debate (Production).

Validated prompt structure: separate P/D/J calls, citation-required,
"cannot invent mitigations" defense rule, "discard uncited" judge rule.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


PROSECUTION_SYSTEM = """You are an offensive security researcher arguing this vulnerability IS exploitable.

RULES:
- Every claim MUST cite evidence as [N]
- Demonstrate the COMPLETE attack path (entry → exploitation → impact)
- Show that no mitigation blocks exploitation
- If Z3 proofs exist in evidence, cite them as strongest support
- Claims without [N] citations will be DISCARDED by the judge"""

DEFENSE_SYSTEM = """You are the application developer arguing this vulnerability is mitigated or lower severity.

RULES:
- Every claim MUST cite evidence as [N]
- You CANNOT invent mitigations not present in the evidence bundle
- You CAN note "evidence does not show X" as genuine uncertainty
- You CAN argue lower severity with cited justification
- If you cannot find genuine mitigation, acknowledge it and focus on impact reduction"""

JUDGE_SYSTEM = """You are a principal security engineer judging this vulnerability debate.

PROCESS:
1. DISCARD any argument not backed by [N] citation
2. Weight: Z3_proof > code_evidence > infra_config > inferred_behavior
3. Did prosecution prove the COMPLETE path? (entry → exploit → impact)
4. Did defense find GENUINE mitigation IN the evidence (not hypothetical)?

VERDICT FORMAT:
- Decision: CONFIRMED / CONFIRMED_ADJUSTED / DISMISSED
- Final severity: CRITICAL / HIGH / MEDIUM / LOW
- Confidence: HIGH / MEDIUM / LOW
- Strongest prosecution point: [cite evidence]
- Strongest defense point: [cite evidence or "none effective"]
- Verified: [claims proven]
- Could not verify: [claims with uncertainty]
- Reasoning: 2-3 sentences"""


@dataclass
class EvidenceItem:
    id: int
    category: str
    content: str
    source: str


@dataclass
class Verdict:
    decision: str  # CONFIRMED / CONFIRMED_ADJUSTED / DISMISSED
    severity: str
    confidence: str
    reasoning: str
    prosecution_best: str = ""
    defense_best: str = ""
    verified: list[str] = field(default_factory=list)
    could_not_verify: list[str] = field(default_factory=list)


class DebateEngine:
    """Production debate engine with separate P/D/J calls."""

    def build_evidence_bundle(self, finding: dict, context: dict) -> list[EvidenceItem]:
        """Assemble numbered evidence for the debate."""
        items = []
        idx = 1

        # Code at finding location
        if finding.get("file_path"):
            items.append(EvidenceItem(idx, "code",
                f"File: {finding['file_path']}:{finding.get('line', 0)}", "source"))
            idx += 1

        # Evidence walk if available
        if context.get("evidence_walk"):
            items.append(EvidenceItem(idx, "walk", context["evidence_walk"][:400], "evidence_walker"))
            idx += 1

        # Z3 proofs
        for proof in context.get("z3_proofs", [])[:2]:
            items.append(EvidenceItem(idx, "z3_proof",
                f"{proof.get('title')}: {proof.get('z3_proof', '')[:200]}", "z3_solver"))
            idx += 1

        # Blast radius
        if context.get("blast_radius"):
            items.append(EvidenceItem(idx, "infra", context["blast_radius"][:300], "zero_trust"))
            idx += 1

        # Secure contrast
        if context.get("secure_contrast"):
            items.append(EvidenceItem(idx, "contrast", context["secure_contrast"][:300], "differential"))
            idx += 1

        # CoT reasoning
        if context.get("cot_reasoning"):
            items.append(EvidenceItem(idx, "cot", context["cot_reasoning"][:500], "layer2_cot"))
            idx += 1

        return items

    def render_bundle(self, items: list[EvidenceItem]) -> str:
        """Render evidence bundle as numbered text."""
        lines = ["## EVIDENCE BUNDLE (shared, immutable)\n"]
        for item in items:
            lines.append(f"[{item.id}] ({item.category}) — {item.source}")
            lines.append(f"    {item.content}")
            lines.append("")
        return "\n".join(lines)

    def build_prosecution_prompt(self, finding: dict, bundle_text: str) -> str:
        return (
            f"## Debate: {finding.get('title', '')}\n"
            f"Claimed severity: {finding.get('severity', '')}\n\n"
            f"{bundle_text}\n\n"
            "Argue this IS exploitable. Cite [N] for every claim.\n"
            "Prove: (1) complete attack path, (2) no mitigation, (3) significant impact."
        )

    def build_defense_prompt(self, finding: dict, bundle_text: str) -> str:
        return (
            f"## Debate: {finding.get('title', '')}\n"
            f"Claimed severity: {finding.get('severity', '')}\n\n"
            f"{bundle_text}\n\n"
            "Argue this is mitigated or lower severity. Cite [N] for every claim.\n"
            "You CANNOT invent protections not in the evidence. If none exist, acknowledge it."
        )

    def build_judge_prompt(self, finding: dict, bundle_text: str,
                          prosecution: str, defense: str) -> str:
        return (
            f"## Judge: {finding.get('title', '')}\n\n"
            f"{bundle_text}\n\n"
            f"### PROSECUTION:\n{prosecution}\n\n"
            f"### DEFENSE:\n{defense}\n\n"
            "Render your verdict following the format in your system prompt."
        )

    def debate(self, finding: dict, context: dict, llm_fn=None) -> Verdict:
        """Run full 3-call debate."""
        items = self.build_evidence_bundle(finding, context)
        bundle_text = self.render_bundle(items)

        if not llm_fn:
            return Verdict("PENDING", finding.get("severity", ""), "PENDING",
                          "Debate not executed (no LLM)")

        prosecution = llm_fn(system=PROSECUTION_SYSTEM,
                            user=self.build_prosecution_prompt(finding, bundle_text))
        defense = llm_fn(system=DEFENSE_SYSTEM,
                        user=self.build_defense_prompt(finding, bundle_text))
        judge_response = llm_fn(system=JUDGE_SYSTEM,
                               user=self.build_judge_prompt(finding, bundle_text, prosecution, defense))

        return self._parse_verdict(judge_response, finding)

    def generate_debate_prompt(self, finding: dict, context: dict) -> str:
        """Generate full debate prompt for in-session execution."""
        items = self.build_evidence_bundle(finding, context)
        bundle_text = self.render_bundle(items)

        return (
            f"# Debate: {finding.get('title', '')}\n\n"
            f"{bundle_text}\n\n"
            f"---\n## PROSECUTION\n{PROSECUTION_SYSTEM}\n\n"
            f"{self.build_prosecution_prompt(finding, bundle_text)}\n\n"
            f"---\n## DEFENSE\n{DEFENSE_SYSTEM}\n\n"
            f"{self.build_defense_prompt(finding, bundle_text)}\n\n"
            f"---\n## JUDGE\n{JUDGE_SYSTEM}\n\n"
            "(Judge evaluates after both sides complete.)\n"
        )

    def _parse_verdict(self, response: str, finding: dict) -> Verdict:
        verdict = Verdict(
            decision="CONFIRMED",
            severity=finding.get("severity", "HIGH"),
            confidence="HIGH",
            reasoning=response[:500],
        )
        for d in ("CONFIRMED_ADJUSTED", "CONFIRMED", "DISMISSED"):
            if d in response:
                verdict.decision = d
                break
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if f"severity: {s}" in response or f"severity**: {s}" in response:
                verdict.severity = s
                break
        return verdict
