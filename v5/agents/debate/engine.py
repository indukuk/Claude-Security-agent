"""
Layer 3: Adversarial Grounded Debate.

Prosecutor argues exploitability. Defender argues safety.
Judge evaluates citation quality and renders verdict.

ALL claims must cite numbered evidence items from the shared bundle.
Uncited claims are discarded by the judge. Z3 proofs outweigh heuristics.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from v5.agents.cot_synthesizer import CoTFinding

logger = logging.getLogger(__name__)


@dataclass
class EvidenceItem:
    """A numbered evidence item in the debate bundle."""
    id: int
    category: str  # "code" | "z3_proof" | "infra" | "contrast" | "cot_reasoning" | "walk"
    content: str
    source: str  # file:line or analysis component


@dataclass
class DebateArgument:
    """An argument from prosecutor or defender."""
    role: str  # "prosecutor" | "defender"
    position: str
    cited_evidence: list[int] = field(default_factory=list)


@dataclass
class DebateVerdict:
    """Judge's final verdict."""
    decision: str  # "CONFIRMED" | "CONFIRMED_ADJUSTED" | "DISMISSED"
    final_severity: str
    confidence: str  # "HIGH" | "MEDIUM" | "LOW"
    reasoning: str
    strongest_prosecution: str = ""
    strongest_defense: str = ""
    verified: list[str] = field(default_factory=list)
    could_not_verify: list[str] = field(default_factory=list)


PROSECUTOR_SYSTEM = """You are an offensive security researcher arguing that a vulnerability finding IS exploitable and DOES represent a genuine security risk.

RULES:
1. Every claim MUST cite an evidence item as [N] where N is the evidence ID
2. Claims without citations will be DISCARDED by the judge
3. You must demonstrate the COMPLETE attack path from entry to impact
4. Z3 proofs [if present] are mathematical facts — cite them as strongest evidence
5. "Could theoretically be exploited" is not enough — show the SPECIFIC exploit path

Your goal: prove this finding is real, exploitable, and impactful."""

DEFENDER_SYSTEM = """You are the application developer arguing that a vulnerability finding is mitigated, unexploitable, or lower severity than claimed.

RULES:
1. Every claim MUST cite an evidence item as [N] where N is the evidence ID
2. Claims without citations will be DISCARDED by the judge
3. You CANNOT invent mitigations not present in the evidence — only cite what IS there
4. You CAN point out missing context ("evidence does not show X, which could mitigate")
5. You CAN argue lower severity if impact is contained

Your goal: find genuine mitigating factors. Do NOT hallucinate protections that don't exist.
If the evidence clearly shows exploitability, acknowledge it and focus on impact reduction."""

JUDGE_SYSTEM = """You are a principal security engineer with 15 years experience judging a vulnerability debate.

RULES:
1. DISCARD any argument not backed by a citation [N]
2. Weight evidence types: Z3_proof > code_reading > infra_config > inferred_behavior
3. Prosecution must prove the COMPLETE path (entry → exploit → impact)
4. Defense wins only with CONCRETE mitigation cited in evidence (not hypothetical)
5. If prosecution proves exploitability but defense shows partial mitigation → CONFIRMED_ADJUSTED

Your verdict must include:
- Decision: CONFIRMED / CONFIRMED_ADJUSTED / DISMISSED
- Final severity (may adjust from original)
- Confidence: HIGH (all claims backed) / MEDIUM (one unverified link) / LOW (speculative)
- What was VERIFIED (proven by evidence)
- What COULD NOT BE VERIFIED (depends on deployment/runtime)"""


class DebateEngine:
    """
    Runs grounded debates on HIGH/CRITICAL findings.
    Each debate: evidence bundle → prosecutor → defender → judge → verdict.
    """

    def __init__(self):
        pass

    def debate(self, cot_finding: CoTFinding, evidence_items: list[EvidenceItem],
               llm_fn=None) -> DebateVerdict:
        """
        Run a full debate on a finding.

        Args:
            cot_finding: The enriched finding from Layer 2
            evidence_items: Numbered evidence bundle
            llm_fn: callable(system, user) -> str
        """
        bundle_text = self._render_evidence_bundle(evidence_items)

        # Build prosecution prompt
        prosecution_prompt = self._build_prosecution_prompt(cot_finding, bundle_text)
        # Build defense prompt
        defense_prompt = self._build_defense_prompt(cot_finding, bundle_text)

        if llm_fn:
            # Run debate via API
            prosecution = llm_fn(system=PROSECUTOR_SYSTEM, user=prosecution_prompt)
            defense = llm_fn(system=DEFENDER_SYSTEM, user=defense_prompt)

            # Judge evaluates both
            judge_prompt = self._build_judge_prompt(cot_finding, bundle_text, prosecution, defense)
            judge_response = llm_fn(system=JUDGE_SYSTEM, user=judge_prompt)

            return self._parse_verdict(judge_response, cot_finding)
        else:
            # In-session mode: return prompts
            return DebateVerdict(
                decision="PENDING",
                final_severity=cot_finding.severity,
                confidence="PENDING",
                reasoning="(debate not yet executed — prompts generated)",
            )

    def build_evidence_bundle(self, cot_finding: CoTFinding,
                              context_evidence: dict) -> list[EvidenceItem]:
        """Assemble the immutable evidence bundle for a debate."""
        items = []
        idx = 1

        # CPG evidence walk (if available)
        if cot_finding.data_flow_trace:
            items.append(EvidenceItem(
                id=idx, category="walk",
                content=cot_finding.data_flow_trace[:500],
                source="Layer 2 CoT Step 2",
            ))
            idx += 1

        # Source code at the sink
        file_path = cot_finding.original.get("file_path", "")
        if file_path and "source_snippet" in context_evidence:
            items.append(EvidenceItem(
                id=idx, category="code",
                content=context_evidence["source_snippet"][:800],
                source=f"{file_path}:{cot_finding.original.get('line', 0)}",
            ))
            idx += 1

        # Z3 proofs
        for proof in context_evidence.get("z3_proofs", []):
            items.append(EvidenceItem(
                id=idx, category="z3_proof",
                content=f"{proof.get('title')}\nProof: {proof.get('z3_proof', '')}",
                source="Z3 SMT solver",
            ))
            idx += 1

        # Infra config
        if "infra_config" in context_evidence:
            items.append(EvidenceItem(
                id=idx, category="infra",
                content=context_evidence["infra_config"][:500],
                source="CDK stack analysis",
            ))
            idx += 1

        # Secure contrast (from differential analysis)
        if "secure_contrast" in context_evidence:
            items.append(EvidenceItem(
                id=idx, category="contrast",
                content=context_evidence["secure_contrast"][:500],
                source="Differential analyzer",
            ))
            idx += 1

        # CoT reasoning
        if cot_finding.full_reasoning:
            items.append(EvidenceItem(
                id=idx, category="cot_reasoning",
                content=cot_finding.full_reasoning[:1000],
                source="Layer 2 CoT analysis",
            ))
            idx += 1

        # Blast radius
        if "blast_radius" in context_evidence:
            items.append(EvidenceItem(
                id=idx, category="infra",
                content=context_evidence["blast_radius"],
                source="Zero trust analyzer",
            ))
            idx += 1

        return items

    def _render_evidence_bundle(self, items: list[EvidenceItem]) -> str:
        """Render evidence bundle as numbered list."""
        lines = ["## EVIDENCE BUNDLE (shared, immutable)\n"]
        for item in items:
            lines.append(f"[{item.id}] ({item.category}) — Source: {item.source}")
            lines.append(f"    {item.content[:300]}")
            lines.append("")
        return "\n".join(lines)

    def _build_prosecution_prompt(self, finding: CoTFinding, bundle: str) -> str:
        return f"""## Debate: {finding.title}
Original severity: {finding.severity}

{bundle}

---

Argue that this finding IS exploitable and represents a genuine security risk.
You MUST cite [N] for every factual claim.

Demonstrate:
1. The attack is feasible end-to-end (cite the path)
2. No effective mitigation exists (cite absence of controls)
3. Impact is significant (cite what data/operations are exposed)
4. The severity rating is appropriate or should be higher

Structure your argument clearly. Cite evidence for every point."""

    def _build_defense_prompt(self, finding: CoTFinding, bundle: str) -> str:
        return f"""## Debate: {finding.title}
Original severity: {finding.severity}

{bundle}

---

Argue that this finding is mitigated, unexploitable, or lower severity than claimed.
You MUST cite [N] for every factual claim.

Consider:
1. Mitigating controls visible in the evidence (framework, runtime, deployment)
2. Preconditions that limit exploitability (auth required, rate limiting)
3. Reduced impact (scoping, monitoring, tenant isolation at other layers)
4. Detection capability (audit logs, alerts that would fire)

IMPORTANT: Do NOT invent mitigations not present in the evidence bundle.
If you cannot find genuine mitigation in the evidence, acknowledge it."""

    def _build_judge_prompt(self, finding: CoTFinding, bundle: str,
                           prosecution: str, defense: str) -> str:
        return f"""## Judge's Review: {finding.title}
Original severity: {finding.severity}

{bundle}

---

### PROSECUTION ARGUMENT:
{prosecution}

---

### DEFENSE ARGUMENT:
{defense}

---

## Your Verdict

1. Score each argument by citation density and quality
2. DISCARD any claim not backed by [N] citation
3. Weigh: Z3 proofs > code evidence > inferred behavior
4. Did prosecution prove exploitability END-TO-END?
5. Did defense find GENUINE mitigation (not hypothetical)?

Render your verdict:
- **Decision**: CONFIRMED / CONFIRMED_ADJUSTED / DISMISSED
- **Final severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Confidence**: HIGH / MEDIUM / LOW
- **Strongest prosecution point**: (cite the evidence)
- **Strongest defense point**: (cite the evidence, or "none effective")
- **Verified**: [list of claims proven by evidence]
- **Could not verify**: [list of claims depending on deployment]
- **Reasoning**: (2-3 sentences justifying the verdict)"""

    def _parse_verdict(self, response: str, finding: CoTFinding) -> DebateVerdict:
        """Parse judge's response into structured verdict."""
        verdict = DebateVerdict(
            decision="CONFIRMED",
            final_severity=finding.severity,
            confidence="HIGH",
            reasoning=response[:500],
        )

        # Parse decision
        for decision in ("CONFIRMED_ADJUSTED", "CONFIRMED", "DISMISSED"):
            if decision in response:
                verdict.decision = decision
                break

        # Parse severity
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if f"severity**: {sev}" in response or f"severity: {sev}" in response:
                verdict.final_severity = sev
                break

        # Parse confidence
        for conf in ("HIGH", "MEDIUM", "LOW"):
            if f"Confidence**: {conf}" in response or f"confidence: {conf}" in response.lower():
                verdict.confidence = conf
                break

        return verdict

    def generate_debate_prompts(self, cot_finding: CoTFinding,
                                evidence_items: list[EvidenceItem]) -> str:
        """Generate full debate prompt set for in-session execution."""
        bundle = self._render_evidence_bundle(evidence_items)

        output = f"# Debate: {cot_finding.title}\n\n"
        output += f"## Evidence Bundle\n{bundle}\n\n"
        output += "---\n\n## PROSECUTION\n\n"
        output += f"{PROSECUTOR_SYSTEM}\n\n"
        output += self._build_prosecution_prompt(cot_finding, bundle)
        output += "\n\n---\n\n## DEFENSE\n\n"
        output += f"{DEFENDER_SYSTEM}\n\n"
        output += self._build_defense_prompt(cot_finding, bundle)
        output += "\n\n---\n\n## JUDGE\n\n"
        output += f"{JUDGE_SYSTEM}\n\n"
        output += "(Judge evaluates after prosecution and defense complete)\n"

        return output
