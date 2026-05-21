"""
Layer 5: Narrative Synthesis Agent.

One senior-analyst agent reads ALL investigation reports, debate verdicts,
exploit proofs, and fix verifications. Produces the final report.

This is the only agent that writes user-facing text.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from v5.agents.cot_synthesizer import CoTFinding
from v5.agents.debate.engine import DebateVerdict
from v5.agents.prover.exploit_generator import ExploitProof
from v5.agents.prover.fix_verifier import ProvenFix
from v5.analysis.zero_trust_analyzer import ZeroTrustAssessment
from v5.agents.base import AgentContext

logger = logging.getLogger(__name__)


NARRATOR_SYSTEM = """You are a principal security consultant writing a report for a CISO.
You have access to the complete investigation performed by your team:
- 5 domain expert investigations
- Chain-of-thought analysis per finding
- Adversarial debate verdicts with citation-quality scoring
- Exploit proofs (concrete curl commands)
- Verified fixes with re-scan confirmation
- Zero trust assessment (blast radius, lateral movement)
- Attack chain composition with formal severity

Write findings that a senior engineer can ACT ON without further investigation.

Principles:
- Specific titles that include the IMPACT (not "Missing auth check" but
  "Unverified JWT Decode Enables Tenant Spoofing in Bedrock Session")
- Evidence walks as the primary evidence format (step-by-step trace)
- Explicit verified/unverified separation
- Fixes that reference existing secure patterns in the same codebase
- Group findings by THEME (tenant isolation, auth, input validation, etc.)
  not just severity
- Attack chains presented as composite narratives
- Zero trust assessment as a separate section showing blast radius map"""


NARRATOR_PROMPT = """## Write the Final Security Report

### Input: Complete Analysis Results

{analysis_summary}

### Report Structure Required:

1. **Executive Summary** (3-5 sentences for a CISO)
   - Total findings with severity breakdown
   - Top 3 risks in business terms
   - Overall security posture assessment
   - Zero trust compliance status

2. **Zero Trust Assessment**
   - Blast radius map (which resources have uncontained access)
   - Lateral movement paths
   - "Assume breach" top scenario
   - Containment recommendations

3. **Findings by Theme** (NOT just sorted by severity)
   Themes: Tenant Isolation | Authentication | Authorization |
   Input Validation | Secrets & Crypto | Operational Controls

   Per finding:
   - Title (specific, includes impact)
   - Severity | Confidence | Risk Type | CWE
   - Description (2-3 paragraphs: what, why, how to exploit)
   - Evidence Walk (step-by-step source→sink trace)
   - Verified / Could Not Verify
   - Attack Chains involving this finding
   - Suggested Fix (short-term code + long-term architecture)

4. **Attack Chains** (multi-step exploit narratives)
   - Full narrative per chain
   - Composite severity justification
   - Which individual findings compose the chain

5. **Recommendations** (prioritized by effort × impact)
   - Immediate (code patches — hours)
   - Short-term (configuration changes — days)
   - Long-term (architectural redesign — weeks)

Write the complete report now."""


@dataclass
class FinalReport:
    """The complete V5 final report."""
    markdown: str = ""
    findings_count: int = 0
    critical_count: int = 0
    attack_chains_count: int = 0
    zero_trust_posture: str = ""


class NarratorAgent:
    """
    Synthesizes all analysis into the final report.
    Can operate in API mode (calls LLM) or produce the synthesis prompt
    for in-session execution.
    """

    def __init__(self):
        pass

    def synthesize(self, context: AgentContext,
                   cot_findings: list[CoTFinding],
                   verdicts: list[DebateVerdict],
                   exploits: list[ExploitProof],
                   fixes: list[ProvenFix],
                   zero_trust: ZeroTrustAssessment | None,
                   attack_chains: list,
                   llm_fn=None) -> FinalReport:
        """Produce the final report."""
        summary = self._build_analysis_summary(
            cot_findings, verdicts, exploits, fixes, zero_trust, attack_chains
        )

        prompt = NARRATOR_PROMPT.format(analysis_summary=summary)

        if llm_fn:
            response = llm_fn(system=NARRATOR_SYSTEM, user=prompt)
            return FinalReport(
                markdown=response,
                findings_count=len(cot_findings),
                critical_count=sum(1 for f in cot_findings if f.severity == "CRITICAL"),
                attack_chains_count=len(attack_chains),
                zero_trust_posture=zero_trust.overall_posture if zero_trust else "NOT_ASSESSED",
            )
        else:
            # In-session mode: produce the prompt
            return FinalReport(
                markdown=f"# V5 Report Synthesis Prompt\n\n{NARRATOR_SYSTEM}\n\n---\n\n{prompt}",
                findings_count=len(cot_findings),
            )

    def generate_synthesis_prompt(self, context: AgentContext,
                                   cot_findings: list[CoTFinding],
                                   zero_trust: ZeroTrustAssessment | None,
                                   attack_chains: list) -> str:
        """Generate the full narrator prompt for in-session execution."""
        summary = self._build_analysis_summary(
            cot_findings, [], [], [], zero_trust, attack_chains
        )
        return f"{NARRATOR_SYSTEM}\n\n---\n\n{NARRATOR_PROMPT.format(analysis_summary=summary)}"

    def _build_analysis_summary(self, cot_findings, verdicts, exploits,
                                 fixes, zero_trust, attack_chains) -> str:
        """Build the analysis summary input for the narrator."""
        sections = []

        # Findings summary
        sections.append(f"### Findings: {len(cot_findings)} total")
        sev_counts = {}
        for f in cot_findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        sections.append(f"Severity: {sev_counts}")
        sections.append("")

        for i, f in enumerate(cot_findings[:20], 1):
            sections.append(f"**{i}. [{f.severity}] {f.title}**")
            if f.entry_point_analysis:
                sections.append(f"  Entry: {f.entry_point_analysis[:150]}")
            if f.data_flow_trace:
                sections.append(f"  Flow: {f.data_flow_trace[:200]}")
            if f.exploit:
                sections.append(f"  Exploit: {f.exploit[:200]}")
            if f.verified:
                sections.append(f"  Verified: {f.verified[:3]}")
            if f.could_not_verify:
                sections.append(f"  Unverified: {f.could_not_verify[:3]}")
            sections.append("")

        # Zero trust
        if zero_trust:
            sections.append(f"\n### Zero Trust Assessment")
            sections.append(f"Posture: {zero_trust.overall_posture}")
            sections.append(f"Uncontained: {zero_trust.summary.get('uncontained', 0)}")
            sections.append(f"Lateral paths: {len(zero_trust.lateral_paths)}")
            for rid, br in zero_trust.blast_radii.items():
                if br.containment_status == "UNCONTAINED":
                    sections.append(
                        f"  UNCONTAINED: {br.iam_role} | "
                        f"{'INTERNET' if br.is_internet_facing else 'internal'} | "
                        f"auth={br.auth_mechanism} | "
                        f"caps: all_tenants={br.can_access_all_tenants}, "
                        f"exfil={br.can_exfiltrate_data}, modify={br.can_modify_data}"
                    )
            sections.append("")

        # Attack chains
        if attack_chains:
            sections.append(f"\n### Attack Chains: {len(attack_chains)}")
            for chain in attack_chains[:5]:
                if hasattr(chain, "narrative"):
                    sections.append(chain.narrative[:300])
                    sections.append("")

        # Debate verdicts
        if verdicts:
            sections.append(f"\n### Debate Verdicts: {len(verdicts)}")
            for v in verdicts:
                sections.append(f"  {v.decision} ({v.final_severity}) — {v.reasoning[:100]}")

        # Exploits
        if exploits:
            sections.append(f"\n### Exploit Proofs: {len(exploits)}")
            for e in exploits[:5]:
                sections.append(f"  {e.title}: {e.exploit_type}")

        return "\n".join(sections)
