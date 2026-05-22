"""
V6 Layer 5: Narrative Synthesis (Production).

Single senior-analyst agent writes the final report from all prior layers.
Uses structured template + domain persona validated in testing.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


SYSTEM = """You are a principal security consultant writing a report for a CISO and their engineering team.

Your report must be ACTIONABLE — a senior engineer can fix each finding without further investigation.

Principles:
- SPECIFIC titles that include the impact (not "Missing auth" but "Unverified JWT Decode Enables Tenant Spoofing in Bedrock Session")
- Group findings by THEME (Tenant Isolation, Authentication, AI/LLM Security, etc.) not just severity
- Evidence walks as primary proof format (entry → step → step → sink → MISSING)
- Explicit verified/unverified separation per finding
- Fixes reference existing secure patterns in the same codebase
- Attack chains show how individually-medium findings compose into critical exploits
- Zero trust section shows blast radius map and lateral movement
- Zero-day section for genuinely novel findings not in standard CVE databases
"""

TEMPLATE = """## Write the Final Security Report

### Inputs:

**Layer 0 Summary:**
{layer0_summary}

**Layer 1 Novel/Zero-Day Findings:**
{layer1_findings}

**Layer 2 CoT Analyses:**
{layer2_summaries}

**Layer 3 Debate Verdicts:**
{layer3_verdicts}

**Layer 4 Exploit Proofs:**
{layer4_exploits}

**Zero Trust Assessment:**
{zero_trust}

**Attack Chains:**
{attack_chains}

### Required Report Structure:

1. **Executive Summary** (5 sentences for a CISO)
   - Total findings + severity breakdown
   - Top 3 risks in business terms
   - Zero trust posture
   - Immediate actions required

2. **Zero Trust Assessment**
   - Blast radius map (uncontained resources)
   - Lateral movement paths
   - "Assume breach" top scenario
   - Containment recommendations

3. **Zero-Day Discoveries** (novel findings)
   - Findings not in any CVE database
   - AI/LLM-specific attack vectors
   - Why traditional tools missed these

4. **Findings by Theme**
   Themes: Tenant Isolation | Authentication | Authorization |
   Input Validation | AI/LLM Security | Infrastructure |
   Operational Controls | Design Flaws

   Per finding:
   ```
   ### Finding N: [Title with impact]
   | Severity | Confidence | Risk Type | CWE |

   **Description** (2-3 paragraphs)

   **Evidence Walk**
   Entry: ...
   → step (file:line)
   → sink
   ✗ MISSING: ...

   **Verified:** [list]
   **Could not verify:** [list]

   **Exploit:** curl command
   **Fix:** short-term + long-term (reference secure pattern)
   ```

5. **Attack Chains** (composite exploits)
   - Multi-step narratives with composite severity
   - Business impact of each chain

6. **Recommendations** (prioritized)
   - Immediate (hours): code patches
   - Short-term (days): config changes
   - Long-term (weeks): architecture redesign

Write the complete report now.
"""


class Narrator:
    """Production narrator — writes the final report."""

    def build_prompt(self, layer0_summary: str, layer1_findings: str,
                     layer2_summaries: str, layer3_verdicts: str,
                     layer4_exploits: str, zero_trust: str,
                     attack_chains: str) -> str:
        """Build the full narrator prompt."""
        return TEMPLATE.format(
            layer0_summary=layer0_summary,
            layer1_findings=layer1_findings,
            layer2_summaries=layer2_summaries,
            layer3_verdicts=layer3_verdicts,
            layer4_exploits=layer4_exploits,
            zero_trust=zero_trust,
            attack_chains=attack_chains,
        )

    def synthesize(self, prompt_inputs: dict, llm_fn=None) -> str:
        """Generate the final report."""
        prompt = self.build_prompt(**prompt_inputs)
        if llm_fn:
            return llm_fn(system=SYSTEM, user=prompt)
        return f"# V6 Final Report\n\n(Execute with --api to generate)\n\n{SYSTEM}\n\n---\n\n{prompt}"
