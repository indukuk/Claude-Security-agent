"""
V6 Layer 2: Chain-of-Thought Synthesis (Production).

Uses the 7-step protocol validated in prompt testing.
Applies Track C investigation style (evidence walks) + citation requirement.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


SYSTEM = """You are a principal security engineer performing deep per-finding analysis.
Every claim MUST cite [file:line]. Uncited claims are discarded.
Think step by step. Be concrete. Show the exact request that exploits this.

CONFIDENCE LEVELS (assign exactly one):
- VERIFIED: Confirmed by code reading
- LIKELY: Consistent with code but one link depends on runtime/framework behavior
- POSSIBLE: Pattern matches but no direct exploitability evidence
"""

PROTOCOL = """## Analyze: {title}
Severity: {severity} | Category: {category} | File: {file_path}:{line}

### Evidence from automated analysis:
{evidence}

### Execute 7-Step Protocol:

**STEP 1 — ENTRY POINT:** What HTTP method/route reaches this? Auth required? Bypassed how?

**STEP 2 — DATA FLOW:** Trace the attacker-controlled value hop-by-hop from entry to sink. At each hop: function, file:line, variable name.

**STEP 3 — CONTROL FLOW:** What conditions must be true? Any early returns/guards that prevent reaching the sink?

**STEP 4 — CROSS-REFERENCE:** Does anything ELSE compensate? Framework behavior? CDK config? Another handler does it correctly?

**STEP 5 — EXPLOIT:** The EXACT curl command:
```bash
curl -X METHOD https://ENDPOINT \\
  -H "Header: value" \\
  -d '{{"field": "payload"}}'
```
What does success look like?

**STEP 6 — CONFIDENCE:**
- Verified: [list with file:line citations]
- Could not verify: [list]

**STEP 7 — SEVERITY:** Final severity + justification. Cite blast radius if applicable.
"""


@dataclass
class CoTResult:
    """Output from Layer 2 CoT analysis."""
    finding_id: str
    title: str
    severity: str
    confidence: str
    steps: dict = field(default_factory=dict)
    full_reasoning: str = ""
    exploit: str = ""
    verified: list[str] = field(default_factory=list)
    could_not_verify: list[str] = field(default_factory=list)


class CoTSynthesizer:
    """Production CoT synthesizer using validated 7-step protocol."""

    def __init__(self, evidence_text: str):
        self.evidence_text = evidence_text

    def build_prompt(self, finding: dict) -> str:
        """Build the CoT prompt for a single finding."""
        return PROTOCOL.format(
            title=finding.get("title", ""),
            severity=finding.get("severity", ""),
            category=finding.get("category", ""),
            file_path=finding.get("file_path", ""),
            line=finding.get("line", 0),
            evidence=self._get_relevant_evidence(finding),
        )

    def build_all_prompts(self, findings: list[dict]) -> str:
        """Build CoT prompts for all findings (for in-session execution)."""
        output = f"# Layer 2: Chain-of-Thought Synthesis\n\n"
        output += f"System: {SYSTEM}\n\n---\n\n"
        for i, f in enumerate(findings, 1):
            output += f"## Finding {i}/{len(findings)}: {f.get('title','')}\n\n"
            output += self.build_prompt(f)
            output += "\n\n---\n\n"
        return output

    def synthesize(self, finding: dict, llm_fn=None) -> CoTResult:
        """Run CoT on a single finding."""
        prompt = self.build_prompt(finding)
        if llm_fn:
            response = llm_fn(system=SYSTEM, user=prompt)
            return self._parse(finding, response)
        return CoTResult(
            finding_id=finding.get("id", ""),
            title=finding.get("title", ""),
            severity=finding.get("severity", ""),
            confidence="PENDING",
            full_reasoning=f"{SYSTEM}\n\n{prompt}",
        )

    def _get_relevant_evidence(self, finding: dict) -> str:
        """Extract relevant evidence for this finding from the package."""
        title = finding.get("title", "").lower()
        category = finding.get("category", "").lower()
        lines = self.evidence_text.split("\n")

        relevant = []
        for i, line in enumerate(lines):
            if (title[:20] in line.lower() or category in line.lower()
                or finding.get("file_path", "XXX") in line):
                # Grab context around the match
                start = max(0, i - 2)
                end = min(len(lines), i + 5)
                relevant.extend(lines[start:end])
                relevant.append("")

        return "\n".join(relevant[:50]) if relevant else "(use evidence package above)"

    def _parse(self, finding: dict, response: str) -> CoTResult:
        """Parse LLM CoT response."""
        result = CoTResult(
            finding_id=finding.get("id", ""),
            title=finding.get("title", ""),
            severity=finding.get("severity", ""),
            confidence="HIGH",
            full_reasoning=response,
        )
        # Extract exploit (Step 5)
        if "```bash" in response:
            start = response.index("```bash") + 7
            end = response.index("```", start)
            result.exploit = response[start:end].strip()
        # Extract verified/unverified (Step 6)
        if "Verified:" in response:
            idx = response.index("Verified:")
            block = response[idx:idx+500]
            result.verified = [l.strip("- ") for l in block.split("\n")[1:6] if l.strip().startswith("-")]
        if "Could not verify:" in response or "could not verify:" in response.lower():
            idx = response.lower().index("could not verify:")
            block = response[idx:idx+500]
            result.could_not_verify = [l.strip("- ") for l in block.split("\n")[1:6] if l.strip().startswith("-")]
        return result
