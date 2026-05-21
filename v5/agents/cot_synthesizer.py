"""
Layer 2: Chain-of-Thought Evidence Synthesis.

For each confirmed finding, runs a structured 7-step reasoning protocol.
The CoT output IS the finding description — not a summary of reasoning,
but the actual trace that becomes the evidence section of the report.

Steps:
1. Entry Point Analysis — how does the attacker reach this?
2. Data Flow Trace — step-by-step from input to sink
3. Control Flow Context — what conditions gate execution?
4. Cross-Reference Verification — does anything else compensate?
5. Exploit Construction — exact request that demonstrates the vuln
6. Confidence Calibration — what's verified vs assumed vs unknown
7. Severity Assessment — final severity with justification
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from v5.agents.base import AgentContext, LLMClient

logger = logging.getLogger(__name__)


@dataclass
class CoTFinding:
    """A finding enriched with Chain-of-Thought analysis."""
    id: str
    title: str
    severity: str
    confidence: str

    # From CoT steps
    entry_point_analysis: str = ""
    data_flow_trace: str = ""
    control_flow_context: str = ""
    cross_reference: str = ""
    exploit: str = ""
    verified: list[str] = field(default_factory=list)
    could_not_verify: list[str] = field(default_factory=list)
    severity_justification: str = ""

    # Full CoT reasoning (for debate input)
    full_reasoning: str = ""

    # Original finding data
    original: dict = field(default_factory=dict)


COT_SYSTEM_PROMPT = """You are a principal security engineer performing deep analysis of a vulnerability finding.
You have access to the complete source code, infrastructure configuration, and automated analysis results.

Your task: produce a rigorous, step-by-step analysis following the 7-step protocol below.
Every claim MUST cite a specific file:line or evidence item. No hand-waving.
Think like you're writing the evidence section of a penetration test report that will be
reviewed by the application team AND their security architect.

Be specific. Be concrete. Cite code. Show the exact request that exploits this."""


COT_PROTOCOL = """## 7-Step Chain-of-Thought Protocol

Analyze the following finding using exactly these 7 steps. Output each step clearly labeled.

### Finding to Analyze:
- **Title**: {title}
- **Severity**: {severity}
- **Category**: {category}
- **File**: {file_path}:{line}
- **CWE**: {cwe}

### Evidence from automated analysis:
{evidence}

---

### STEP 1: ENTRY POINT ANALYSIS
What is the attacker's entry point? Answer:
- HTTP method and route
- Is it internet-reachable? (check infra auth config)
- What authentication is required? (authorizer, API key, none)
- Can authentication be bypassed? (JWT fallback, missing authorizer)

### STEP 2: DATA FLOW TRACE
Trace the attacker-controlled value from entry to sink:
- At each hop: function name, file:line, variable name, what it contains
- Show the EXACT code at each step
- Note where the value crosses trust boundaries

### STEP 3: CONTROL FLOW CONTEXT
What conditions must be true for this path to execute?
- Are there early returns or error conditions?
- What branches are taken to reach the sink?
- Are there any guards that might prevent exploitation?

### STEP 4: CROSS-REFERENCE VERIFICATION
Does anything else in the system compensate for this vulnerability?
- Is there a WAF, rate limiter, or API Gateway config that helps?
- Does another handler do this correctly? (contrast with secure version)
- Could the framework or runtime provide mitigation?

### STEP 5: EXPLOIT CONSTRUCTION
Provide the EXACT request that demonstrates exploitation:
```
curl -X METHOD https://ENDPOINT \\
  -H "Header: value" \\
  -d '{{"field": "payload"}}'
```
What does the attacker observe on success?
What data do they get access to?

### STEP 6: CONFIDENCE CALIBRATION
Classify each claim:
- **Verified** (read from code, mathematically proven): [list]
- **Assumed** (depends on framework/runtime behavior): [list]
- **Could not verify** (depends on deployment/infra): [list]

### STEP 7: SEVERITY ASSESSMENT
Given exploitability, impact, blast radius, and detectability:
- Final severity: CRITICAL / HIGH / MEDIUM / LOW
- Justification (cite specific evidence)
- CVSS-like factors: attack vector, complexity, privileges required, scope
"""


class CoTSynthesizer:
    """
    Runs the 7-step CoT protocol on each finding.
    Produces enriched findings suitable for debate (Layer 3) and report (Layer 5).
    """

    def __init__(self, context: AgentContext):
        self.context = context

    def synthesize(self, findings: list[dict], llm_fn=None) -> list[CoTFinding]:
        """
        Run CoT on each finding.

        Args:
            findings: list of finding dicts from Layer 0
            llm_fn: callable(system, user) -> str. If None, produces prompts only.
        """
        cot_findings = []

        for finding in findings:
            cot = self._synthesize_one(finding, llm_fn)
            cot_findings.append(cot)

        return cot_findings

    def _synthesize_one(self, finding: dict, llm_fn=None) -> CoTFinding:
        """Run CoT protocol on a single finding."""
        # Gather relevant evidence for this finding
        evidence = self._gather_evidence(finding)

        # Build the CoT prompt
        prompt = COT_PROTOCOL.format(
            title=finding.get("title", ""),
            severity=finding.get("severity", ""),
            category=finding.get("category", ""),
            file_path=finding.get("file_path", ""),
            line=finding.get("line", 0),
            cwe=finding.get("cwe", ""),
            evidence=evidence,
        )

        if llm_fn:
            # API mode: call the LLM
            response = llm_fn(system=COT_SYSTEM_PROMPT, user=prompt)
            return self._parse_cot_response(finding, response)
        else:
            # In-session mode: return the prompt for Claude Code execution
            return CoTFinding(
                id=finding.get("id", ""),
                title=finding.get("title", ""),
                severity=finding.get("severity", "MEDIUM"),
                confidence="PENDING",
                full_reasoning=f"{COT_SYSTEM_PROMPT}\n\n---\n\n{prompt}",
                original=finding,
            )

    def _gather_evidence(self, finding: dict) -> str:
        """Gather all relevant evidence for a finding from the context."""
        sections = []
        file_path = finding.get("file_path", "")
        category = finding.get("category", "")
        title = finding.get("title", "")

        # Source code of the relevant file
        if file_path and file_path in self.context.file_contents:
            content = self.context.file_contents[file_path]
            line = finding.get("line", 0)
            lines = content.split("\n")
            start = max(0, line - 15)
            end = min(len(lines), line + 30)
            snippet = "\n".join(f"{i+1:4d} | {lines[i]}" for i in range(start, end))
            sections.append(f"**Source code** ({Path(file_path).name}:{start+1}-{end}):\n```python\n{snippet}\n```")

        # Evidence walks matching this file/category
        for walk in self.context.evidence_walks:
            if file_path and Path(file_path).name in walk:
                sections.append(f"**Evidence walk**:\n```\n{walk}\n```")
                break

        # Absence findings for this file
        for af in self.context.absence_findings:
            if file_path and Path(file_path).name in af.get("file_path", ""):
                sections.append(f"**Missing control**: {af['title']}")

        # Differential findings involving this file
        for df in self.context.differential_findings:
            if file_path and Path(file_path).name in df.get("weaker_path", ""):
                sections.append(f"**Bypass path**: {df['title']}")

        # Z3 proofs relevant to this category
        if "tenant" in category or "iam" in category:
            for proof in self.context.z3_proofs[:3]:
                sections.append(f"**Z3 proof**: [{proof.get('severity')}] {proof.get('title')}")

        # Blast radius if infra-related
        if "iam" in category or "infra" in category:
            for br in self.context.blast_radii[:3]:
                if br.get("status") == "UNCONTAINED":
                    sections.append(
                        f"**Blast radius**: {br['role']} — {br['score']} | "
                        f"{br['status']} | capabilities: {br.get('can_all_tenants')}"
                    )

        # CDK context for auth
        if "auth" in category or "tenant" in category:
            sections.append(f"**Infrastructure context**: Check CDK for authorizer config")

        return "\n\n".join(sections) if sections else "(no additional evidence)"

    def _parse_cot_response(self, finding: dict, response: str) -> CoTFinding:
        """Parse the LLM's CoT response into structured finding."""
        cot = CoTFinding(
            id=finding.get("id", ""),
            title=finding.get("title", ""),
            severity=finding.get("severity", "MEDIUM"),
            confidence="HIGH",
            full_reasoning=response,
            original=finding,
        )

        # Extract each step from the response
        steps = {
            "STEP 1": "entry_point_analysis",
            "STEP 2": "data_flow_trace",
            "STEP 3": "control_flow_context",
            "STEP 4": "cross_reference",
            "STEP 5": "exploit",
            "STEP 6": "confidence",
            "STEP 7": "severity_justification",
        }

        for step_marker, field_name in steps.items():
            start = response.find(step_marker)
            if start == -1:
                continue
            # Find end (next STEP or end of response)
            end = len(response)
            for next_step in steps:
                if next_step == step_marker:
                    continue
                next_idx = response.find(next_step, start + len(step_marker))
                if next_idx != -1 and next_idx < end:
                    end = next_idx

            content = response[start:end].strip()

            if field_name == "entry_point_analysis":
                cot.entry_point_analysis = content
            elif field_name == "data_flow_trace":
                cot.data_flow_trace = content
            elif field_name == "control_flow_context":
                cot.control_flow_context = content
            elif field_name == "cross_reference":
                cot.cross_reference = content
            elif field_name == "exploit":
                cot.exploit = content
            elif field_name == "confidence":
                # Parse verified/unverified
                if "Verified" in content:
                    cot.verified = self._extract_list(content, "Verified")
                if "Could not verify" in content:
                    cot.could_not_verify = self._extract_list(content, "Could not verify")
                cot.confidence = "HIGH" if cot.verified else "MEDIUM"
            elif field_name == "severity_justification":
                cot.severity_justification = content
                # Extract final severity if mentioned
                for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    if f"Final severity: {sev}" in content or f"severity: {sev}" in content.upper():
                        cot.severity = sev
                        break

        return cot

    def _extract_list(self, text: str, marker: str) -> list[str]:
        """Extract a bullet list following a marker."""
        items = []
        idx = text.find(marker)
        if idx == -1:
            return items
        lines = text[idx:].split("\n")[1:]
        for line in lines:
            line = line.strip()
            if line.startswith("- ") or line.startswith("* "):
                items.append(line[2:])
            elif line.startswith("•"):
                items.append(line[1:].strip())
            elif not line:
                break
        return items

    def generate_all_prompts(self, findings: list[dict]) -> str:
        """Generate all CoT prompts for in-session execution."""
        output = "# Layer 2: Chain-of-Thought Synthesis\n\n"
        output += f"Process each of the {len(findings)} findings below using the 7-step protocol.\n\n"

        for i, finding in enumerate(findings, 1):
            evidence = self._gather_evidence(finding)
            prompt = COT_PROTOCOL.format(
                title=finding.get("title", ""),
                severity=finding.get("severity", ""),
                category=finding.get("category", ""),
                file_path=finding.get("file_path", ""),
                line=finding.get("line", 0),
                cwe=finding.get("cwe", ""),
                evidence=evidence,
            )
            output += f"\n{'═' * 60}\n## Finding {i}/{len(findings)}: {finding.get('title', '')}\n\n"
            output += prompt
            output += f"\n{'═' * 60}\n"

        return output
