"""
V6 Layer 1, Track B: Zero-Day Discovery Agent (Production).

Winner: Variant C structure (AI/anomaly-first) + Variant A's "question assumptions" phase.
Model: Opus (frontier required for novel pattern reasoning).
"""
from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


SYSTEM = """You are a security researcher who finds vulnerabilities by:
1. Identifying code that DOESN'T FIT (anomalies vs normal patterns)
2. Analyzing AI/LLM-specific attack vectors that traditional scanners cannot detect
3. Questioning every ASSUMPTION the code makes and proving it wrong

You specialize in multi-tenant SaaS + AI agent applications. You understand:
- How shared AI memory enables cross-user data leakage
- How stored data entering AI context becomes a prompt injection vector
- How AI-driven routing decisions create attacker-controllable code paths
- How agent tool-use can be escalated beyond intended permissions
- How embeddings and retrieval can leak data across trust boundaries
- How namespace collisions in databases create cross-tenant access
- How temporal gaps between auth checks and actions create exploitation windows

You are ONLY interested in genuinely novel findings — things not in any CVE database.

CITATION REQUIREMENT: Every claim must reference [file:path:line].
CONFIDENCE: VERIFIED (confirmed by code) | LIKELY (one runtime assumption) | POSSIBLE (needs testing)
"""


PROMPT_TEMPLATE = """## Zero-Day Discovery Mission

### Phase 1: Map the Normal Pattern
For each code category (auth, data access, AI integration, session management),
identify what MOST code does. Then find the ANOMALIES.

### Phase 2: AI/LLM-Specific Attack Vectors
Analyze these categories:
1. **Memory Poisoning**: Shared AI memory (memory_id scoping). Can one user poison another's AI context?
2. **Prompt Injection via Stored Data**: Data stored → later injected into LLM prompts. Multi-hop chain?
3. **Agent Routing Manipulation**: Can adversarial input force AI routing to unintended code paths?
4. **Tool Escalation**: Can a user's message cause the AI to invoke tools beyond intent?
5. **Cross-Tenant Context Bleed**: Do logs/embeddings/shared state leak across trust boundaries?

### Phase 3: Question Assumptions
For each architectural element, ask:
- "What does this code ASSUME about [X]?"
- "Under what conditions could that assumption be FALSE?"
- "Can an attacker MAKE it false?"
- "What's the impact?"

Focus on: namespace assumptions, temporal assumptions, service behavior assumptions,
data model assumptions, trust boundary assumptions.

### Phase 4: Cross-Service Interaction Bugs
Vulnerabilities that only exist because of how services INTERACT:
- App vulnerability + IAM overpermission = amplified impact
- AI agent + shared state + unauthenticated endpoint = ?
- Code generation + user-controlled input in preamble = ?

### Evidence Package (Layer 0 deterministic output):
{evidence}

### Known Findings (DO NOT RE-REPORT):
{known_findings}

### Output
For each finding (target 5-8):
```json
{{
  "title": "novel vulnerability title",
  "category": "memory_poisoning|prompt_injection|routing_manipulation|tool_escalation|context_bleed|assumption_violation|namespace_collision|temporal|cross_service",
  "assumption_or_anomaly": "what the code assumes/does differently",
  "attack_scenario": "step-by-step exploitation",
  "impact": "concrete consequence",
  "evidence": "[file:path:line] citations",
  "novelty": "why this isn't in any CVE database",
  "confidence": "VERIFIED|LIKELY|POSSIBLE",
  "rule_suggestion": "how to detect this deterministically next time"
}}
```
"""


class ZeroDayAgent:
    """Production zero-day discovery agent."""

    def build_prompt(self, evidence_text: str, known_findings: list[str]) -> str:
        """Build the zero-day discovery prompt."""
        known_text = "\n".join(f"- {f}" for f in known_findings[:40])
        return PROMPT_TEMPLATE.format(
            evidence=evidence_text,
            known_findings=known_text,
        )

    def get_system(self) -> str:
        return SYSTEM

    def run(self, evidence_text: str, known_findings: list[str], llm_fn=None) -> str:
        """Run the zero-day agent."""
        prompt = self.build_prompt(evidence_text, known_findings)
        if llm_fn:
            return llm_fn(system=SYSTEM, user=prompt)
        return f"{SYSTEM}\n\n---\n\n{prompt}"
