"""
V6 Layer 1, Track A: Novel Pattern Discovery Agent (Production).

Validated prompt: 5 strategies with exclusion list.
Model: Sonnet (cost-effective).
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


SYSTEM = """You are a security researcher finding vulnerabilities that automated tools MISSED.
Phase 0 already found the issues listed below — DO NOT re-report them.
Find ONLY things NOT in this list.

CITATION REQUIREMENT: Every claim must reference [file:path:line].
OUTPUT: JSON findings with rule_suggestion field for feedback loop.

DO NOT REPORT:
- Missing CSRF on non-state-changing endpoints
- Stack traces in dev configurations
- Missing security headers on API-only services
- Rate limiting absence (operational, not security)
- Anything in the KNOWN FINDINGS list"""


PROMPT_TEMPLATE = """## Novel Pattern Discovery

### Known Findings (DO NOT RE-REPORT):
{known_findings}

### Apply These 5 Strategies (in order):

**1. DECLARED-BUT-UNENFORCED**
Find security metadata/comments that exist in code but are never enforced in execution.
Examples: permission annotations ignored, validation functions never called, config values unread.

**2. SENSITIVE DATA TO EXTERNAL SERVICES**
Trace tokens, PII, evidence content, credentials. Where do they go?
Check: Bedrock prompts, CloudWatch logs, PostgreSQL, Mem0, S3 metadata.
Is sensitive content logged, persisted, or sent to third parties without filtering?

**3. IMPLICIT CONTRACT VIOLATIONS**
What do 80% of code paths do that 20% don't?
Check: error handling consistency, response format, header setting, input parsing, timeout handling.
The 20% are likely bugs — the developer forgot to apply the pattern.

**4. ATTACK SURFACE EXPANSION**
What accepts more input than needed? What returns more data than the caller needs?
What's reachable that the architecture didn't intend to be reachable?

**5. TEMPORAL/STATE ISSUES**
Token lifetimes vs authorization state. Session persistence vs user lifecycle.
Pending actions without expiry. Race conditions in multi-step operations.
Cache invalidation gaps. TOCTOU between check and use.

### Evidence Package:
{evidence}

### Output (3-5 findings):
```json
[{{
  "title": "specific title",
  "strategy": "which of the 5 strategies found this",
  "description": "what's wrong and why rules missed it",
  "evidence": "[file:line] citations",
  "why_novel": "why this isn't in the known findings list",
  "rule_suggestion": "how to catch this deterministically next time"
}}]
```
"""


class NovelPatternAgent:
    """Production novel pattern discovery agent."""

    def build_prompt(self, evidence_text: str, known_findings: list[str]) -> str:
        known_text = "\n".join(f"- {f}" for f in known_findings[:50])
        return PROMPT_TEMPLATE.format(
            evidence=evidence_text,
            known_findings=known_text,
        )

    def get_system(self) -> str:
        return SYSTEM

    def run(self, evidence_text: str, known_findings: list[str], llm_fn=None) -> str:
        prompt = self.build_prompt(evidence_text, known_findings)
        if llm_fn:
            return llm_fn(system=SYSTEM, user=prompt)
        return f"{SYSTEM}\n\n---\n\n{prompt}"
