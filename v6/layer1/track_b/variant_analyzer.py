"""
V6 Layer 1, Track B: CVE Variant Analysis.

Seeds the zero-day agent with known vulnerability patterns
and asks it to find structural analogs in the target code.
Big Sleep's primary technique: 40% of 0-days are variants.
"""
from __future__ import annotations

import logging
from pathlib import Path

from v6.knowledge.cve_rag import get_relevant_seeds, detect_characteristics

logger = logging.getLogger(__name__)


VARIANT_SYSTEM = """You are a variant analysis specialist. Given examples of KNOWN vulnerability patterns,
your job is to find STRUCTURALLY SIMILAR but NOT IDENTICAL code in the target.

Do NOT re-report the exact pattern shown. Find VARIANTS:
- Same structural flaw in a different function/module
- Same category of assumption but in a different context
- Same missing check but reached via a different code path

Focus on the STRUCTURAL PATTERN (source → sink without gate), not the specific variable names."""


VARIANT_PROMPT = """## CVE Variant Analysis

### Known Vulnerability Patterns (seeds):

{seeds}

### Target Code Evidence:

{evidence}

### Your Task:

For each seed pattern above, search the target codebase for code that has a
SIMILAR STRUCTURE but isn't an exact match of what's already been reported.

The structural patterns to look for:
1. SOURCE(user_input) → SINK(data_operation) WITHOUT GATE(ownership_check)
2. SOURCE(token) → OPERATION(decode) WITHOUT GATE(signature_verify)
3. AI_MEMORY_SCOPE(shared) WHERE USERS_SHARE_CONTEXT
4. SOURCE(user_path) → SINK(storage_key) WITHOUT GATE(sanitization)
5. CODE_INPUT(generated) → CHECK(string_blocklist) → EXEC(execute)

### Already Known (DO NOT report these):
{known}

### Output:
For each variant found:
```json
{{
  "seed_pattern": "which CVE seed this is a variant of",
  "variant_location": "[file:line]",
  "structural_similarity": "what's the same",
  "structural_difference": "what's different (why it's a variant, not identical)",
  "exploitability": "can it be reached and exploited?",
  "confidence": "VERIFIED|LIKELY|POSSIBLE"
}}
```
"""


class VariantAnalyzer:
    """Finds structural variants of known CVE patterns."""

    def build_prompt(self, evidence_text: str, known_findings: list[str]) -> str:
        """Build the variant analysis prompt with relevant seeds."""
        characteristics = detect_characteristics(evidence_text)
        seeds = get_relevant_seeds(characteristics)
        known_text = "\n".join(f"- {f}" for f in known_findings[:30])

        return VARIANT_PROMPT.format(
            seeds=seeds,
            evidence=evidence_text[:80000],
            known=known_text,
        )

    def get_system(self) -> str:
        return VARIANT_SYSTEM

    def run(self, evidence_text: str, known_findings: list[str], llm_fn=None) -> str:
        prompt = self.build_prompt(evidence_text, known_findings)
        if llm_fn:
            return llm_fn(system=VARIANT_SYSTEM, user=prompt)
        return f"{VARIANT_SYSTEM}\n\n---\n\n{prompt}"
