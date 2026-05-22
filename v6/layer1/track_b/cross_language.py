"""
V6 Layer 1, Track B: Cross-Language Pattern Transfer.

Takes confirmed Python vulnerabilities and searches for equivalent
patterns in JavaScript/TypeScript (frontend), CDK (infrastructure),
and YAML (configuration).
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


SYSTEM = """You are a polyglot security researcher. Given a vulnerability found in Python,
your job is to find the EQUIVALENT vulnerability in other languages in the same repo.

Key transfers:
- Python tenant_id mishandling → JavaScript fetch() calls with wrong tenant context
- Python missing sanitization → Frontend innerHTML without DOMPurify
- Python credential exposure → JavaScript hardcoded API keys/tokens
- Python IDOR → Frontend direct API calls with user-supplied IDs
- CDK IAM misconfiguration → Application code relying on IAM for something it doesn't provide
"""

PROMPT = """## Cross-Language Pattern Transfer

### Python Findings (confirmed):
{python_findings}

### Frontend JavaScript to Search:
{js_evidence}

### CDK Infrastructure to Search:
{cdk_evidence}

### For each Python finding, determine:
1. Does the JavaScript frontend have an EQUIVALENT pattern?
   - Does JS pass tenant_id/customer_id in requests?
   - Does JS construct API URLs with user-controlled path params?
   - Does JS use innerHTML with API response data?
   - Does JS store tokens/keys that should be server-side?

2. Does the CDK infrastructure RELY on application-layer security that doesn't exist?
   - Does CDK assume the handler validates X when it doesn't?
   - Are resource policies depending on app-level tenant scoping?
   - Are IAM permissions broader than the application's actual needs?

### Output:
```json
[{{
  "original_finding": "Python finding title",
  "cross_language_equivalent": "what was found in JS/CDK",
  "language": "javascript|typescript|cdk|yaml",
  "location": "[file:line]",
  "how_equivalent": "structural similarity",
  "additional_risk": "what the cross-language version adds beyond the Python finding"
}}]
```
"""


class CrossLanguageTransfer:
    """Finds cross-language equivalents of Python vulnerabilities."""

    def build_prompt(self, python_findings: list[dict],
                     js_evidence: str, cdk_evidence: str) -> str:
        findings_text = "\n".join(
            f"- [{f.get('severity','')}] {f.get('title','')}: {f.get('category','')}"
            for f in python_findings[:10]
        )
        return PROMPT.format(
            python_findings=findings_text,
            js_evidence=js_evidence[:20000],
            cdk_evidence=cdk_evidence[:20000],
        )

    def get_system(self) -> str:
        return SYSTEM

    def run(self, python_findings: list[dict], js_evidence: str,
            cdk_evidence: str, llm_fn=None) -> str:
        prompt = self.build_prompt(python_findings, js_evidence, cdk_evidence)
        if llm_fn:
            return llm_fn(system=SYSTEM, user=prompt)
        return f"{SYSTEM}\n\n---\n\n{prompt}"
