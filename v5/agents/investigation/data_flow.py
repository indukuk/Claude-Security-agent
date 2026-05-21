"""
Investigation Agent: Data Flow & Input Validation Expert.

For every user-controlled input reaching a sensitive sink, determines the
complete validation chain, identifies bypasses, and constructs concrete exploits.
"""
from __future__ import annotations

from v5.agents.base import InvestigationAgent, AgentContext


class DataFlowAgent(InvestigationAgent):

    def __init__(self):
        super().__init__(
            name="Data Flow & Input Validation Expert",
            domain="data_flow_validation",
        )

    def get_system_prompt(self) -> str:
        return """You are an input validation and data flow security expert. You specialize in:
- Path traversal attacks (../, /, \\ in file paths and S3 keys)
- SQL/NoSQL injection via unsanitized query parameters
- Server-Side Request Forgery via user-controlled URLs
- Deserialization attacks
- Finding where sanitization exists in one code path but is missing in an equivalent path

Your approach: trace every user-controlled value from HTTP entry point to sensitive
operation. At each hop, ask: "Is this value validated? Can the validation be bypassed?
Is there another path to the same sink without this validation?"

For each finding, produce a CONCRETE exploit — the exact curl command or request
that demonstrates the vulnerability. Not pseudocode. Actual payloads."""

    def get_investigation_prompt(self, context: AgentContext) -> str:
        evidence = context.to_prompt_context()
        return f"""## Investigation: Data Flow & Input Validation

### Your Evidence Package:
{evidence}

### Investigation Mandate:

For every user-controlled input that reaches a sensitive sink:

**1. Trace the complete data flow:**
- HTTP request → parsing → assignment → function calls → sink
- At each hop: what's the variable name? what does it contain?

**2. Check validation:**
- Is there sanitization? (replace, strip, regex, schema validation)
- Can the sanitization be bypassed? (encoding, double-encoding, null bytes)
- Is there an ALTERNATIVE path to the same sink without sanitization?

**3. Construct exploits:**
For each exploitable path, provide:
- The exact HTTP request (curl command with headers and body)
- The expected response showing success
- The impact (what data is accessed/modified)

**Focus areas from evidence package:**
- Path traversal in S3 key construction (presigned URLs)
- Session ID from body used as DynamoDB key (no ownership check)
- Filename parameters used without sanitization
- Framework/control_id parameters in S3 paths
- The contrast between handler.py (sanitizes) and data_handler.py (doesn't)

### Output Format:
```json
{{
  "title": "finding title",
  "severity": "CRITICAL|HIGH|MEDIUM",
  "source": "what user input (field name, from where)",
  "sink": "what sensitive operation",
  "sanitization": "what validation exists (or NONE)",
  "bypass": "how to bypass validation (if any)",
  "exploit": "curl -X POST ... (exact command)",
  "impact": "what happens on success",
  "evidence_walk": "step by step with file:line"
}}
```"""
