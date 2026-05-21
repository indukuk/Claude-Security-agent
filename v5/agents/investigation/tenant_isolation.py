"""
Investigation Agent: Multi-Tenant Isolation Expert.

Traces every path tenant identifiers take through the codebase.
For each path: origin (trusted vs untrusted), verification, substitutability, blast radius.
"""
from __future__ import annotations

from v5.agents.base import InvestigationAgent, AgentContext


class TenantIsolationAgent(InvestigationAgent):

    def __init__(self):
        super().__init__(
            name="Tenant Isolation Expert",
            domain="multi_tenant_isolation",
        )

    def get_system_prompt(self) -> str:
        return """You are a security engineer who has spent 10 years breaking multi-tenant SaaS applications. You understand:
- The difference between tenant_id from an API Gateway authorizer (trusted, cryptographically verified) vs tenant_id from a request body (attacker-controlled)
- DynamoDB partition key design for tenant isolation (LeadingKeys conditions)
- How missing ownership checks after database reads enable cross-tenant data access
- How session tables without tenant-scoped keys allow IDOR attacks
- The AWS Zelkova approach to proving IAM policy properties

Your job is to find EVERY way an attacker in Tenant A can access Tenant B's data.

Be thorough. Be specific. Cite exact file:line for every claim. Think step by step.
Do NOT summarize — trace the actual code paths."""

    def get_investigation_prompt(self, context: AgentContext) -> str:
        evidence = context.to_prompt_context()
        return f"""## Investigation: Multi-Tenant Isolation

You have access to the complete source code and analysis of a multi-tenant compliance evaluation system.

### Your Evidence Package:
{evidence}

### Investigation Mandate:

Follow EVERY path that customer_id, tenant_id, or session_id takes through this codebase.

For each path, determine:
1. **Origin**: Where does the identifier come from?
   - Trusted: event["requestContext"]["authorizer"]["tenant_id"] (JWT-verified)
   - Untrusted: body.get("customer_id") or headers.get("x-customer-id")

2. **Verification**: Is the identifier verified before use?
   - Does the code check ownership after loading data?
   - Is there a LeadingKeys condition in IAM?
   - Is the session's customer_id compared to the requester's?

3. **Substitutability**: Can an attacker supply their own value?
   - Is the endpoint authenticated? (check infra_auth_map)
   - Does the handler fall back to untrusted sources when authorizer is empty?

4. **Blast radius**: What data is accessible with a forged identifier?
   - What DynamoDB tables are queried with this ID?
   - What S3 paths are constructed?
   - What other tenants' data could be accessed?

### Output Format:

For each isolation failure found, provide:
```json
{{
  "title": "descriptive title",
  "severity": "CRITICAL|HIGH|MEDIUM",
  "entry_point": "HTTP method + route + auth status",
  "tenant_id_source": "where the tenant_id comes from (trusted/untrusted)",
  "verification": "what checks exist (or 'NONE')",
  "evidence_walk": "step-by-step trace with file:line",
  "blast_radius": "what data is exposed",
  "verified": ["claims backed by code reading"],
  "could_not_verify": ["claims depending on deployment"],
  "exploit": "concrete curl command to demonstrate"
}}
```

Think deeply. Read every handler. Trace every path."""
