"""
Investigation Agent: Authentication & Authorization Architecture Expert.

Maps the complete auth architecture. For each endpoint: what auth, what authz,
what bypass paths, what happens on JWT fallback.
"""
from __future__ import annotations

from v5.agents.base import InvestigationAgent, AgentContext


class AuthArchitectureAgent(InvestigationAgent):

    def __init__(self):
        super().__init__(
            name="Auth & Authorization Expert",
            domain="authentication_authorization",
        )

    def get_system_prompt(self) -> str:
        return """You are an authentication and authorization security specialist. You understand:
- API Gateway authorizers (Token, Request, Cognito)
- JWT token verification vs unsigned decode
- Role-Based Access Control implementation patterns
- Permission bypass via alternative code paths
- The difference between authentication (who are you?) and authorization (what can you do?)
- How approval workflows prevent destructive actions

Your job is to map the COMPLETE auth architecture and find every weakness.
Find: unauthenticated endpoints, JWT verification gaps, missing role checks,
bypass paths where one route enforces auth but an equivalent route doesn't.

Be exhaustive. Cite file:line for every claim."""

    def get_investigation_prompt(self, context: AgentContext) -> str:
        evidence = context.to_prompt_context()
        return f"""## Investigation: Authentication & Authorization Architecture

### Your Evidence Package:
{evidence}

### Investigation Mandate:

Map the complete authentication and authorization architecture of this application.

**Part 1: Authentication Map**
For each API endpoint/handler:
- What authentication mechanism protects it? (API Gateway authorizer, API key, none)
- Is JWT signature verification performed? (jwt.decode vs base64.b64decode)
- What happens when the authorizer context is empty? (fallback behavior)
- Is the endpoint reachable without any credentials?

**Part 2: Authorization Map**
For each endpoint that passes authentication:
- What role checks are performed? (admin, compliance_manager, viewer)
- What operations does each role allow?
- Are write/delete operations restricted to specific roles?
- Is there an approval workflow for destructive actions?

**Part 3: Bypass Paths**
Using the differential analysis results:
- Which endpoints reach the same backend operations but with different auth?
- Can agent_proxy bypass agent_chat's permission checks?
- Can the standalone MCP server bypass _safe_id() sanitization?
- What's the "weakest link" — the easiest path to each sensitive operation?

**Part 4: JWT Security**
- Where is JWT decoded without signature verification?
- What's the comment say vs what the code actually does?
- If the authorizer isn't configured, what tenant_id does the handler use?

### Output Format:
```json
{{
  "title": "finding title",
  "severity": "CRITICAL|HIGH|MEDIUM",
  "category": "auth_bypass|missing_auth|jwt_forgery|missing_authz|bypass_path",
  "description": "detailed explanation",
  "evidence_walk": "entry → step → step → impact",
  "verified": ["claims"],
  "could_not_verify": ["claims"],
  "suggested_fix": "specific recommendation"
}}
```"""
