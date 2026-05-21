"""
Investigation Agent: Business Logic & Design Flaw Expert.

Understands what the application IS and what it SHOULD enforce.
Identifies architecture-level mistakes, not just code bugs.
"""
from __future__ import annotations

from v5.agents.base import InvestigationAgent, AgentContext


class BusinessLogicAgent(InvestigationAgent):

    def __init__(self):
        super().__init__(
            name="Business Logic & Design Flaw Expert",
            domain="business_logic_design",
        )

    def get_system_prompt(self) -> str:
        return """You are a security architect who reviews application designs for fundamental flaws.
You look beyond code bugs to find ARCHITECTURE mistakes:
- Insecure defaults (admin role on signup, auto-confirm, wildcard CORS)
- Missing audit trails for sensitive operations
- Session management without tenant scoping
- Self-registration without rate limiting or approval
- Secrets in client-side code with no rotation mechanism
- Custom cryptography instead of established libraries
- Missing operational controls (no monitoring, no alerting on anomalies)

Your focus: what SHOULD this system enforce based on what it IS?
A compliance evaluation system holding tenant security assessments MUST have:
- Strong tenant isolation (the data IS the product)
- Audit logging (compliance systems need to be compliant themselves)
- Role-based access (not every user should modify compliance data)
- Secure defaults (a new signup shouldn't be admin)

Think about what a security auditor would flag in a SOC2 Type II audit
of THIS application itself."""

    def get_investigation_prompt(self, context: AgentContext) -> str:
        evidence = context.to_prompt_context()
        return f"""## Investigation: Business Logic & Design Flaws

### Your Evidence Package:
{evidence}

### Investigation Mandate:

**Part 1: Application Understanding**
What is this application? What data does it handle? What are the trust boundaries?
- It's a multi-tenant compliance evaluation system
- Tenants upload evidence, run evaluations (SOC2, ISO27001)
- Results contain pass/fail per control — highly sensitive business intelligence
- There's an AI agent (Bedrock) that assists with evaluations

**Part 2: Design-Level Flaws**
Not code bugs — fundamental architecture mistakes:

1. **Insecure Defaults**: What's the out-of-box posture?
   - What role does a new user get? (admin? viewer?)
   - Is email verification required? (auto-confirm?)
   - What CORS policy? (wildcard?)
   - What API authentication? (key in client JS?)

2. **Missing Operational Controls**: What's absent?
   - Audit logging for CRUD operations?
   - Rate limiting on auth endpoints?
   - Rotation policy for secrets/keys?
   - Monitoring for anomalous cross-tenant access?

3. **Data Architecture Flaws**:
   - DynamoDB partition key design (tenant-scoped or just session_id?)
   - S3 key structure (tenant prefix enforced at what layer?)
   - Session management (who can access whose sessions?)

4. **Crypto/Secret Hygiene**:
   - Custom signature verification vs established library?
   - API keys hardcoded in client code?
   - Database credentials with no rotation?

**Part 3: Compliance Irony**
This is a COMPLIANCE system — it helps tenants achieve SOC2/ISO27001.
But does IT meet those standards? Flag any requirement from these frameworks
that the application itself violates.

### Output Format:
```json
{{
  "title": "design flaw title",
  "severity": "CRITICAL|HIGH|MEDIUM",
  "category": "insecure_default|missing_control|data_architecture|crypto_hygiene|compliance_irony",
  "description": "what's wrong at the architecture level",
  "business_impact": "why this matters for THIS application specifically",
  "evidence": "code/config citations",
  "recommendation_short_term": "immediate mitigation",
  "recommendation_long_term": "architectural fix"
}}
```"""
