"""
Investigation Agent: Infrastructure & Blast Radius Expert.

For each compute resource: what happens if compromised?
Maps IAM blast radius, network isolation, and lateral movement.
"""
from __future__ import annotations

from v5.agents.base import InvestigationAgent, AgentContext


class InfraBlastRadiusAgent(InvestigationAgent):

    def __init__(self):
        super().__init__(
            name="Infrastructure & Blast Radius Expert",
            domain="infrastructure_zero_trust",
        )

    def get_system_prompt(self) -> str:
        return """You are an AWS infrastructure security specialist focused on zero trust architecture.
You understand:
- IAM least privilege and how wildcard permissions create blast radius
- VPC design for network isolation between services
- How DynamoDB LeadingKeys conditions provide IAM-level tenant isolation
- Lateral movement via shared data stores, role assumption, and Lambda invocation
- The "assume breach" mindset: what happens AFTER initial compromise?
- How overpermissive IAM on an unauthenticated endpoint amplifies application vulnerabilities

Your job: for each internet-facing compute resource, determine the COMPLETE blast radius
if that resource is compromised. Then map lateral movement paths to other resources.
Use Z3 proofs as mathematical evidence where available.

Focus on the GAP between "what this resource needs" and "what it can do" — that gap
is the attacker's playground after initial compromise."""

    def get_investigation_prompt(self, context: AgentContext) -> str:
        evidence = context.to_prompt_context()
        return f"""## Investigation: Infrastructure & Blast Radius (Zero Trust)

### Your Evidence Package:
{evidence}

### Investigation Mandate:

**Part 1: Per-Resource Blast Radius**
For each Lambda function / compute resource:
- What IAM permissions does it have? (list the role's permissions)
- What does it ACTUALLY NEED? (minimal required for its function)
- What's the GAP? (permissions it has but shouldn't)
- If compromised, what can the attacker do?
  - Read other tenants' data?
  - Write/delete data?
  - Invoke other services (Bedrock, other Lambdas)?
  - Access logs/metrics?
  - Escalate privileges?

**Part 2: "Assume Breach" Scenarios**
For the most dangerous resource (internet-facing + most permissions):
- Step 1: How is initial compromise achieved? (which app vulnerability?)
- Step 2: What does the attacker do first? (enumerate accessible resources)
- Step 3: Lateral movement — can they reach other resources?
- Step 4: What's the maximum damage achievable?

**Part 3: Containment Failures**
From the Z3 proofs and blast radius analysis:
- Which resources violate zero trust? (uncontained blast radius)
- What IAM changes would contain the blast radius?
- What network changes (VPC, endpoints) would limit lateral movement?

**Part 4: Amplification**
How does infrastructure overpermission AMPLIFY application-layer vulnerabilities?
Example: "Path traversal in data_handler is HIGH severity alone, but combined with
S3 bucket read permissions on all tenants' data, it becomes CRITICAL because the
presigned URL gives access to any tenant's evidence files."

### Output Format:
```json
{{
  "title": "finding title",
  "severity": "CRITICAL|HIGH",
  "resource": "which resource/role",
  "blast_radius": "what can be accessed",
  "assume_breach_scenario": "step-by-step compromise narrative",
  "containment_recommendation": "specific IAM/network changes",
  "amplifies": ["list of app-layer findings this makes worse"]
}}
```"""
