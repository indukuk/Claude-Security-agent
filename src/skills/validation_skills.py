from __future__ import annotations

"""
Validation Agent Skills
========================
Skills for the Validation Agent (Agent 5) — adversarial false positive filtering.

Tailored to the compliance codebase's specific patterns where findings might
appear dangerous but are actually safe due to framework protections, architectural
choices, or environmental controls.
"""


# =============================================================================
# SKILL 1: Known False Positive Patterns (Compliance Codebase)
# =============================================================================

KNOWN_SAFE_PATTERNS = [
    {
        "id": "FP-DDB-001",
        "finding_pattern": "DynamoDB wildcard resource in IAM",
        "why_safe": "DynamoDB does not support resource-level permissions for all operations. "
                  "table.grant_read_write_data() generates a policy with the table ARN "
                  "and table ARN + /index/* which IS resource-scoped (not truly wildcard). "
                  "CDK nag flags this as IAM5 but it's the correct minimal scope.",
        "dismiss_if": "Resource ARN is the specific table ARN (not *)",
    },
    {
        "id": "FP-BEDROCK-001",
        "finding_pattern": "Bedrock InvokeModel with resource *",
        "why_safe": "AWS Bedrock InvokeModel does not support resource-level permissions "
                  "as of 2025. The only way to grant this permission is with resource: *. "
                  "This is an AWS limitation, not a misconfiguration.",
        "dismiss_if": "Action is bedrock:InvokeModel and no alternative exists",
    },
    {
        "id": "FP-TEXTRACT-001",
        "finding_pattern": "Textract actions with resource *",
        "why_safe": "AWS Textract does not support resource-level permissions. "
                  "All Textract API actions require resource: *.",
        "dismiss_if": "Actions are textract:DetectDocumentText, AnalyzeDocument, etc.",
    },
    {
        "id": "FP-CORS-001",
        "finding_pattern": "CORS allow_origins: * on Function URL with AWS_IAM auth",
        "why_safe": "Function URL with auth_type=AWS_IAM requires SigV4 signing on every "
                  "request. CORS * alone does not enable unauthorized access because "
                  "browsers cannot generate SigV4 signatures without credentials. "
                  "The real auth boundary is SigV4, not CORS.",
        "dismiss_if": "auth_type is AWS_IAM (not NONE)",
        "keep_if": "auth_type is NONE — then CORS * is critical",
    },
    {
        "id": "FP-TENANT-001",
        "finding_pattern": "Tenant ID from request body used in DynamoDB query",
        "why_safe_conditions": [
            "The tenant_id from request body is validated against the JWT-authenticated "
            "tenant_id from event['requestContext']['authorizer']['tenant_id']",
            "The comparison happens BEFORE the DynamoDB query",
            "The code pattern: if body_tenant != auth_tenant: return 403",
        ],
        "dismiss_if": "Validation exists before DB query",
        "keep_if": "No validation or validation after DB query",
    },
    {
        "id": "FP-LOG-001",
        "finding_pattern": "User data logged to CloudWatch",
        "why_safe_conditions": [
            "Logged data is non-PII (e.g., session_id, framework_name, intent)",
            "Logged at DEBUG level that's disabled in production",
            "CloudWatch logs are encrypted at rest and access-controlled",
        ],
        "dismiss_if": "Logged data is non-sensitive metadata only",
        "keep_if": "Logged data includes: JWT tokens, passwords, evidence content, PII",
    },
]


# =============================================================================
# SKILL 2: Framework Protection Knowledge
# =============================================================================

FRAMEWORK_PROTECTIONS = {
    "api_gateway_authorizer": {
        "protection": "Lambda authorizer validates JWT before request reaches handler",
        "what_it_prevents": [
            "Unauthenticated access to any protected route",
            "Requests with expired tokens",
            "Requests with invalid signatures",
            "Requests from non-existent users",
        ],
        "what_it_does_not_prevent": [
            "Authorized user accessing another tenant's data (application-level check needed)",
            "Authorized user escalating within their own tenant (RBAC check needed)",
            "Prompt injection through authorized messages",
        ],
        "bypass_conditions": [
            "Route added without authorizer in CDK (check add_method calls)",
            "Lambda Function URL (separate auth mechanism)",
            "API Gateway stage with no deployment (route exists but isn't live)",
        ]
    },
    "dynamodb_expression_attributes": {
        "protection": "ExpressionAttributeValues parameterize DynamoDB queries",
        "what_it_prevents": [
            "NoSQL injection via filter/key/update expressions",
            "Expression operator injection",
        ],
        "what_it_does_not_prevent": [
            "Using wrong tenant_id in the query (logic bug, not injection)",
            "Overly broad queries that return cross-tenant data",
        ],
    },
    "cognito_token_validation": {
        "protection": "RS256 JWT signature verification + expiry + issuer + audience check",
        "what_it_prevents": [
            "Forged tokens",
            "Expired tokens",
            "Tokens from wrong user pool",
            "Modified claims (signature invalidates)",
        ],
        "what_it_does_not_prevent": [
            "Valid token used beyond intended scope (RBAC bypass)",
            "Token theft (must be detected by other means)",
            "Claims that are correct but the user shouldn't have (role assignment bug)",
        ],
    },
    "pydantic_validation": {
        "protection": "Type + structure + constraint validation on input data",
        "what_it_prevents": [
            "Wrong types reaching application logic",
            "Missing required fields",
            "Values outside defined constraints (min/max, regex, enum)",
        ],
        "what_it_does_not_prevent": [
            "Semantically valid but malicious content (e.g., valid string containing SQL)",
            "Business logic bypasses (valid data used in wrong context)",
            "Values that pass type check but are dangerous (e.g., '../' is a valid string)",
        ],
    },
    "s3_block_public_access": {
        "protection": "All 4 public access block settings enabled",
        "what_it_prevents": [
            "Public bucket policies",
            "Public ACLs",
            "Public access grants",
        ],
        "what_it_does_not_prevent": [
            "Access via overly permissive IAM policies",
            "Access via presigned URLs (intentional sharing mechanism)",
            "Cross-account access via bucket policy (if block is later removed)",
        ],
    },
}


# =============================================================================
# SKILL 3: Adversarial Prompts (Compliance-Specific)
# =============================================================================

ADVERSARIAL_TEMPLATE = """A security scanner has flagged the following in a multi-tenant
compliance platform (AWS Lambda + DynamoDB + Cognito):

FINDING:
  Category: {category}
  Severity: {severity}
  Title: {title}
  Description: {description}

EVIDENCE:
{evidence}

CODEBASE CONTEXT:
- Authentication: Cognito JWT → Lambda authorizer validates before handler runs
- Authorization: RBAC via permissions.py (check_permission function)
- Data isolation: DynamoDB pk = TENANT#{{tenant_id}}, tenant_id from JWT
- Storage: S3 with tenant-prefixed keys, presigned URLs (5 min expiry)
- API Gateway: Authorizer on all routes except /auth/*
- Framework: LangGraph for agent orchestration, Pydantic for validation

KNOWN FRAMEWORK PROTECTIONS:
{applicable_protections}

---

Your task: Argue why this finding is NOT exploitable. Consider:

1. AUTHENTICATION GATE: Does the Lambda authorizer prevent this path from being
   reached by an unauthenticated attacker? Is this finding only exploitable by
   an already-authenticated user?

2. AUTHORIZATION CHECK: Does the RBAC system (check_permission) prevent this
   action for the user's role? Would the user need a specific role that limits
   who can trigger this?

3. TENANT ISOLATION: Does the DynamoDB partition key scheme (TENANT#{{tenant_id}})
   inherently prevent cross-tenant access even without application-level checks?

4. AWS SERVICE GUARANTEES: Does the AWS service itself prevent this?
   (e.g., DynamoDB ExpressionAttributeValues prevent injection)

5. CDK-LEVEL CONTROLS: Are there CDK-defined controls not visible in application
   code? (e.g., bucket policies, resource policies, VPC isolation)

6. PRACTICAL EXPLOITABILITY: Even if theoretically vulnerable, would exploiting
   this require: (a) being an authenticated user, (b) with a specific role,
   (c) targeting only their own tenant? If so, the impact is significantly reduced.

---

VERDICT:
CONFIRMED — Cannot find a valid defense. The vulnerability is real and exploitable.
DISMISSED — [specific protection] prevents exploitation because [reason].
UNCERTAIN — Partially mitigated by [X] but uncertain whether [Y] fully prevents it."""


# =============================================================================
# SKILL 4: Severity Adjustment Rules
# =============================================================================

SEVERITY_ADJUSTMENTS = {
    "requires_authentication": {
        "adjustment": -1,
        "reason": "Finding requires valid Cognito authentication to exploit. "
                 "Attack surface limited to authenticated users only.",
    },
    "requires_admin_role": {
        "adjustment": -2,
        "reason": "Finding only exploitable by admin role. Admin is already trusted. "
                 "This is an insider threat scenario, not an external attack.",
    },
    "single_tenant_impact": {
        "adjustment": -1,
        "reason": "Impact limited to attacker's own tenant data. "
                 "No cross-tenant exposure.",
    },
    "aws_service_limitation": {
        "adjustment": "DISMISS",
        "reason": "AWS service does not support resource-level permissions. "
                 "This is a platform limitation, not a misconfiguration.",
    },
    "compensating_control_exists": {
        "adjustment": -1,
        "reason": "A compensating control (WAF, SCP, Config rule, monitoring) "
                 "mitigates the practical risk.",
    },
}


# =============================================================================
# SKILL 5: Context Enrichment Queries
# =============================================================================

CONTEXT_ENRICHMENT = {
    "for_app_findings": [
        {
            "question": "Is this Lambda handler behind an API Gateway with authorizer?",
            "how_to_check": "Look at CDK stack: does add_method() include authorizer parameter?",
            "if_yes": "Finding requires authentication — reduce severity",
        },
        {
            "question": "Does check_permission() gate this tool execution?",
            "how_to_check": "Trace tool_name through permissions.py TOOL_PERMISSIONS mapping",
            "if_yes": "Finding requires specific RBAC permission — note which roles have access",
        },
        {
            "question": "Is the tenant_id from auth context or request body?",
            "how_to_check": "Look at where tenant_id/customer_id is extracted in the handler",
            "if_auth_context": "Tenant isolation enforced by authorizer — cross-tenant finding is FP",
            "if_body": "Tenant isolation depends on application validation — finding may be real",
        },
    ],
    "for_infra_findings": [
        {
            "question": "Is this a CDK nag suppression with documented justification?",
            "how_to_check": "Look for NagSuppressions.add_resource_suppressions() with reason",
            "if_justified": "Review the justification — if it's a service limitation, DISMISS",
        },
        {
            "question": "Is there an SCP or Config rule at the org level?",
            "how_to_check": "Check if account is in an AWS Organization with SCPs",
            "if_yes": "Org-level controls may mitigate — note as compensating control",
        },
        {
            "question": "Is the finding about default encryption vs. CMK?",
            "how_to_check": "Check if the finding is about SSE-S3 vs. SSE-KMS",
            "if_default": "SSE-S3 is still encrypted at rest — LOW severity unless "
                        "regulatory requirement mandates CMK (HIPAA/FedRAMP may)",
        },
    ],
}
