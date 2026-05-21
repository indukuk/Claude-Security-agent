from __future__ import annotations

"""
Infrastructure Security Skills
================================
Skills for the Infrastructure Agent (Agent 4) tailored to the compliance codebase.

This codebase uses AWS CDK (Python) with:
- 3 stacks: ComplianceAgentStack, ComplianceAuthStack, ComplianceFrontendStack
- Lambda functions (Docker-based)
- DynamoDB tables
- S3 buckets
- API Gateway (REST + Function URLs)
- Cognito User Pool
- Bedrock integration
- CloudWatch monitoring
"""

from dataclasses import dataclass, field
from enum import Enum


# =============================================================================
# SKILL 1: CDK Resource Security Rules (Deterministic Checks)
# =============================================================================

CDK_SECURITY_RULES = [
    # --- IAM ---
    {
        "id": "CDK-IAM-001",
        "title": "Wildcard resource on IAM policy",
        "severity": "HIGH",
        "applies_to": ["aws_cdk.aws_iam.PolicyStatement"],
        "check": "resources contains '*' and actions are not read-only",
        "description": "IAM policy grants actions on all resources. Scope to specific ARNs.",
        "cis_mapping": "CIS 1.16",
        "detection": """
            In CDK: iam.PolicyStatement(actions=[...], resources=['*'])
            In CFN: Statement with Resource: '*' and non-read-only Action
        """,
        "exceptions": [
            "bedrock:InvokeModel (no resource-level permissions available)",
            "textract:* (no resource-level permissions available)",
            "logs:FilterLogEvents (requires * for cross-log-group queries)"
        ]
    },
    {
        "id": "CDK-IAM-002",
        "title": "Service wildcard actions (service:*)",
        "severity": "CRITICAL",
        "applies_to": ["aws_cdk.aws_iam.PolicyStatement"],
        "check": "action contains 'service:*' pattern",
        "description": "Grants all current and future actions for a service. Use specific actions.",
        "detection": """
            actions=['bedrock-agentcore:*'] → grants ALL agentcore actions including
            administrative ones (CreateAgent, DeleteAgent, UpdateAgent)
        """,
        "codebase_finding": "bedrock-agentcore:* in compliance_stack.py — should be scoped to "
                          "InvokeAgent, GetAgent only"
    },
    {
        "id": "CDK-IAM-003",
        "title": "Lambda function can invoke other Lambda functions",
        "severity": "MEDIUM",
        "applies_to": ["aws_cdk.aws_iam.PolicyStatement"],
        "check": "lambda:InvokeFunction granted to a Lambda",
        "description": "Lambda-to-Lambda invocation. Verify the target is specifically scoped.",
        "detection": """
            agent_lambda.add_to_role_policy(iam.PolicyStatement(
                actions=['lambda:InvokeFunction'],
                resources=[target_lambda.function_arn]
            ))
            — Check: is the resource ARN specific or wildcarded?
        """
    },
    {
        "id": "CDK-IAM-004",
        "title": "CDK grant methods with overly broad scope",
        "severity": "HIGH",
        "applies_to": ["aws_cdk.aws_s3.Bucket", "aws_cdk.aws_dynamodb.Table"],
        "check": "grant_read_write_data() or grant() without condition",
        "description": "CDK's grant methods are convenient but may grant more than needed.",
        "detection": """
            bucket.grant_read_write(lambda_fn) → grants s3:GetObject, s3:PutObject,
            s3:DeleteObject, s3:ListBucket on all keys in bucket.

            Consider: Does this Lambda need DeleteObject? Does it need ListBucket?
            Use grant_read() + grant_put() separately if Delete not needed.
        """
    },

    # --- Network / API Gateway ---
    {
        "id": "CDK-NET-001",
        "title": "API Gateway without authorization on routes",
        "severity": "HIGH",
        "applies_to": ["aws_cdk.aws_apigateway.RestApi"],
        "check": "method added without authorizer",
        "description": "API routes accessible without authentication.",
        "detection": """
            api.root.add_resource('path').add_method('POST')
            — Missing: authorizer=token_authorizer parameter

            In this codebase: Check if /auth/* routes correctly skip authorizer
            (they should — login/signup are pre-auth) while all other routes require it.
        """
    },
    {
        "id": "CDK-NET-002",
        "title": "Function URL with open CORS",
        "severity": "MEDIUM",
        "applies_to": ["aws_cdk.aws_lambda.FunctionUrl"],
        "check": "cors allow_origins contains '*'",
        "description": "Lambda Function URL accessible from any origin.",
        "detection": """
            fn_url = lambda_fn.add_function_url(
                auth_type=lambda_.FunctionUrlAuthType.AWS_IAM,
                cors=lambda_.FunctionUrlCorsOptions(
                    allowed_origins=['*'],  ← Any website can call this
                )
            )
        """,
        "codebase_finding": "Function URL has CORS * — if auth_type is AWS_IAM this is "
                          "partially mitigated by SigV4, but if auth_type is NONE, critical."
    },
    {
        "id": "CDK-NET-003",
        "title": "API Gateway throttling too permissive",
        "severity": "LOW",
        "applies_to": ["aws_cdk.aws_apigateway.RestApi"],
        "check": "throttle rate_limit > 100 or burst_limit > 500",
        "description": "High rate limits may allow abuse or cost spike.",
        "detection": """
            Check deploy_options throttling_rate_limit and throttling_burst_limit.
            Current: 100 req/s, 200 burst — reasonable for compliance platform.
        """
    },

    # --- Cognito ---
    {
        "id": "CDK-COG-001",
        "title": "Cognito self-signup without admin approval",
        "severity": "HIGH",
        "applies_to": ["aws_cdk.aws_cognito.UserPool"],
        "check": "self_sign_up_enabled=True without pre-signup trigger validation",
        "description": "Users can create accounts without admin approval. In multi-tenant, "
                     "this may allow unauthorized tenant access.",
        "detection": """
            UserPool(self_sign_up_enabled=True) without a pre_sign_up Lambda trigger
            that validates invitation tokens or domain restrictions.
        """,
        "codebase_finding": "Compliance platform uses admin_create_user (not self-signup) "
                          "but verify this is enforced at Cognito level, not just app level."
    },
    {
        "id": "CDK-COG-002",
        "title": "Custom attributes modifiable by user",
        "severity": "CRITICAL",
        "applies_to": ["aws_cdk.aws_cognito.UserPool"],
        "check": "custom attribute mutable=True for security-critical attributes",
        "description": "If custom:role or custom:tenant_id is user-mutable, privilege escalation possible.",
        "detection": """
            custom_attributes={'role': cognito.StringAttribute(mutable=True)}
            — If mutable, user could change their own role via UpdateUserAttributes API.

            MUST be mutable=False or protected by a pre-token-generation trigger.
        """
    },
    {
        "id": "CDK-COG-003",
        "title": "MFA not enforced",
        "severity": "MEDIUM",
        "applies_to": ["aws_cdk.aws_cognito.UserPool"],
        "check": "mfa=cognito.Mfa.OPTIONAL or mfa not set",
        "description": "MFA is optional — admin/compliance_manager accounts should require MFA.",
        "codebase_finding": "MFA is OPTIONAL. For a compliance platform handling audit data, "
                          "at minimum admin role should require MFA."
    },

    # --- S3 ---
    {
        "id": "CDK-S3-001",
        "title": "S3 bucket without versioning",
        "severity": "MEDIUM",
        "applies_to": ["aws_cdk.aws_s3.Bucket"],
        "check": "versioned=False or not set",
        "description": "Without versioning, evidence can be permanently deleted or overwritten.",
        "codebase_finding": "Evidence bucket stores compliance artifacts. Versioning should "
                          "be enabled for audit trail integrity."
    },
    {
        "id": "CDK-S3-002",
        "title": "S3 bucket without access logging",
        "severity": "MEDIUM",
        "applies_to": ["aws_cdk.aws_s3.Bucket"],
        "check": "server_access_logs_bucket not set",
        "description": "No audit trail of who accessed evidence files.",
    },

    # --- DynamoDB ---
    {
        "id": "CDK-DDB-001",
        "title": "DynamoDB table without encryption with CMK",
        "severity": "LOW",
        "applies_to": ["aws_cdk.aws_dynamodb.Table"],
        "check": "encryption=TableEncryption.DEFAULT (AWS-owned key)",
        "description": "Default encryption uses AWS-owned key. For compliance data, "
                     "consider customer-managed KMS key for key rotation control.",
    },
    {
        "id": "CDK-DDB-002",
        "title": "DynamoDB table without deletion protection",
        "severity": "MEDIUM",
        "applies_to": ["aws_cdk.aws_dynamodb.Table"],
        "check": "deletion_protection not enabled",
        "description": "Table can be deleted accidentally. Enable deletion protection "
                     "for tables containing compliance/audit data.",
    },

    # --- Lambda ---
    {
        "id": "CDK-LAM-001",
        "title": "Lambda timeout exceeds API Gateway limit",
        "severity": "LOW",
        "applies_to": ["aws_cdk.aws_lambda.Function"],
        "check": "timeout > 29 seconds AND connected to API Gateway (not Function URL)",
        "description": "API Gateway has 29s hard limit. Lambda will be killed mid-execution.",
        "codebase_finding": "Agent Lambda has 15 min timeout but is behind API Gateway (29s). "
                          "Long-running evaluations will timeout. V2 uses async pattern correctly."
    },
    {
        "id": "CDK-LAM-002",
        "title": "Lambda with broad environment variable exposure",
        "severity": "LOW",
        "applies_to": ["aws_cdk.aws_lambda.Function"],
        "check": "environment variables contain sensitive values or endpoints",
        "description": "Lambda environment variables are visible in console and logs. "
                     "Use Secrets Manager for sensitive configuration.",
    },

    # --- Logging ---
    {
        "id": "CDK-LOG-001",
        "title": "CloudWatch log retention too short for compliance",
        "severity": "MEDIUM",
        "applies_to": ["aws_cdk.aws_logs.LogGroup"],
        "check": "retention < 365 days for compliance-relevant functions",
        "description": "Compliance platforms typically require 1-7 year log retention.",
        "codebase_finding": "Log retention is 7 days. For SOC2/HIPAA compliance auditing, "
                          "this should be at minimum 1 year (365 days)."
    },
]


# =============================================================================
# SKILL 2: IAM Privilege Escalation Checks (Compliance-Specific)
# =============================================================================

IAM_ESCALATION_CHECKS = [
    {
        "id": "ESC-001",
        "title": "Agent Lambda can invoke model + write to DynamoDB",
        "description": "If compromised, attacker can: (1) invoke Bedrock to generate "
                     "compliance evaluations, (2) write results to DynamoDB as if legitimate. "
                     "This could forge audit evidence.",
        "severity": "HIGH",
        "permissions_required": ["bedrock:InvokeModel", "dynamodb:PutItem"],
        "attack_scenario": "Compromise agent Lambda → Generate fake compliance evaluation "
                         "via Bedrock → Store in DynamoDB sessions table → Appears as "
                         "legitimate audit evidence.",
        "mitigation": "Separate read/write roles. Evaluation results should require "
                    "a signing step or be write-once (condition on put_item)."
    },
    {
        "id": "ESC-002",
        "title": "bedrock-agentcore:* grants administrative actions",
        "description": "Wildcard on agentcore grants CreateAgent, DeleteAgent, UpdateAgent, "
                     "etc. The Lambda only needs InvokeAgent.",
        "severity": "HIGH",
        "permissions_required": ["bedrock-agentcore:*"],
        "attack_scenario": "Compromise agent Lambda → Create new agent with different "
                         "system prompt → Route traffic through malicious agent → "
                         "Exfiltrate compliance data.",
        "mitigation": "Scope to: bedrock-agentcore:InvokeAgent, bedrock-agentcore:GetAgent"
    },
    {
        "id": "ESC-003",
        "title": "Auth Lambda has Cognito admin powers",
        "description": "Auth handler can AdminCreateUser, AdminSetUserPassword, AdminInitiateAuth. "
                     "If compromised, attacker can create users in any tenant.",
        "severity": "CRITICAL",
        "permissions_required": [
            "cognito-idp:AdminCreateUser",
            "cognito-idp:AdminSetUserPassword",
            "cognito-idp:AdminUpdateUserAttributes"
        ],
        "attack_scenario": "Compromise auth Lambda → Create admin user in target tenant → "
                         "Login as created user → Full tenant data access.",
        "mitigation": "Add condition key: cognito-idp:* only callable from specific "
                    "API Gateway source (aws:SourceArn). Consider separate Lambdas "
                    "for signup vs. user management."
    },
]


# =============================================================================
# SKILL 3: Toxic Combinations (Compliance-Codebase-Specific)
# =============================================================================

COMPLIANCE_TOXIC_COMBINATIONS = [
    {
        "id": "TC-COMP-001",
        "name": "Public API + Agent Lambda + Broad IAM = Full Account Risk",
        "components": [
            "API Gateway is internet-facing (public)",
            "Agent Lambda has bedrock-agentcore:* + S3 read_write + DynamoDB read_write",
            "Lambda timeout is 15 minutes (long execution window for attacker)",
        ],
        "individual_severity": ["LOW", "HIGH", "LOW"],
        "combined_severity": "CRITICAL",
        "attack_narrative": "Exploit vulnerability in agent handler (e.g., prompt injection "
                          "leading to tool misuse) → 15 minutes to exfiltrate S3 evidence + "
                          "DynamoDB compliance data + create rogue Bedrock agents.",
        "blast_radius": ["All S3 evidence", "All DynamoDB sessions", "Bedrock agent config"],
    },
    {
        "id": "TC-COMP-002",
        "name": "Self-Signup + Role from Request + No Approval = Tenant Hijack",
        "components": [
            "Signup creates new tenant from user-provided tenant_name",
            "Role (admin) assigned during signup without external validation",
            "Custom Cognito attributes set at creation time",
        ],
        "individual_severity": ["LOW", "MEDIUM", "LOW"],
        "combined_severity": "HIGH",
        "attack_narrative": "Attacker signs up → Provides any tenant_name → Gets admin role → "
                          "Creates isolated tenant (no hijack) BUT if tenant_name collision "
                          "is possible or if the system allows joining existing tenants...",
        "blast_radius": ["Potential unauthorized tenant creation", "Resource exhaustion"],
    },
    {
        "id": "TC-COMP-003",
        "name": "Short Log Retention + No S3 Access Logging = Evidence Tampering Undetectable",
        "components": [
            "CloudWatch log retention is 7 days",
            "S3 evidence bucket has no access logging",
            "No CloudTrail for S3 data events configured in stack",
        ],
        "individual_severity": ["MEDIUM", "MEDIUM", "MEDIUM"],
        "combined_severity": "HIGH",
        "attack_narrative": "Attacker modifies compliance evidence in S3 → No access log → "
                          "CloudWatch logs expire in 7 days → After 7 days, tampering is "
                          "completely undetectable. Critical for a COMPLIANCE platform.",
        "mitigation": "Enable S3 access logging + versioning + extend CW retention to 1yr"
    },
    {
        "id": "TC-COMP-004",
        "name": "Function URL + CORS * + IAM Auth = Confused Deputy Potential",
        "components": [
            "Lambda Function URL with auth_type=AWS_IAM",
            "CORS allowed_origins=['*']",
            "No additional origin validation in Lambda code",
        ],
        "individual_severity": ["LOW", "MEDIUM", "LOW"],
        "combined_severity": "MEDIUM",
        "attack_narrative": "While AWS_IAM auth requires SigV4 (mitigates most attacks), "
                          "if the frontend sends credentials with requests and CORS allows "
                          "any origin, a malicious site could potentially make authenticated "
                          "requests if credentials are leaked.",
    },
    {
        "id": "TC-COMP-005",
        "name": "DynamoDB Shared Table + Tenant Prefix Only + No Item-Level Auth",
        "components": [
            "All tenants share the same DynamoDB table",
            "Tenant isolation is only via pk prefix (TENANT#{tenant_id})",
            "IAM policy grants full table read_write (no condition on LeadingKey)",
        ],
        "individual_severity": ["LOW", "LOW", "MEDIUM"],
        "combined_severity": "HIGH",
        "attack_narrative": "If application-level tenant check is bypassed (bug in authorizer, "
                          "or direct DynamoDB access via compromised Lambda), all tenant data "
                          "is accessible because IAM doesn't enforce the prefix.",
        "mitigation": "Add IAM condition: dynamodb:LeadingKeys to restrict Lambda to "
                    "specific tenant partition keys. Or use separate tables per tenant."
    },
]


# =============================================================================
# SKILL 4: Infrastructure CoT Template
# =============================================================================

INFRA_COT_TEMPLATE = """Analyze this CDK infrastructure for security issues.

CODEBASE CONTEXT:
This is a multi-tenant compliance platform (Lotus AI) deployed on AWS:
- 3 CDK stacks: Agent (compute + storage), Auth (Cognito + auth Lambdas), Frontend
- Multi-tenant: all tenants share same DynamoDB tables, S3 bucket
- Compliance-critical: handles SOC2/HIPAA audit evidence
- AI-powered: Bedrock for evaluations, LangGraph for orchestration

RESOURCE UNDER ANALYSIS:
{resource_config}

GRAPH POSITION (connections):
{graph_context}

EFFECTIVE PERMISSIONS (resolved):
{effective_permissions}

DETERMINISTIC FINDINGS:
{deterministic_facts}

RELEVANT CIS/COMPLIANCE RULES:
{applicable_rules}

---

STEP 1 — CONTEXT: What is this resource's role?
- Is it handling compliance evidence (audit-critical)?
- Is it multi-tenant (shared across customers)?
- Is it internet-facing?
- What sensitivity level is the data it handles?

STEP 2 — COMPLIANCE REQUIREMENTS: For a compliance platform specifically:
- Does this resource meet SOC2 CC6.1 (logical access controls)?
- Does it meet CC7.2 (monitoring of system components)?
- Is there sufficient audit trail (CC4.1)?
- Is data encrypted per CC6.7?
- Is the retention period sufficient for compliance audits?

STEP 3 — MULTI-TENANT ISOLATION: Is tenant data properly isolated?
- Is there IAM-level enforcement (not just application-level)?
- Could a bug in one Lambda expose all tenants?
- Is the blast radius limited to a single tenant if compromised?

STEP 4 — ATTACK PATHS: If this resource is compromised:
- What's the blast radius?
- Can the attacker pivot to other tenants?
- Can they tamper with compliance evidence?
- Can they forge audit results?

STEP 5 — VERIFY: Challenge your reasoning:
- Are there mitigating controls not visible in the CDK code?
- Is this finding practically exploitable or just theoretical?
- Does the CDK nag suppression justify the exception?

STEP 6 — VERDICT + REMEDIATION:
{{ CRITICAL | HIGH | MEDIUM | LOW | ACCEPTABLE }}
Confidence: {{ HIGH | MEDIUM | LOW }}
Specific fix in CDK code (Python)."""


# =============================================================================
# SKILL 5: CDK Nag Suppression Audit
# =============================================================================

CDK_NAG_SUPPRESSION_AUDIT = {
    "description": "Verify that CDK nag suppressions are justified and not hiding real issues",
    "checks": [
        {
            "suppressed_rule": "AwsSolutions-IAM4",
            "original_purpose": "Flags use of AWS managed policies",
            "justification_required": "Managed policy is least-privilege for this use case",
            "risk_if_unjustified": "Overly broad managed policy attached to Lambda",
        },
        {
            "suppressed_rule": "AwsSolutions-IAM5",
            "original_purpose": "Flags wildcard permissions in statements",
            "justification_required": "Service does not support resource-level permissions",
            "risk_if_unjustified": "Unnecessarily broad access to all resources",
            "codebase_note": "Used for Bedrock, Textract, AgentCore — verify each one. "
                          "Bedrock/Textract genuinely lack resource-level perms. "
                          "AgentCore MAY support resource-level (check latest docs)."
        },
        {
            "suppressed_rule": "AwsSolutions-APIG4",
            "original_purpose": "API Gateway should have authorization on all methods",
            "justification_required": "Method is intentionally public (health check, login)",
            "risk_if_unjustified": "Unauthenticated access to sensitive endpoints",
        },
        {
            "suppressed_rule": "AwsSolutions-COG4",
            "original_purpose": "Cognito should use advanced security features",
            "justification_required": "Cost or feature not needed for use case",
            "risk_if_unjustified": "Missing threat protection (compromised credentials, bot detection)",
        },
        {
            "suppressed_rule": "AwsSolutions-L1",
            "original_purpose": "Lambda should use latest runtime version",
            "justification_required": "Docker-based Lambda (runtime managed in Dockerfile)",
            "risk_if_unjustified": "Running on unpatched runtime with known vulnerabilities",
        },
    ]
}


# =============================================================================
# SKILL 6: Blast Radius Computation (Pre-defined for this architecture)
# =============================================================================

BLAST_RADIUS_MAP = {
    "agent_lambda": {
        "description": "Main compliance agent Lambda",
        "if_compromised": [
            "All DynamoDB sessions (read/write) — all tenants",
            "All S3 evidence artifacts (read/write) — all tenants",
            "Bedrock model invocation (could generate fake evaluations)",
            "Bedrock AgentCore (could create/modify agents)",
            "Lambda invocation of v2/v3 (lateral movement)",
            "CloudWatch Logs (read all log groups)",
        ],
        "tenant_impact": "ALL TENANTS (no IAM-level tenant isolation)",
        "data_at_risk": "Compliance evaluations, evidence documents, session history",
        "blast_score": 9.2,
    },
    "auth_lambda": {
        "description": "Authentication/authorization Lambda",
        "if_compromised": [
            "Cognito User Pool (create/modify any user)",
            "DynamoDB tenants table (read/write)",
            "DynamoDB policies table (read/write)",
            "DynamoDB user_tenants table (read/write)",
        ],
        "tenant_impact": "ALL TENANTS + can create new unauthorized tenants",
        "data_at_risk": "User credentials (via password reset), tenant configuration, RBAC policies",
        "blast_score": 9.5,
    },
    "authorizer_lambda": {
        "description": "API Gateway Lambda authorizer",
        "if_compromised": [
            "DynamoDB policies table (read only)",
            "Can return arbitrary permissions to API Gateway",
            "Effectively bypasses all RBAC",
        ],
        "tenant_impact": "ALL TENANTS (authorizer is shared)",
        "data_at_risk": "Complete authorization bypass — all downstream access",
        "blast_score": 10.0,
    },
    "observer_lambda": {
        "description": "Monitoring/observability Lambda",
        "if_compromised": [
            "CloudWatch Logs Insights (read all logs)",
            "Could expose PII, tokens, or internal errors from logs",
        ],
        "tenant_impact": "ALL TENANTS (shared log groups)",
        "data_at_risk": "Operational logs, potentially containing user data",
        "blast_score": 5.0,
    },
}


# =============================================================================
# SKILL 7: Remediation Templates (CDK-Specific)
# =============================================================================

REMEDIATION_TEMPLATES = {
    "scope_iam_wildcard": {
        "before": """
iam.PolicyStatement(
    actions=['bedrock-agentcore:*'],
    resources=['*']
)""",
        "after": """
iam.PolicyStatement(
    actions=[
        'bedrock-agentcore:InvokeAgent',
        'bedrock-agentcore:GetAgent',
    ],
    resources=[f'arn:aws:bedrock-agentcore:{region}:{account}:agent/*']
)""",
        "explanation": "Scope agentcore actions to only what the Lambda needs"
    },
    "add_dynamodb_leading_key_condition": {
        "before": """
sessions_table.grant_read_write_data(agent_lambda)
""",
        "after": """
agent_lambda.add_to_role_policy(iam.PolicyStatement(
    actions=[
        'dynamodb:GetItem', 'dynamodb:PutItem',
        'dynamodb:UpdateItem', 'dynamodb:Query'
    ],
    resources=[sessions_table.table_arn],
    conditions={
        'ForAllValues:StringLike': {
            'dynamodb:LeadingKeys': ['TENANT#${aws:PrincipalTag/tenant_id}*']
        }
    }
))
""",
        "explanation": "Enforce tenant isolation at IAM level using leading key condition"
    },
    "enable_s3_versioning_and_logging": {
        "before": """
evidence_bucket = s3.Bucket(self, 'EvidenceBucket',
    encryption=s3.BucketEncryption.S3_MANAGED,
    block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
    enforce_ssl=True,
)""",
        "after": """
access_logs_bucket = s3.Bucket(self, 'EvidenceAccessLogs',
    encryption=s3.BucketEncryption.S3_MANAGED,
    block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
    lifecycle_rules=[s3.LifecycleRule(expiration=Duration.days(365))],
)

evidence_bucket = s3.Bucket(self, 'EvidenceBucket',
    encryption=s3.BucketEncryption.S3_MANAGED,
    block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
    enforce_ssl=True,
    versioned=True,
    server_access_logs_bucket=access_logs_bucket,
    server_access_logs_prefix='evidence-access/',
)""",
        "explanation": "Enable versioning (prevent evidence tampering) and access logging (audit trail)"
    },
    "extend_log_retention": {
        "before": """
log_retention=logs.RetentionDays.ONE_WEEK,
""",
        "after": """
log_retention=logs.RetentionDays.ONE_YEAR,
""",
        "explanation": "Compliance platforms require minimum 1 year log retention for audit"
    },
    "cognito_immutable_role": {
        "before": """
custom_attributes={
    'tenant_id': cognito.StringAttribute(mutable=True),
    'role': cognito.StringAttribute(mutable=True),
}""",
        "after": """
custom_attributes={
    'tenant_id': cognito.StringAttribute(mutable=False),
    'tenant_name': cognito.StringAttribute(mutable=False),
    'role': cognito.StringAttribute(mutable=False),
}""",
        "explanation": "Security-critical attributes must be immutable to prevent self-escalation"
    },
}
