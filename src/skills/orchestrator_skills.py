from __future__ import annotations

"""
Orchestrator Skills
====================
Skills for the Orchestrator Agent (Agent 1) — repo scanning, agent dispatch,
cross-boundary correlation.

Tailored to the compliance codebase structure.
"""


# =============================================================================
# SKILL 1: Technology Detection Rules
# =============================================================================

TECHNOLOGY_DETECTION = {
    "python_app": {
        "indicators": [
            "src/agent/handler.py",
            "src/auth/auth_handler.py",
            "src/agent_chat/handler.py",
        ],
        "frameworks_detected": {
            "langgraph": "src/agent/graph.py (LangGraph state machine)",
            "langchain": "langchain-aws in requirements",
            "boto3": "boto3 used in 30+ files",
            "pydantic": "pydantic used for state/request validation",
        },
        "entry_points": [
            "src/agent/handler.py:lambda_handler",
            "src/agent/handler_v2.py:lambda_handler",
            "src/agent/handler_v3.py:lambda_handler",
            "src/auth/auth_handler.py:lambda_handler",
            "src/auth/authorizer.py:lambda_handler",
            "src/auth/data_handler.py:lambda_handler",
            "src/observer/handler.py:lambda_handler",
            "src/agent_chat/handler.py:lambda_handler",
        ],
        "directories": ["src/"],
    },
    "cdk_infra": {
        "indicators": [
            "cdk.json",
            "infra/app.py",
            "infra/stacks/compliance_stack.py",
        ],
        "stacks_detected": [
            "ComplianceAgentStack (compute + storage)",
            "ComplianceAuthStack (cognito + auth lambdas)",
            "ComplianceFrontendStack (SPA distribution)",
            "ComplianceV2Stack (async agent)",
        ],
        "directories": ["infra/"],
    },
    "frontend": {
        "indicators": [
            "frontend/index.html",
            "frontend/auth.js",
            "frontend/app.js",
        ],
        "framework": "Vanilla JS SPA (no React/Vue/Angular)",
        "security_relevant": [
            "frontend/auth.js (token handling, API endpoint hardcoded)",
        ],
        "directories": ["frontend/"],
    },
}


# =============================================================================
# SKILL 2: Cross-Boundary Reference Map
# =============================================================================

CROSS_BOUNDARY_REFERENCES = [
    {
        "type": "env_var_injection",
        "source": "infra/stacks/compliance_stack.py (CDK environment variables)",
        "target": "src/agent/config.py (reads os.environ)",
        "variables": [
            "S3_BUCKET_NAME",
            "DYNAMODB_TABLE_NAME",
            "BEDROCK_MODEL_ID",
            "BEDROCK_REGION",
            "BEDROCK_KB_ID",
            "AGENTCORE_GATEWAY_ENDPOINT",
            "AGENTCORE_RUNTIME_ENDPOINT",
            "LAMBDA_FUNCTION_NAME",
        ],
        "security_implication": "If env vars are modified (via Lambda configuration access), "
                              "agent could be pointed at attacker-controlled endpoints."
    },
    {
        "type": "iam_to_code",
        "source": "infra/stacks/compliance_stack.py (IAM policies)",
        "target": "src/agent/handler_v2.py (boto3 calls)",
        "relationship": "IAM policy defines ceiling, code uses a subset. "
                       "If policy is broader than code needs, compromise is worse.",
        "specific_excess": [
            "bedrock-agentcore:* granted but code only uses InvokeAgent",
            "S3 grant_read_write but some Lambdas only read",
            "DynamoDB full read_write but observer only reads",
        ]
    },
    {
        "type": "cognito_to_auth",
        "source": "infra/stacks/compliance_auth_stack.py (Cognito config)",
        "target": "src/auth/authorizer.py (JWT validation)",
        "relationship": "Cognito user pool attributes flow into JWT claims → authorizer "
                       "extracts them → injects into Lambda context → used for RBAC",
        "attack_surface": "If custom attributes (role, tenant_id) are mutable in Cognito, "
                        "user can self-assign via UpdateUserAttributes SDK call."
    },
    {
        "type": "permissions_to_tools",
        "source": "src/agent_chat/permissions.py (RBAC matrix)",
        "target": "src/agent/graph.py (LangGraph tool nodes)",
        "relationship": "Permission check uses tool_name → maps to (resource, action) → "
                       "checks role. Tool execution in graph must call check_permission first.",
        "gap_risk": "If a tool node in the graph is invoked without passing through "
                  "the permission check node, RBAC is bypassed."
    },
    {
        "type": "presigned_url_scope",
        "source": "infra/stacks/compliance_stack.py (S3 bucket + IAM)",
        "target": "src/agent/handler_v2.py (presigned URL generation)",
        "relationship": "Lambda generates presigned URLs for evidence upload. "
                       "The URL scope is determined by the S3 key passed to generate_presigned_url.",
        "gap_risk": "If the S3 key includes user-controlled filename without tenant prefix validation, "
                  "user could generate URL for another tenant's path."
    },
]


# =============================================================================
# SKILL 3: Cross-Boundary Correlation Patterns
# =============================================================================

CORRELATION_PATTERNS = [
    {
        "id": "XB-001",
        "name": "Overpermissive IAM + Unsafe Input Handling",
        "app_signal": "User input reaches boto3 call without full validation",
        "infra_signal": "IAM policy broader than minimum needed",
        "compound_severity": "CRITICAL",
        "detection": """
            IF Python agent finds: user-controlled data influences DynamoDB/S3 key
            AND Infra agent finds: IAM grants read_write to entire table/bucket
            THEN: Compromise enables full data access, not just target resource
        """,
        "example_in_codebase": """
            Python finding: customer_id from request body used in DynamoDB query
            Infra finding: Lambda has dynamodb:* on sessions table (no LeadingKey condition)
            Compound: If tenant validation is bypassed, attacker reads ALL tenants' sessions
        """
    },
    {
        "id": "XB-002",
        "name": "Prompt Injection + Tool Execution + Broad Permissions",
        "app_signal": "User messages reach LLM without content filtering",
        "infra_signal": "Agent Lambda has broad permissions (S3 write, DynamoDB write, Lambda invoke)",
        "compound_severity": "HIGH",
        "detection": """
            IF Python agent finds: user message flows to Bedrock without boundary markers
            AND Python agent finds: LangGraph can route to tools (evidence upload, evaluation)
            AND Infra agent finds: Lambda role has write access to evidence bucket
            THEN: Prompt injection could cause agent to upload malicious evidence or
                  forge evaluation results
        """,
    },
    {
        "id": "XB-003",
        "name": "JWT Claim Trust + Mutable Cognito Attributes",
        "app_signal": "Authorizer trusts custom:role claim without additional verification",
        "infra_signal": "Cognito custom:role attribute is mutable (user can self-modify)",
        "compound_severity": "CRITICAL",
        "detection": """
            IF Python agent finds: authorizer extracts role from JWT custom:role claim
            AND Infra agent finds: custom:role is mutable=True in Cognito config
            THEN: User calls UpdateUserAttributes → sets custom:role=admin →
                  next token includes admin role → full privilege escalation
        """,
    },
    {
        "id": "XB-004",
        "name": "Short Log Retention + Sensitive Data Logging",
        "app_signal": "User data (messages, evidence) flows to logger.info/print",
        "infra_signal": "CloudWatch log retention is 7 days",
        "compound_severity": "MEDIUM",
        "detection": """
            IF Python agent finds: sensitive data logged
            AND Infra agent finds: log retention < 365 days
            THEN: PII in logs cannot be audited beyond 7 days, but also:
                  the short retention means evidence of breach disappears quickly
        """,
        "note": "This is both a compliance violation AND a security weakness"
    },
    {
        "id": "XB-005",
        "name": "No S3 Versioning + Evidence Write Access",
        "app_signal": "Lambda handler writes compliance evaluation results to S3",
        "infra_signal": "S3 bucket has no versioning enabled",
        "compound_severity": "HIGH",
        "detection": """
            IF Python agent finds: evidence/evaluation written to S3
            AND Infra agent finds: bucket versioned=False
            THEN: Compromised Lambda (or authorized user with write access) can
                  overwrite/delete compliance evidence with no recovery path.
                  For a COMPLIANCE platform, this undermines the entire audit trail.
        """,
    },
]


# =============================================================================
# SKILL 4: Execution Plan for Compliance Codebase
# =============================================================================

EXECUTION_PLAN = {
    "phase_1_discovery": {
        "technologies": ["python_app", "cdk_infra"],
        "agents_needed": ["python", "infrastructure", "validation"],
        "parallel_groups": [
            ["python", "infrastructure"],  # Can run in parallel (independent)
        ],
        "sequential_dependencies": [
            "infrastructure before correlation (need IAM findings first)",
        ],
    },
    "phase_2_agent_config": {
        "python_agent": {
            "directories": ["src/"],
            "entry_points": [
                "src/agent/handler.py",
                "src/agent/handler_v2.py",
                "src/auth/auth_handler.py",
                "src/auth/authorizer.py",
                "src/auth/data_handler.py",
                "src/agent_chat/handler.py",
            ],
            "frameworks": ["langgraph", "boto3", "pydantic", "cognito"],
            "priority_paths": [
                "event['body'] → DynamoDB key construction",
                "event['body'] → S3 key construction",
                "event['body'] → Cognito user attributes",
                "state['messages'] → tool execution",
            ],
            "budget": 2.00,
        },
        "infrastructure_agent": {
            "input_type": "cdk",
            "synth_command": "cd /Users/indukuk/compliance && cdk synth",
            "stacks": [
                "infra/stacks/compliance_stack.py",
                "infra/stacks/compliance_auth_stack.py",
                "infra/stacks/compliance_frontend_stack.py",
            ],
            "focus_areas": [
                "IAM wildcard permissions",
                "Cognito attribute mutability",
                "S3 versioning and logging",
                "Log retention for compliance",
                "Multi-tenant isolation at IAM level",
            ],
            "budget": 1.50,
        },
        "validation_agent": {
            "known_safe_patterns": "validation_skills.KNOWN_SAFE_PATTERNS",
            "framework_protections": "validation_skills.FRAMEWORK_PROTECTIONS",
            "budget": 1.00,
        },
    },
    "phase_5_correlation": {
        "cross_references": "CROSS_BOUNDARY_REFERENCES",
        "correlation_patterns": "CORRELATION_PATTERNS",
        "budget": 0.50,
    },
    "total_budget": 5.00,
}


# =============================================================================
# SKILL 5: Report Template (Compliance-Specific)
# =============================================================================

REPORT_TEMPLATE = """
# Security Assessment: Lotus AI Compliance Platform
Generated: {timestamp}

## Executive Summary
{executive_summary}

## Risk Overview
| Severity | Count | Action Required |
|----------|-------|-----------------|
| CRITICAL | {critical_count} | Immediate remediation |
| HIGH | {high_count} | Remediate before next release |
| MEDIUM | {medium_count} | Plan remediation |
| LOW | {low_count} | Accept or address opportunistically |

## Coverage
{coverage_summary}

## Critical Findings
{critical_findings}

## Compound Risk (Cross-Boundary)
{compound_findings}

## Infrastructure Findings
{infra_findings}

## Application Code Findings
{app_findings}

## Compliance Impact
For a compliance platform (SOC2, HIPAA), these findings have additional implications:
{compliance_impact}

## Recommended Remediation Priority
{remediation_priority}

## Appendix: CDK Nag Suppression Audit
{nag_audit}

---
Analysis cost: ${total_cost:.2f}
Risk-weighted coverage: {coverage_pct:.0%}
"""
