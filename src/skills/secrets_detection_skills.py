from __future__ import annotations

"""
Secrets & Credential Detection Skills
========================================
Identify hardcoded secrets, credentials, and sensitive configuration
exposed in the compliance codebase.
"""


# =============================================================================
# SKILL 1: Secret Patterns to Detect
# =============================================================================

SECRET_PATTERNS = [
    {
        "id": "SEC-001",
        "category": "aws_account_id",
        "severity": "LOW",
        "pattern": r'\d{12}',
        "context_required": "Must appear in context of AWS ARN, account reference, or CDK env",
        "description": "AWS Account ID hardcoded. Not a credential itself but enables "
                     "targeted attacks (phishing, resource enumeration).",
        "known_instances": [
            "infra/app.py: account='421528023685'",
        ],
        "remediation": "Use CDK environment lookup: os.environ.get('CDK_DEFAULT_ACCOUNT') "
                     "or cdk.Aws.ACCOUNT_ID for runtime references.",
    },
    {
        "id": "SEC-002",
        "category": "api_endpoint",
        "severity": "MEDIUM",
        "pattern": r'https://[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com',
        "description": "API Gateway endpoint hardcoded in frontend JavaScript. "
                     "Exposes the API URL for direct access outside the application.",
        "known_instances": [
            "frontend/auth.js: AUTH_API = 'https://4hvoe6om48.execute-api.us-east-1.amazonaws.com/v1'",
        ],
        "remediation": "Inject API URL at build/deploy time via environment config. "
                     "Or use relative paths with CloudFront origin routing.",
    },
    {
        "id": "SEC-003",
        "category": "api_key",
        "severity": "HIGH",
        "pattern": r'[Xx]-[Aa]pi-[Kk]ey[\'\":\s]+[\w]{20,}',
        "description": "API key in client-side code. Anyone can extract and use it. "
                     "API keys are not authentication — they're for throttling.",
        "known_instances": [
            "Check frontend/ for X-Api-Key header values",
            "Check .env files for COMPLIANCE_API_KEY",
        ],
        "impact": "Shared API key = no per-user attribution of API calls. "
                 "If rate-limited by key, one abuser blocks all users.",
        "remediation": "Remove API key from frontend. Use Cognito tokens (already implemented) "
                     "as primary auth. API key adds nothing if Cognito auth is enforced.",
    },
    {
        "id": "SEC-004",
        "category": "cognito_ids",
        "severity": "LOW",
        "pattern": r'(us-east-1_[A-Za-z0-9]+|[0-9a-z]{26})',
        "description": "Cognito User Pool ID and App Client ID. These are semi-public "
                     "(needed by clients) but unnecessary to expose in source code.",
        "known_instances": [
            "Check Lambda environment variables for USER_POOL_ID, APP_CLIENT_ID",
        ],
        "impact": "Enables targeted Cognito attacks (InitiateAuth brute force, "
                 "enumerate users via SignUp error messages).",
        "remediation": "These IDs must be accessible to the frontend (for Cognito JS SDK). "
                     "Not a vulnerability per se, but ensure: rate limiting on Cognito, "
                     "advanced security features (bot detection), and email enumeration prevention.",
    },
    {
        "id": "SEC-005",
        "category": "bedrock_model_id",
        "severity": "LOW",
        "pattern": r'(anthropic|amazon|meta)\.[a-z0-9-]+v\d',
        "description": "Bedrock model ID in code/config. Not sensitive but reveals "
                     "which model is used (cost/capability inference).",
        "known_instances": [
            "src/agent/config.py: BEDROCK_MODEL_ID = 'us.anthropic.claude-3-5-haiku-20241022-v1:0'",
        ],
        "remediation": "No action needed — model IDs are not secrets.",
    },
    {
        "id": "SEC-006",
        "category": "private_key_material",
        "severity": "CRITICAL",
        "pattern": r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
        "description": "Private key in source code.",
        "remediation": "Immediately rotate. Store in AWS Secrets Manager or SSM SecureString.",
    },
    {
        "id": "SEC-007",
        "category": "database_credentials",
        "severity": "CRITICAL",
        "pattern": r'(password|passwd|pwd)\s*[=:]\s*[\'"][^\'"]+[\'"]',
        "description": "Database password hardcoded.",
        "context_exclude": "Test fixtures, example configs with placeholder values",
        "remediation": "Use Secrets Manager with automatic rotation.",
    },
    {
        "id": "SEC-008",
        "category": "jwt_secret",
        "severity": "CRITICAL",
        "pattern": r'(jwt_secret|JWT_SECRET|secret_key|SECRET_KEY)\s*[=:]\s*[\'"][^\'"]+[\'"]',
        "description": "JWT signing secret in code. Allows token forgery.",
        "note": "This codebase uses Cognito (RS256 with managed keys), not custom JWT. "
               "So this pattern likely won't match — but check anyway.",
    },
]


# =============================================================================
# SKILL 2: Environment Variable Security Audit
# =============================================================================

ENV_VAR_AUDIT = {
    "description": "Classify environment variables by sensitivity and verify "
                 "appropriate handling.",
    "variables": [
        {
            "name": "S3_BUCKET_NAME",
            "sensitivity": "LOW",
            "reason": "Bucket name is not a secret (access controlled by IAM)",
            "handling": "Environment variable is fine",
        },
        {
            "name": "DYNAMODB_TABLE_NAME",
            "sensitivity": "LOW",
            "reason": "Table name is not a secret",
            "handling": "Environment variable is fine",
        },
        {
            "name": "USER_POOL_ID",
            "sensitivity": "LOW",
            "reason": "Semi-public (clients need it for auth)",
            "handling": "Environment variable is fine",
        },
        {
            "name": "APP_CLIENT_ID",
            "sensitivity": "LOW",
            "reason": "Semi-public (clients need it for auth)",
            "handling": "Environment variable is fine",
        },
        {
            "name": "BEDROCK_MODEL_ID",
            "sensitivity": "LOW",
            "reason": "Model identifier, not a credential",
            "handling": "Environment variable is fine",
        },
        {
            "name": "AGENTCORE_GATEWAY_ENDPOINT",
            "sensitivity": "MEDIUM",
            "reason": "Internal endpoint URL — reveals infrastructure",
            "handling": "Environment variable acceptable if Lambda is in VPC. "
                      "If exposed, attacker knows where to target.",
        },
        {
            "name": "AGENTCORE_RUNTIME_ENDPOINT",
            "sensitivity": "MEDIUM",
            "reason": "Internal endpoint URL",
            "handling": "Same as above",
        },
        {
            "name": "BEDROCK_KB_ID",
            "sensitivity": "LOW",
            "reason": "Knowledge base ID, access controlled by IAM",
            "handling": "Environment variable is fine",
        },
    ],
    "missing_secrets_manager": [
        "No database passwords found (DynamoDB uses IAM — good)",
        "No API keys for external services found in env vars",
        "Cognito uses managed keys (no secret storage needed)",
        "Bedrock uses IAM auth (no API key needed)",
    ],
    "verdict": "This codebase correctly avoids storing secrets in environment variables. "
             "All AWS service access uses IAM roles. No external API keys detected. "
             "The main concern is hardcoded endpoints and account IDs (LOW severity).",
}


# =============================================================================
# SKILL 3: Git History Secret Scan Rules
# =============================================================================

GIT_HISTORY_CHECKS = {
    "description": "Secrets may have been committed and later removed. "
                 "They remain in git history.",
    "commands": [
        "git log --all --diff-filter=D -- '*.env' '*.key' '*.pem'",
        "git log --all -p -- '*secret*' '*credential*' '*password*'",
        "git log --all -p -- '.env' '.env.local' '.env.production'",
    ],
    "tools": [
        "trufflehog (scans git history for high-entropy strings)",
        "gitleaks (pattern-based secret detection in git history)",
        "git-secrets (AWS-specific secret patterns)",
    ],
    "note": "This is a runtime check, not static analysis. "
           "Include in CI pipeline, not in every agent scan.",
}


# =============================================================================
# SKILL 4: Sensitive Data Flow Classification
# =============================================================================

SENSITIVE_DATA_FLOWS = {
    "pii_fields": [
        "email (in Cognito user, DynamoDB user records)",
        "user_id / sub (in JWT, DynamoDB, logs)",
        "tenant_name (in Cognito, DynamoDB)",
    ],
    "compliance_data": [
        "Evaluation results (in DynamoDB sessions, S3)",
        "Evidence documents (in S3, referenced in DynamoDB)",
        "Audit logs (in DynamoDB, CloudWatch)",
        "Control test results (in DynamoDB)",
    ],
    "credentials": [
        "JWT tokens (in sessionStorage, request headers, possibly logs)",
        "Refresh tokens (in sessionStorage, Cognito)",
        "AWS credentials (Lambda role — never in code, from IMDS)",
    ],
    "classification_rules": {
        "MUST_NOT_LOG": ["JWT tokens", "refresh tokens", "passwords", "evidence content"],
        "MUST_ENCRYPT_AT_REST": ["evaluation results", "evidence documents", "audit logs"],
        "MUST_ENCRYPT_IN_TRANSIT": ["all API calls (TLS enforced by API Gateway)"],
        "MUST_HAVE_ACCESS_LOGGING": ["S3 evidence bucket", "DynamoDB compliance tables"],
    },
}
