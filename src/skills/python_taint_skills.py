from __future__ import annotations

"""
Python Application Security Skills
====================================
Skills for the Python Application Agent (Agent 2) tailored to the compliance codebase.

This codebase is a serverless multi-tenant compliance platform with:
- Lambda handlers as entry points (API Gateway + Function URL)
- LangGraph/LangChain agentic workflows
- boto3 for AWS service interaction (DynamoDB, S3, Cognito, Bedrock)
- Pydantic for data validation
- Custom JWT validation (RSA RS256)
- Role-based access control (RBAC)
"""

from dataclasses import dataclass, field


# =============================================================================
# SKILL 1: Source/Sink/Sanitizer Definitions (Baseline)
# =============================================================================

@dataclass
class TaintSpec:
    function: str
    category: str
    cwe: str | None = None
    confidence: str = "HIGH"
    description: str = ""


PYTHON_SOURCES = [
    # Lambda entry points (API Gateway events)
    TaintSpec(
        function="event['body']",
        category="http_input",
        description="Lambda handler receives API Gateway event body (user-controlled JSON)"
    ),
    TaintSpec(
        function="event['queryStringParameters']",
        category="http_input",
        description="URL query parameters from API Gateway"
    ),
    TaintSpec(
        function="event['pathParameters']",
        category="http_input",
        description="URL path parameters from API Gateway"
    ),
    TaintSpec(
        function="event['headers']",
        category="http_input",
        description="HTTP headers (partially user-controlled)"
    ),
    TaintSpec(
        function="json.loads(event.get('body', '{}'))",
        category="http_input",
        description="Parsed JSON body from Lambda event"
    ),

    # Request context (injected by authorizer but originates from JWT)
    TaintSpec(
        function="event['requestContext']['authorizer']",
        category="auth_context",
        confidence="MEDIUM",
        description="Authorizer context — validated but tenant_id/role from JWT claims"
    ),

    # Environment variables (could be set externally)
    TaintSpec(
        function="os.environ.get()",
        category="env_var",
        confidence="LOW",
        description="Environment variables — set at deploy time, generally trusted"
    ),
    TaintSpec(
        function="os.getenv()",
        category="env_var",
        confidence="LOW",
        description="Environment variables"
    ),

    # DynamoDB query results (could contain user-supplied data)
    TaintSpec(
        function="table.query()['Items']",
        category="database_output",
        confidence="MEDIUM",
        description="DynamoDB results may contain previously stored user input"
    ),
    TaintSpec(
        function="table.get_item()['Item']",
        category="database_output",
        confidence="MEDIUM",
        description="DynamoDB item may contain user-supplied data"
    ),

    # S3 object content
    TaintSpec(
        function="s3_client.get_object()['Body'].read()",
        category="file_input",
        confidence="MEDIUM",
        description="S3 object content — may be user-uploaded evidence"
    ),

    # LangGraph state (carries user messages through the graph)
    TaintSpec(
        function="state['messages']",
        category="user_message",
        description="User messages flowing through LangGraph state machine"
    ),
    TaintSpec(
        function="state.get('messages')",
        category="user_message",
        description="User messages from agent state"
    ),
]


PYTHON_SINKS = [
    # DynamoDB write operations (injection via expression attributes)
    TaintSpec(
        function="table.put_item(Item=...)",
        category="nosql_write",
        cwe="CWE-943",
        description="DynamoDB put_item — data stored without validation could be retrieved later unsafely"
    ),
    TaintSpec(
        function="table.update_item(UpdateExpression=...)",
        category="nosql_write",
        cwe="CWE-943",
        description="DynamoDB update expression — verify ExpressionAttributeValues are used"
    ),

    # Cognito admin operations (user attribute injection)
    TaintSpec(
        function="cognito_client.admin_create_user(UserAttributes=...)",
        category="identity_write",
        cwe="CWE-284",
        description="Setting Cognito user attributes — controls tenant/role assignment"
    ),
    TaintSpec(
        function="cognito_client.admin_update_user_attributes(UserAttributes=...)",
        category="identity_write",
        cwe="CWE-284",
        description="Updating user attributes could elevate privileges"
    ),

    # S3 operations (path injection)
    TaintSpec(
        function="s3_client.put_object(Key=...)",
        category="file_write",
        cwe="CWE-22",
        description="S3 key constructed from user input — path traversal risk"
    ),
    TaintSpec(
        function="s3_client.generate_presigned_url(Params={'Key': ...})",
        category="file_access",
        cwe="CWE-22",
        description="Presigned URL key from user input — could access other tenants' data"
    ),

    # Code execution (sandbox evaluation)
    TaintSpec(
        function="exec()",
        category="code_execution",
        cwe="CWE-94",
        description="Dynamic code execution — sandbox escape risk"
    ),
    TaintSpec(
        function="eval()",
        category="code_execution",
        cwe="CWE-94",
        description="Dynamic expression evaluation"
    ),
    TaintSpec(
        function="subprocess.run()",
        category="command_injection",
        cwe="CWE-78",
        description="System command execution"
    ),

    # Bedrock model invocation (prompt injection)
    TaintSpec(
        function="bedrock_client.invoke_model(body=...)",
        category="prompt_injection",
        cwe="CWE-77",
        description="User input reaching LLM prompt — prompt injection risk"
    ),

    # HTTP response (information disclosure)
    TaintSpec(
        function="return {'statusCode': 200, 'body': json.dumps(...)}",
        category="http_response",
        cwe="CWE-200",
        confidence="LOW",
        description="Data returned to user — check for information leakage across tenants"
    ),

    # Logging (sensitive data exposure)
    TaintSpec(
        function="logger.info()",
        category="logging",
        cwe="CWE-532",
        confidence="LOW",
        description="Logging user data — PII or credentials in logs"
    ),
    TaintSpec(
        function="print()",
        category="logging",
        cwe="CWE-532",
        confidence="LOW",
        description="Print statements going to CloudWatch"
    ),
]


PYTHON_SANITIZERS = [
    # Pydantic validation
    TaintSpec(
        function="BaseModel.model_validate()",
        category="schema_validation",
        description="Pydantic model validation — enforces type and structure"
    ),
    TaintSpec(
        function="TypeAdapter.validate_python()",
        category="schema_validation",
        description="Pydantic type validation"
    ),

    # DynamoDB expression attributes (parameterized queries)
    TaintSpec(
        function="ExpressionAttributeValues",
        category="parameterized_query",
        description="DynamoDB expression attributes prevent injection"
    ),
    TaintSpec(
        function="Key({'pk': ..., 'sk': ...})",
        category="parameterized_query",
        description="DynamoDB Key conditions are type-safe"
    ),

    # JSON schema validation
    TaintSpec(
        function="json.loads()",
        category="type_conversion",
        confidence="MEDIUM",
        description="JSON parsing provides type structure but not value validation"
    ),

    # Permission checks (authorization gates)
    TaintSpec(
        function="check_permission()",
        category="authorization",
        description="RBAC permission check — gates access to resources"
    ),

    # Tenant isolation check
    TaintSpec(
        function="tenant_id == request_tenant_id",
        category="tenant_isolation",
        description="Tenant boundary enforcement"
    ),
]


# =============================================================================
# SKILL 2: Compliance-Codebase-Specific Vulnerability Patterns
# =============================================================================

VULNERABILITY_PATTERNS = [
    {
        "id": "COMP-TENANT-001",
        "name": "Cross-Tenant Data Access",
        "cwe": "CWE-639",
        "severity": "CRITICAL",
        "description": "User from Tenant A can access data belonging to Tenant B",
        "pattern": {
            "source": "tenant_id from request context or body",
            "sink": "DynamoDB query or S3 key construction",
            "missing_sanitizer": "tenant_id validation against authenticated tenant"
        },
        "detection_query": """
            Find paths where:
            1. A tenant_id or customer_id is extracted from request body (user-controlled)
            2. That ID is used to construct a DynamoDB pk/sk or S3 key
            3. Without verifying it matches the authenticated tenant from JWT
        """,
        "example": """
            # VULNERABLE: tenant_id from body, not from auth context
            body = json.loads(event['body'])
            customer_id = body.get('customer_id')  # User-controlled!
            table.query(KeyConditionExpression=Key('pk').eq(f'TENANT#{customer_id}'))

            # SAFE: tenant_id from authorizer context
            tenant_id = event['requestContext']['authorizer']['tenant_id']
            table.query(KeyConditionExpression=Key('pk').eq(f'TENANT#{tenant_id}'))
        """
    },
    {
        "id": "COMP-TENANT-002",
        "name": "S3 Path Traversal Across Tenants",
        "cwe": "CWE-22",
        "severity": "HIGH",
        "description": "User-controlled filename in S3 key allows accessing other tenants' evidence",
        "pattern": {
            "source": "filename or key from request body",
            "sink": "S3 put_object or generate_presigned_url",
            "missing_sanitizer": "path normalization + tenant prefix enforcement"
        },
        "detection_query": """
            Find paths where:
            1. A filename/key is extracted from user input
            2. Used to construct an S3 key (possibly with tenant prefix)
            3. Without validating: no '../', key starts with expected tenant prefix
        """
    },
    {
        "id": "COMP-AUTH-001",
        "name": "JWT Claim Injection via Custom Attributes",
        "cwe": "CWE-290",
        "severity": "HIGH",
        "description": "Cognito custom attributes (tenant_id, role) set at signup without admin validation",
        "pattern": {
            "source": "signup request body",
            "sink": "admin_create_user UserAttributes",
            "missing_sanitizer": "admin approval step for tenant/role assignment"
        },
        "detection_query": """
            Find paths where:
            1. User provides tenant_name or role in signup request
            2. These are passed directly to Cognito custom attributes
            3. Without admin approval or invitation token validation
        """
    },
    {
        "id": "COMP-AUTH-002",
        "name": "Permission Bypass via Tool Name Manipulation",
        "cwe": "CWE-285",
        "severity": "HIGH",
        "description": "User can invoke tools not in the permission matrix by using unmapped names",
        "pattern": {
            "source": "tool_name from user request or LangGraph routing",
            "sink": "tool execution (function call)",
            "missing_sanitizer": "check_permission() with deny-by-default for unknown tools"
        },
        "detection_query": """
            Find paths where:
            1. A tool_name is determined from user input or LLM routing
            2. check_permission() returns allow-by-default for unmapped tools
            3. Tool is executed without explicit permission grant
        """
    },
    {
        "id": "COMP-PROMPT-001",
        "name": "Prompt Injection via User Messages",
        "cwe": "CWE-77",
        "severity": "MEDIUM",
        "description": "User message content flows to Bedrock prompt without sanitization",
        "pattern": {
            "source": "state['messages'] (user input in LangGraph)",
            "sink": "bedrock invoke_model or agent graph node",
            "missing_sanitizer": "prompt boundary enforcement or input filtering"
        },
        "detection_query": """
            Find paths where:
            1. User message content enters the LangGraph state
            2. Flows through graph nodes to a Bedrock model call
            3. Without content filtering or prompt boundary markers

            Note: This is an inherent risk in LLM applications.
            Focus on cases where prompt injection could bypass RBAC
            (e.g., tricking the agent into running tools the user lacks permission for).
        """
    },
    {
        "id": "COMP-SCOPE-001",
        "name": "Scope Bypass via Resource ID Manipulation",
        "cwe": "CWE-639",
        "severity": "HIGH",
        "description": "Scoped user (compliance_manager) accesses controls outside their assigned scope",
        "pattern": {
            "source": "control_id or resource_id from request",
            "sink": "DynamoDB query or tool execution",
            "missing_sanitizer": "scope.rules check against allowed_resource_ids"
        },
        "detection_query": """
            Find paths where:
            1. A compliance_manager invokes a scoped action (controls:write, controls:evaluate)
            2. Resource ID comes from request rather than from their scope rules
            3. Without checking resource_id ∈ allowed_resource_ids
        """
    },
    {
        "id": "COMP-DATA-001",
        "name": "Sensitive Data in CloudWatch Logs",
        "cwe": "CWE-532",
        "severity": "MEDIUM",
        "description": "PII, credentials, or compliance evidence logged to CloudWatch",
        "pattern": {
            "source": "user messages, evidence content, JWT tokens",
            "sink": "logger.info/warning/error or print()",
            "missing_sanitizer": "log sanitizer or structured logging with field filtering"
        },
        "detection_query": """
            Find paths where:
            1. Variables containing user PII, tokens, or evidence are in scope
            2. They are passed to logging functions
            3. Without masking/redaction
        """
    },
    {
        "id": "COMP-SSRF-001",
        "name": "SSRF via Agent Configuration Endpoints",
        "cwe": "CWE-918",
        "severity": "MEDIUM",
        "description": "User-controlled URLs in agent config reach external HTTP calls",
        "pattern": {
            "source": "AGENTCORE_GATEWAY_ENDPOINT or similar from env/config",
            "sink": "HTTP request (requests.get, urllib, boto3 endpoint override)",
            "missing_sanitizer": "URL allowlist or domain validation"
        },
        "detection_query": """
            Find paths where:
            1. An endpoint URL is constructed or configured
            2. Used to make an HTTP request
            3. Any component of the URL could be influenced by user input

            Note: In this codebase, most endpoints come from env vars (deploy-time).
            Focus on cases where request body data influences URL construction.
        """
    },
]


# =============================================================================
# SKILL 3: CoT Templates (Codebase-Specific)
# =============================================================================

TAINT_COT_TEMPLATE = """Analyze this code path for {cwe_id}: {cwe_name}.

{cwe_definition}

CODEBASE CONTEXT:
This is a multi-tenant serverless compliance platform (AWS Lambda + DynamoDB + S3).
- Entry points are Lambda handlers receiving API Gateway events
- Authentication is via Cognito JWT (validated by a Lambda authorizer)
- Authorization is RBAC with scoped access for compliance_managers
- Tenant isolation relies on DynamoDB partition keys (pk: TENANT#{{tenant_id}})
- S3 keys are prefixed with customer_id
- LangGraph routes user messages through an agent graph to various tools

CRITICAL INVARIANT: tenant_id used for data access MUST come from the validated
JWT context (event['requestContext']['authorizer']['tenant_id']), never from the
request body.

CODE CONTEXT (CPG Slice):
{cpg_slice_code}

DATA FLOW GRAPH:
{cpg_slice_graph}

---

STEP 1 — IDENTIFY: What untrusted input enters this path?
- Is it from event['body'] (user-controlled)?
- Is it from event['requestContext']['authorizer'] (validated by authorizer)?
- Is it from DynamoDB (previously stored user data)?
- Is it from the LangGraph state (user messages)?

STEP 2 — TRACE: Follow the data through each transformation.
For each step: (a) variable name, (b) operation, (c) taint preserved/removed.
Pay special attention to:
- Where tenant_id/customer_id values originate
- Whether S3 keys or DynamoDB keys are constructed from user input
- Whether permission checks (check_permission) gate the path

STEP 3 — ASSESS: Is there a sanitizer on this path?
- Pydantic model validation?
- Permission check (check_permission)?
- Tenant ID verification against auth context?
- DynamoDB ExpressionAttributeValues (parameterized)?
- Path normalization for S3 keys?

STEP 4 — CONCLUDE: Does tainted data reach the sink unsanitized?
- Can an attacker access another tenant's data?
- Can an attacker elevate their role/permissions?
- Can an attacker execute unauthorized tools?
- Can an attacker read/write S3 objects outside their tenant prefix?

STEP 5 — VERIFY: Challenge your reasoning:
- Does the Lambda authorizer validate the JWT correctly?
- Does the API Gateway enforce the authorizer on this route?
- Is there a CDK-level resource policy that limits access?
- Could the DynamoDB partition scheme inherently prevent cross-tenant access?
- Is this path only reachable with a valid, authenticated request?

STEP 6 — VERDICT:
{{ VULNERABLE | SAFE | UNCERTAIN }}
Confidence: {{ HIGH | MEDIUM | LOW }}
If VULNERABLE: describe the cross-tenant or privilege escalation scenario."""


SPEC_INFERENCE_PROMPT = """Analyze this compliance platform codebase to identify
additional sources, sinks, and sanitizers beyond the baseline definitions.

PROJECT CONTEXT:
- Multi-tenant serverless compliance platform on AWS
- Lambda handlers as entry points (API Gateway events)
- LangGraph agent with tool routing (controls, evidence, audit, evaluation)
- Cognito authentication + custom Lambda authorizer
- DynamoDB for state/sessions, S3 for evidence/artifacts
- Bedrock for AI evaluation

IMPORTS AND PATTERNS:
{imports}

FUNCTION SIGNATURES:
{signatures}

FOCUS AREAS:
1. LangGraph tool functions that handle user data
2. Custom middleware or decorators that perform validation
3. DynamoDB access patterns that might miss tenant isolation
4. S3 key construction functions
5. Any function that bridges the auth context to data access

Identify:
- Sources: Functions where external/user data enters (beyond standard Lambda event)
- Sinks: Functions performing security-sensitive operations specific to this platform
- Sanitizers: Functions that validate/gate access (beyond standard permission checks)
- Propagators: Functions that pass tenant context or user data through layers

Output as JSON with confidence levels."""


# =============================================================================
# SKILL 4: Path Prioritization Rules (Compliance-Specific)
# =============================================================================

PATH_PRIORITY_RULES = {
    "critical_paths": [
        "Any path from event['body'] to DynamoDB key construction",
        "Any path from event['body'] to S3 key construction",
        "Any path where customer_id/tenant_id from body is used for data access",
        "Any path from user input to Cognito attribute setting",
        "Any path from LangGraph state to tool execution without permission check",
    ],
    "high_paths": [
        "Any path where presigned URL key is user-influenced",
        "Any path from user messages to Bedrock prompt (prompt injection)",
        "Any path where role/permission data flows without validation",
        "Any path from DynamoDB result to HTTP response (data leakage)",
    ],
    "medium_paths": [
        "Any path from user data to logging functions",
        "Any path where session state carries unvalidated data between requests",
        "Any path where error messages might expose internal structure",
    ],
}


# =============================================================================
# SKILL 5: Framework-Specific Knowledge (LangGraph + boto3)
# =============================================================================

FRAMEWORK_KNOWLEDGE = {
    "langgraph": {
        "state_propagation": "LangGraph state flows between nodes. User messages in state['messages'] "
                            "carry through the entire graph. Any node can read them.",
        "tool_routing": "The router node classifies intent and routes to tool nodes. "
                       "If permission checking happens AFTER routing, an attacker might "
                       "trigger a tool node before permissions are verified.",
        "security_pattern": "Permission check should happen BEFORE tool execution, not after. "
                          "Check: does the graph have a permission-check node that gates "
                          "all tool-executing nodes?",
    },
    "boto3_dynamodb": {
        "safe_patterns": [
            "table.query(KeyConditionExpression=Key('pk').eq(value), ExpressionAttributeValues={...})",
            "table.get_item(Key={'pk': value, 'sk': value})",
        ],
        "unsafe_patterns": [
            "table.scan(FilterExpression=f'contains(pk, {user_input})')",
            "table.query(KeyConditionExpression=f'pk = {user_input}')",
        ],
        "tenant_isolation": "Safe pattern: pk always starts with TENANT#{tenant_id} where "
                          "tenant_id comes from auth context, not request body.",
    },
    "boto3_s3": {
        "safe_patterns": [
            "key = f'{tenant_id}/{uuid4()}/{filename}' where tenant_id from auth context",
            "generate_presigned_url with key validated against tenant prefix",
        ],
        "unsafe_patterns": [
            "key = f'{customer_id}/{filename}' where customer_id from request body",
            "key with '../' not stripped",
        ],
    },
    "cognito": {
        "privilege_escalation_risk": "custom:role attribute set at signup from user request. "
                                   "If not validated against invitation/approval flow, "
                                   "user could self-assign admin role.",
        "safe_pattern": "Role assignment only via admin_update_user_attributes called "
                       "by an admin user, not during self-signup.",
    },
}
