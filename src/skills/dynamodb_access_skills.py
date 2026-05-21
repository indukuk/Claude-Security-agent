from __future__ import annotations

"""
DynamoDB Access Pattern Security Skills
=========================================
Exhaustive map of DynamoDB access patterns in the compliance codebase.
The #1 vulnerability class for this multi-tenant platform is cross-tenant
data access via incorrect tenant_id sourcing.

Every DynamoDB call is classified as:
- SAFE: tenant_id comes from auth context (JWT-validated)
- UNSAFE: tenant_id comes from request body (user-controlled)
- NEEDS_REVIEW: tenant_id source is ambiguous or conditional
"""


# =============================================================================
# SKILL 1: DynamoDB Table Schema (Security-Relevant)
# =============================================================================

DYNAMODB_SCHEMA = {
    "sessions_table": {
        "description": "Agent conversation sessions and usage tracking",
        "pk_pattern": "SESSION#{customer_id} | usage#{customer_id}",
        "sk_pattern": "ID#{session_id} | METADATA",
        "contains": "Conversation history, evaluation results, artifacts, usage metrics",
        "sensitivity": "HIGH — contains compliance evaluation data across all tenants",
        "tenant_isolation_mechanism": "pk prefix with customer_id",
        "risk": "If customer_id in pk comes from request body instead of auth context, "
               "any user can read/write any tenant's sessions.",
    },
    "tenants_table": {
        "description": "Tenant metadata and configuration",
        "pk_pattern": "TENANT#{tenant_id}",
        "sk_pattern": "METADATA | USER#{user_id}",
        "contains": "Tenant settings, framework selections, plan tier",
        "sensitivity": "MEDIUM — tenant configuration, no PII directly",
        "tenant_isolation_mechanism": "pk prefix with tenant_id",
    },
    "policies_table": {
        "description": "RBAC policy templates and tenant-specific policies",
        "pk_pattern": "TENANT#{tenant_id} | SYSTEM#defaults",
        "sk_pattern": "ROLE_TEMPLATE#{role} | USER#{user_id}",
        "contains": "Permission matrices, scope rules, resource assignments",
        "sensitivity": "HIGH — controls who can do what",
        "risk": "If attacker can write to this table, they can grant themselves permissions.",
    },
    "user_tenants_table": {
        "description": "User-to-tenant membership mapping",
        "pk_pattern": "USER#{user_id}",
        "sk_pattern": "TENANT#{tenant_id}",
        "contains": "Role, status, invitation metadata",
        "sensitivity": "MEDIUM — reveals org structure",
    },
}


# =============================================================================
# SKILL 2: Access Pattern Classification
# =============================================================================

ACCESS_PATTERNS = [
    # ---- SESSIONS TABLE ----
    {
        "file": "src/agent/handler_v2.py",
        "function": "lambda_handler (POST /chat)",
        "operation": "get_item",
        "key_construction": "pk=f'SESSION#{customer_id}', sk=f'ID#{session_id}'",
        "tenant_id_source": "NEEDS_REVIEW",
        "detail": "customer_id extracted from body OR headers (X-Customer-Id). "
                 "If from headers, it may not be validated against auth context.",
        "line_hint": "Look for: customer_id = body.get('customer_id') or event.get('headers', {}).get('x-customer-id')",
        "risk_score": 0.8,
    },
    {
        "file": "src/agent/handler_v2.py",
        "function": "lambda_handler (POST /chat)",
        "operation": "put_item",
        "key_construction": "pk=f'SESSION#{customer_id}', sk=f'ID#{session_id}'",
        "tenant_id_source": "NEEDS_REVIEW",
        "detail": "Same customer_id as the read — but writing session state. "
                 "If customer_id is user-controlled, attacker can create sessions "
                 "in another tenant's namespace.",
        "risk_score": 0.9,
    },
    {
        "file": "src/agent/handler_v2.py",
        "function": "POST /usage",
        "operation": "update_item",
        "key_construction": "pk=f'usage#{customer_id}'",
        "tenant_id_source": "NEEDS_REVIEW",
        "detail": "Usage tracking. If customer_id from body, attacker could "
                 "inflate another tenant's usage (billing manipulation).",
        "risk_score": 0.6,
    },

    # ---- AUTH HANDLER ----
    {
        "file": "src/auth/auth_handler.py",
        "function": "signup",
        "operation": "put_item (tenants_table)",
        "key_construction": "pk=f'TENANT#{tenant_id}'",
        "tenant_id_source": "SAFE",
        "detail": "tenant_id generated server-side (uuid4) during signup. "
                 "Not user-controlled.",
        "risk_score": 0.0,
    },
    {
        "file": "src/auth/auth_handler.py",
        "function": "signup",
        "operation": "put_item (policies_table)",
        "key_construction": "pk=f'TENANT#{tenant_id}', sk=f'ROLE_TEMPLATE#{role}'",
        "tenant_id_source": "SAFE",
        "detail": "Copies system default role templates to new tenant. "
                 "tenant_id from server-generated UUID. Roles from SYSTEM#defaults (not user input).",
        "risk_score": 0.0,
    },

    # ---- AUTHORIZER ----
    {
        "file": "src/auth/authorizer.py",
        "function": "get_user_permissions",
        "operation": "get_item (policies_table)",
        "key_construction": "pk=f'TENANT#{tenant_id}#USER#{user_id}'",
        "tenant_id_source": "SAFE",
        "detail": "tenant_id extracted from JWT custom:tenant_id claim. "
                 "JWT is cryptographically signed — cannot be modified.",
        "risk_score": 0.0,
    },
    {
        "file": "src/auth/authorizer.py",
        "function": "get_scope_rules",
        "operation": "query (policies_table)",
        "key_construction": "pk begins_with TENANT#{tenant_id}",
        "tenant_id_source": "SAFE",
        "detail": "tenant_id from JWT claims. Scope rules retrieved for authenticated tenant only.",
        "risk_score": 0.0,
    },

    # ---- DATA HANDLER ----
    {
        "file": "src/auth/data_handler.py",
        "function": "handle_evidence_read",
        "operation": "query",
        "key_construction": "pk=f'TENANT#{tenant_id}#EVIDENCE'",
        "tenant_id_source": "NEEDS_REVIEW",
        "detail": "Check: does tenant_id come from event['requestContext']['authorizer']['tenant_id'] "
                 "or from request body/path?",
        "risk_score": 0.7,
    },
    {
        "file": "src/auth/data_handler.py",
        "function": "handle_evidence_write",
        "operation": "put_item",
        "key_construction": "pk=f'TENANT#{tenant_id}#EVIDENCE', sk=evidence_id",
        "tenant_id_source": "NEEDS_REVIEW",
        "detail": "Writing evidence. If tenant_id from body, attacker plants evidence "
                 "in another tenant's namespace.",
        "risk_score": 0.9,
    },
    {
        "file": "src/auth/data_handler.py",
        "function": "handle_audit_read",
        "operation": "query",
        "key_construction": "pk=f'TENANT#{tenant_id}#AUDIT'",
        "tenant_id_source": "NEEDS_REVIEW",
        "detail": "Audit log access. Cross-tenant audit log read would be a compliance violation.",
        "risk_score": 0.8,
    },

    # ---- AGENT GRAPH NODES ----
    {
        "file": "src/agent/graph.py",
        "function": "storage_node",
        "operation": "put_item (sessions_table)",
        "key_construction": "pk from state['customer_id']",
        "tenant_id_source": "NEEDS_REVIEW",
        "detail": "The storage node persists evaluation results. "
                 "state['customer_id'] was set at request entry. "
                 "Check: was it set from auth context or from request body?",
        "risk_score": 0.7,
    },
    {
        "file": "src/agent/graph.py",
        "function": "query_node",
        "operation": "query (sessions_table)",
        "key_construction": "pk from state['customer_id']",
        "tenant_id_source": "NEEDS_REVIEW",
        "detail": "The query node retrieves historical data. "
                 "Same question: where does state['customer_id'] originate?",
        "risk_score": 0.7,
    },
]


# =============================================================================
# SKILL 3: Automated Audit Query
# =============================================================================

AUDIT_QUERIES = {
    "find_all_dynamodb_calls": """
        Search for these patterns across all .py files in src/:
        - table.get_item(
        - table.put_item(
        - table.update_item(
        - table.query(
        - table.scan(
        - table.delete_item(
        - dynamodb_client.get_item(
        - dynamodb_client.put_item(
        - dynamodb_client.query(

        For each: trace backward to find where the Key/pk/sk values originate.
    """,

    "classify_tenant_source": """
        For each DynamoDB call that includes a tenant/customer ID in its key:

        1. Trace the variable backward:
           - If it reaches event['requestContext']['authorizer']['tenant_id'] → SAFE
           - If it reaches event['body'] or json.loads(body) → UNSAFE
           - If it reaches event['headers'] → NEEDS_REVIEW (check which header)
           - If it reaches state['customer_id'] → trace where state was initialized

        2. Check for validation:
           - Is there a comparison: body_id == auth_id before the DB call?
           - If yes and it returns 403 on mismatch → SAFE
           - If comparison exists but doesn't block → UNSAFE (validation without enforcement)
    """,

    "find_scans": """
        DynamoDB scan() is especially dangerous in multi-tenant:
        - Scan reads ALL items in the table (no partition key filter)
        - If FilterExpression is used, it's applied AFTER reading (still scans all data)
        - For tenant isolation: scans should NEVER be used on shared tables
        - Exception: admin operations with strict access control

        Find: table.scan( or dynamodb_client.scan(
        Classify: does FilterExpression enforce tenant_id?
        Risk: Even with filter, the Lambda IAM role could read cross-tenant data.
    """,
}


# =============================================================================
# SKILL 4: DynamoDB-Specific CoT Addition
# =============================================================================

DYNAMODB_COT_ADDITION = """
ADDITIONAL STEP FOR DYNAMODB ACCESS:

For every DynamoDB operation in this path, verify:

A) KEY CONSTRUCTION:
   - Where does the partition key (pk) value come from?
   - If pk contains a tenant/customer ID: is it from auth context or user input?
   - Could an attacker influence the pk to access another tenant's partition?

B) TENANT ISOLATION AT IAM LEVEL:
   - Does the Lambda's IAM policy include a dynamodb:LeadingKeys condition?
   - If NO: application-level check is the ONLY barrier (single point of failure)
   - If YES: even if application bug exists, IAM prevents cross-tenant access

C) OPERATION TYPE MATTERS:
   - get_item: reads one item — attacker needs exact pk+sk (lower risk if sk is UUID)
   - query: reads all items in a partition — attacker with wrong pk reads entire tenant
   - scan: reads ENTIRE TABLE — never acceptable in multi-tenant without extreme caution
   - put_item: writes to any partition — attacker plants data in other tenant's space
   - delete_item: removes data from any partition — attacker destroys other tenant's data

D) EXPRESSION ATTRIBUTES (injection prevention):
   - Are ExpressionAttributeValues used? (parameterized = safe from injection)
   - Or are f-strings used in expressions? (string interpolation = injection risk)
"""
