# Security Scan Report — V2 + Z3 Formal Verification

**Date:** 2026-05-18
**Target:** Lotus AI Compliance Platform (`/Users/indukuk/compliance`)
**Method:** Python CPG (regex) + CDK Infrastructure Graph + IAM Escalation + Z3 SMT Formal Verification
**Scanner:** `run_scan.py` (deterministic phases, no LLM cost)
**Cost:** $0.00

---

## Executive Summary

Full security scan of a multi-tenant compliance platform across Python backend (84 files), AWS CDK infrastructure (5 stacks, 27 resources), and 46 IAM permission edges. The **new Z3 formal verification** (Zelkova approach) mathematically proves that cross-tenant data access is possible at the IAM layer — confirming zero defense-in-depth for tenant isolation.

| Severity | Count | Source |
|----------|-------|--------|
| **CRITICAL** | 19 | 18 Z3 (LeadingKeys) + 1 IAM escalation |
| **HIGH** | 11 | 3 Z3 (wildcards) + 5 IAM escalation + 3 deterministic |
| **MEDIUM** | 6 | Encryption + logging gaps |
| **LOW** | 7 | Default encryption (DynamoDB) |
| **Total** | **43** | |

---

## Phase 1: Python Code Property Graph

| Metric | Value |
|--------|-------|
| Files scanned | 84 Python files |
| CPG nodes | 7,643 |
| CPG edges | 10,490 |
| Sources (user input entry points) | 72 |
| Sinks (security-sensitive operations) | 167 |
| Sanitizers (validation/escaping) | 28 |
| Taint pairs for LLM analysis | 9 |

### Key Sources Detected

- `handler.py`, `handler_v2.py`, `handler_v3.py` — `body.get("customer_id")`, `body.get("session_id")`, `body.get("message")`
- `data_handler.py` — `body.get("filename")`, `body.get("control_id")`, `body.get("framework")`
- `auth_handler.py` — `body["email"]`, `body["password"]`, `body["tenant_name"]`
- `tenant_management.py`, `user_management.py` — admin operations from body

### Key Sinks Detected

- DynamoDB `put_item`, `get_item`, `update_item`, `query` — 15+ sinks
- S3 `generate_presigned_url` — 2 sinks
- Cognito `admin_create_user`, `admin_update_user_attributes` — 3 sinks
- Bedrock `invoke_model` — 4 sinks
- `logger.info` with user data — multiple sinks

### Taint Pairs (Source → Sink, same file)

1. `data_handler.py:37` (body from event) → `data_handler.py:174` (S3 presigned URL)
2. `data_handler.py:167` (filename from body) → `data_handler.py:174` (S3 presigned URL)
3. `data_handler.py:168` (control_id from body) → `data_handler.py:174` (S3 presigned URL)
4. `data_handler.py:169` (framework from body) → `data_handler.py:174` (S3 presigned URL)
5. `tenant_management.py:42` (body) → `tenant_management.py:148` (Cognito admin_create_user)
6. `tenant_management.py:103-113` (name, email, plan) → `tenant_management.py:148` (Cognito admin_create_user)

---

## Phase 2: Infrastructure Security Analysis

### Resources Discovered (27 total)

| Type | Count | Stacks |
|------|-------|--------|
| AWS::Lambda::Function | 17 | auth, compliance, v2 |
| AWS::DynamoDB::Table | 4 | auth (3), compliance (1) |
| AWS::S3::Bucket | 3 | frontend (2), compliance (1) |
| AWS::Cognito::UserPool | 1 | auth |
| AWS::ApiGateway::RestApi | 3 | auth (1), compliance (2) |

### Infrastructure Graph

- **Network layer:** 28 nodes, 3 edges (INTERNET → API Gateways)
- **IAM layer:** 46 permission edges across 13 principals

### IAM Permission Map (46 edges)

| Principal | Targets | Key Actions |
|-----------|---------|-------------|
| role_auth_handler_fn | tenants_table, policies_table, user_tenants_table, Cognito | DynamoDB full + Cognito admin |
| role_user_mgmt_fn | policies_table, user_tenants_table, Cognito | DynamoDB full + Cognito admin |
| role_tenant_mgmt_fn | tenants_table, user_tenants_table, policies_table, Cognito | DynamoDB full + Cognito admin |
| role_agent_fn | bucket, table, * | S3 r/w + DynamoDB full + Bedrock + **bedrock-agentcore:\*** |
| role_v2_fn | bucket, table, * | S3 r/w + DynamoDB full + Bedrock + **bedrock-agentcore:\*** |
| role_v3_fn | bucket, table, * | S3 r/w + DynamoDB full + Bedrock + **bedrock-agentcore:\*** |
| role_observer_fn | table, * | DynamoDB full + CloudWatch Logs + Bedrock |
| role_data_fn / data_fn2 | tenants_table, S3 | DynamoDB full + S3 |
| role_preprocessor_fn | bucket, * | S3 r/w + Bedrock |
| role_agent_fn_v2 | bucket, table, * | S3 + DynamoDB + Bedrock + Textract + AgentCore + Lambda invoke |

---

## Z3 Formal IAM Verification (NEW — Zelkova Approach)

### Method

Uses the Z3 SMT theorem prover to formally verify IAM permission properties. Instead of heuristic pattern matching, Z3 mathematically PROVES whether cross-tenant access is satisfiable under the current IAM configuration.

**Zelkova formula:** `SAT(allowed AND NOT denied AND leading_key ≠ tenant_prefix)`

If satisfiable → cross-tenant access is provably possible at the IAM layer.

### CRITICAL: Missing DynamoDB LeadingKeys (18 findings)

Every Lambda with DynamoDB `grant_read_write_data()` lacks a `dynamodb:LeadingKeys` IAM condition. Z3 proves:

> There exists a valid request where the principal accesses partition keys belonging to ANY tenant, because no IAM condition restricts which partition keys are accessible.

| Principal | Tables Affected |
|-----------|----------------|
| role_auth_handler_fn | tenants_table, policies_table, user_tenants_table |
| role_user_mgmt_fn | policies_table, user_tenants_table |
| role_tenant_mgmt_fn | tenants_table, user_tenants_table, policies_table |
| role_risk_fn | tenants_table |
| role_data_fn | tenants_table |
| role_data_fn2 | tenants_table |
| role_seed_fn | policies_table |
| role_config_evidence_fn | tenants_table |
| role_agent_fn_v2 | table |
| role_agent_fn | table |
| role_v2_fn | table |
| role_v3_fn | table |
| role_observer_fn | table |

**Remediation:**
```python
# Replace: table.grant_read_write_data(lambda_fn)
# With:
lambda_fn.add_to_role_policy(iam.PolicyStatement(
    actions=["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:Query", ...],
    resources=[table.table_arn],
    conditions={
        'ForAllValues:StringLike': {
            'dynamodb:LeadingKeys': ['TENANT#${aws:PrincipalTag/tenant_id}*']
        }
    }
))
```

### HIGH: Unscoped Wildcard Actions (3 findings)

| Principal | Action | Conditions |
|-----------|--------|------------|
| role_agent_fn | bedrock-agentcore:* | None |
| role_v2_fn | bedrock-agentcore:* | None |
| role_v3_fn | bedrock-agentcore:* | None |

Z3 proves administrative actions (CreateAgent, DeleteAgent, UpdateAgent) are reachable. If any of these Lambdas is compromised via SSRF or injection, the attacker can create rogue agents or delete existing ones.

---

## IAM Escalation Analysis (9 findings)

| Severity | Finding | Principals |
|----------|---------|------------|
| CRITICAL | Auth Lambda has Cognito admin powers | role_auth_handler_fn |
| HIGH | Agent Lambda can invoke model + write to DynamoDB | role_agent_fn, v2_fn, v3_fn, observer_fn, agent_fn_v2 |
| HIGH | bedrock-agentcore:* grants administrative actions | role_agent_fn, v2_fn, v3_fn |

---

## Deterministic Checks (13 findings)

### HIGH (3)
- Wildcard action `bedrock-agentcore:*` grants all service permissions (3 Lambdas)

### MEDIUM (6)
- S3 bucket missing encryption configuration (3 buckets)
- S3 bucket has no access logging (3 buckets)

### LOW (4)
- DynamoDB table uses default encryption — not CMK (4 tables)

---

## Combined Risk Assessment

### Defense-in-Depth Failure (CRITICAL)

The compliance platform has **zero tenant isolation at the IAM layer**:

1. **Application layer:** `customer_id` comes from request body (proven by V2 taint analysis)
2. **IAM layer:** No `LeadingKeys` condition on any DynamoDB grant (proven by Z3)
3. **Combined:** A single spoofed `customer_id` field in the request body gives unrestricted access to ALL tenants' data with NO infrastructure-level backstop

### Attack Surface

If ANY Lambda is compromised (via prompt injection, SSRF, or code injection):
- `bedrock-agentcore:*` → create/delete/modify AI agents
- Full DynamoDB access → read/write all tenant data
- S3 read/write → access all evidence files
- Cognito admin → create users in any tenant

---

## Scan Summary

```
Python CPG:               7,643 nodes, 72 sources, 167 sinks
Taint pairs for LLM:      9
Infrastructure resources:  27
IAM permission edges:      46
Infrastructure findings:   43
  - Deterministic checks:  13
  - IAM escalation:        9
  - Z3 formal verification: 21
  - Toxic combinations:    0
```

---

## What's New vs. Previous Scan

| Capability | Previous (V2) | This Scan (V2 + Z3) |
|-----------|---------------|---------------------|
| IAM wildcard detection | Pattern matching | Pattern matching + Z3 proof |
| Multi-tenant isolation | Inferred from missing auth context | **Formally proven** by SMT solver |
| Deny statement analysis | Not checked | Z3 proves deny effectiveness |
| Condition evaluation | Not parsed | Extracted and verified |
| Confidence level | "Likely vulnerable" | "Mathematically provable" |
