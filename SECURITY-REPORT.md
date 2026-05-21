# Security Assessment: Lotus AI Compliance Platform

**Date:** 2026-05-14
**Scope:** /Users/indukuk/compliance (full codebase)
**Method:** Graph-based analysis + LLM reasoning (Think & Verify CoT)
**Cost:** $0.00 (deterministic + in-session Claude reasoning)

---

## Executive Summary

Scanned 84 Python files and 5 CDK stacks. Built Code Property Graph with **7,621 nodes** and **10,470 edges**. Identified **78 sources**, **161 sinks**, and **28 sanitizers**. Analyzed 27 AWS resources across 4 CDK stacks with 23 IAM permission edges.

| Severity | Count |
|----------|-------|
| CRITICAL | 2 |
| HIGH | 4 |
| MEDIUM | 7 |
| LOW | 6 |
| **Total** | **19** |

---

## CRITICAL Findings

### CRIT-001: customer_id from request body used for data access (handler_v2.py)

**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)
**Location:** `src/agent/handler_v2.py:369`
**Evidence:**
```python
customer_id = body.get("customer_id") or event.get("headers", {}).get("x-customer-id", "")
```

**Analysis:** The `customer_id` used for session storage and usage tracking comes from the request body OR from the `x-customer-id` header — both are user-controlled. If this ID is used to construct DynamoDB keys (which it is, for session storage and usage tracking), any authenticated user can read/write another tenant's sessions.

**Impact:** Cross-tenant data access. Attacker reads other tenants' compliance evaluations, evidence metadata, and session history.

**Remediation:** Use `tenant_id` from `event['requestContext']['authorizer']['tenant_id']` exclusively. Remove body/header fallback.

---

### CRIT-002: bedrock-agentcore:* grants administrative permissions

**CWE:** CWE-250 (Execution with Unnecessary Privileges)
**Location:** `infra/stacks/compliance_stack.py` (PolicyStatement)
**Evidence:**
```python
actions=['bedrock-agentcore:*'], resources=['*']
```

**Analysis:** Grants ALL bedrock-agentcore actions including `CreateAgent`, `DeleteAgent`, `UpdateAgent`. The Lambda only needs `InvokeAgent`. If the Lambda is compromised (e.g., via prompt injection), attacker can create a rogue agent with a different system prompt, route traffic through it, and exfiltrate data.

**Impact:** Full AgentCore administrative access from a compromised Lambda.

**Remediation:** Scope to `['bedrock-agentcore:InvokeAgent', 'bedrock-agentcore:GetAgent']`.

---

## HIGH Findings

### HIGH-001: handler_v2.py customer_id from x-customer-id header

**CWE:** CWE-639
**Location:** `src/agent/handler_v2.py:369`, `src/agent/handler_v3.py:144`
**Evidence:** Same as CRIT-001 — the header fallback `event.get("headers", {}).get("x-customer-id", "")` allows any request to spoof the tenant context.
**Note:** This pattern exists in handler_v2 AND handler_v3.

---

### HIGH-002: S3 presigned URL filename not sanitized

**CWE:** CWE-22
**Location:** `src/agent/handler.py:107-113`, `src/agent/handler_v2.py` (upload)
**Evidence:**
```python
filename = body.get("filename", "file")
key = f"{customer_id}/{framework}/{control_id}/{filename}"
presigned_url = s3.generate_presigned_url('put_object', Params={'Key': key})
```

**Analysis:** While S3 keys are flat (no true traversal), the `customer_id` in this handler comes from the body (see CRIT-001). Combined with user-controlled filename, framework, and control_id, an attacker can write objects to arbitrary key paths. Cross-tenant because `customer_id` is from body.

**Impact:** Write files to another tenant's S3 prefix. Upload forged compliance evidence.

**Remediation:** (1) customer_id from auth context only, (2) os.path.basename(filename), (3) UUID prefix.

---

### HIGH-003: CloudWatch log retention 7 days (compliance violation)

**CWE:** CWE-778
**Location:** `infra/stacks/compliance_stack.py` (all log groups)
**Evidence:** `log_retention=logs.RetentionDays.ONE_WEEK`

**Analysis:** For a compliance platform (SOC2 CC7.2, HIPAA §164.312(b)), 7-day log retention is insufficient. SOC2 requires audit trail availability for control testing. HIPAA requires 6 years. If a breach occurs and logs expire after 7 days, forensic investigation is impossible.

**Compliance Impact:** Violates SOC2 CC7.2, HIPAA §164.312(b)

**Remediation:** `log_retention=logs.RetentionDays.ONE_YEAR` (minimum).

---

### HIGH-004: No S3 versioning on evidence bucket

**CWE:** CWE-693
**Location:** `infra/stacks/compliance_stack.py` (S3 bucket)
**Evidence:** Evidence bucket created without `versioned=True`.

**Analysis:** Compliance evidence can be overwritten or deleted with no recovery. A compromised Lambda (which has s3:PutObject and s3:DeleteObject) can destroy or forge evidence. There is no audit trail of what the original evidence contained.

**Compliance Impact:** Violates SOC2 CC6.7 (data integrity), HIPAA §164.312(c)(1)

**Remediation:** Enable `versioned=True` on evidence bucket. Consider Object Lock for immutable records.

---

## MEDIUM Findings

### MED-001: S3 buckets missing encryption configuration (3 buckets)
- S3_compliance_frontend_stack_0
- S3_compliance_frontend_stack_1
- S3_compliance_stack_18 (evidence bucket)

### MED-002: S3 buckets without access logging (3 buckets)
No server access logging configured. Cannot audit who accessed evidence files.

### MED-003: data_handler.py presigned URL — filename from body
**Location:** `src/auth/data_handler.py:167-174`
**Analysis:** This instance is SAFE for cross-tenant (tenant_id from auth context at line 30). But filename, framework, and control_id from body allow the user to control the key structure within their own tenant prefix. LOW individual risk but noted for completeness.
**Verdict:** MEDIUM (downgraded from HIGH because tenant_id is from auth context here)

---

## LOW Findings

### LOW-001 through LOW-004: DynamoDB tables using default encryption (4 tables)
AWS-owned key encryption (default). Consider CMK for compliance-regulated data.

### LOW-005: Multiple print() statements logging operational data
Various handlers log to CloudWatch via print(). Content is mostly metadata (paths, counts, errors) not PII. Acceptable with current 7-day retention but should be structured logging.

### LOW-006: API Gateway API key in frontend code
Known architectural choice — API key used for throttling, Cognito tokens for auth. Low risk but disclose this in security documentation.

---

## Findings NOT Confirmed (Dismissed by Validation)

| Pattern | Why Dismissed |
|---------|--------------|
| Bedrock InvokeModel with resource: * | AWS does not support resource-level permissions for Bedrock |
| Textract actions with resource: * | AWS does not support resource-level permissions for Textract |
| DynamoDB grant_read_write in auth stack | Resources are specific table ARNs (not wildcard) — CDK generates scoped policy |
| data_handler.py presigned URL cross-tenant | tenant_id comes from auth context (line 30), NOT body — SAFE |

---

## Cross-Boundary Compound Finding

### COMPOUND-001: customer_id from body + broad S3/DynamoDB IAM = all-tenant blast radius

**Components:**
1. `handler_v2.py` and `handler_v3.py` accept `customer_id` from request body
2. Lambda IAM grants full `s3:*` on evidence bucket (all tenants' prefixes)
3. Lambda IAM grants full `dynamodb:*` on sessions table (all tenants' partitions)
4. No IAM-level LeadingKeys condition restricts access to specific tenant

**Combined Impact:** Attacker sends `{"customer_id": "victim-tenant"}` → Lambda uses this for DynamoDB key → reads/writes victim's sessions. IAM doesn't block because there's no tenant condition at the IAM level.

**Severity:** CRITICAL (cross-tenant data access + no defense-in-depth)

**Remediation:**
1. Remove `customer_id` from request body — use auth context only
2. Add IAM condition `dynamodb:LeadingKeys` restricting to authenticated tenant
3. Add S3 condition restricting key prefix to authenticated tenant

---

## Coverage Summary

```
Python Application:
  Files scanned:              84
  CPG nodes:                  7,621
  CPG edges:                  10,470
  Sources identified:         78
  Sinks identified:           161
  Sanitizers identified:      28
  Taint pairs analyzed:       9 (LLM reasoning)

Infrastructure:
  CDK stacks parsed:          5
  Resources identified:       27
  IAM permissions mapped:     23
  Deterministic checks:       10 findings
  
Validation:
  Findings dismissed (FP):    4
  Findings confirmed:         19
```

---

## Recommended Remediation Priority

| # | Finding | Effort | Impact |
|---|---------|--------|--------|
| 1 | CRIT-001: Remove customer_id from body in handler_v2/v3 | 30 min | Fixes cross-tenant access |
| 2 | CRIT-002: Scope bedrock-agentcore to InvokeAgent only | 5 min | Reduces blast radius |
| 3 | HIGH-004: Enable S3 versioning on evidence bucket | 5 min | Compliance requirement |
| 4 | HIGH-003: Extend log retention to 1 year | 5 min | Compliance requirement |
| 5 | HIGH-002: Sanitize filename + use auth tenant_id for S3 key | 30 min | Prevents evidence forgery |
| 6 | Add IAM LeadingKeys condition | 1 hour | Defense-in-depth for tenant isolation |
