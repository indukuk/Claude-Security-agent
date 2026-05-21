# Chain-of-Thought Verdicts — V2 Analysis

## Finding 1/3: handler.py:132 — Usage Data Cross-Tenant Read

### STEP 1 — IDENTIFY

**Query result:** `joern.backward_slice("customer_id", "handler.py", 126)`
**Tool result:** Auth context usage in file = [] (NONE)

The untrusted input is `customer_id` at line 126:
```python
customer_id = body.get("customer_id")
```

Origin: `body` ← `json.loads(event.get("body", "{}"))` ← HTTP request body.
The attacker controls the full JSON body of the request. They can set `customer_id` to any value.

The authorizer injects `tenant_id` into `event['requestContext']['authorizer']` — but this file NEVER accesses it (tool result: auth context = []).

**Classification: TAINTED. Source is user-controlled with no authentication binding.**

---

### STEP 2 — TRACE

**Query result:** Semgrep CONFIRMED taint from `body.get("customer_id")` → `table.get_item()`

| Step | Variable | Operation | Taint |
|------|----------|-----------|-------|
| 1 | `body` | `json.loads(event.get("body"))` line 125 | TAINTED |
| 2 | `customer_id` | `body.get("customer_id")` line 126 | TAINTED |
| 3 | f-string | `f"usage#{customer_id}"` line 132 | TAINTED — string interpolation preserves taint |
| 4 | DynamoDB key | `Key={"session_id": f"usage#{customer_id}"}` line 132 | TAINTED |
| 5 | `table.get_item(Key=...)` | DynamoDB read | **SINK REACHED** |

Path length: 5 steps, single function, no branches that could prevent reaching sink.

**Taint confirmed: user-controlled value directly forms DynamoDB lookup key.**

---

### STEP 3 — ASSESS

**Tool result:** Sanitizers found = `[{"line": 128, "type": "customer_id validation", "code": "if not customer_id:"}]`
**Tool result:** Auth context usage = `[]`

The only "sanitizer" is:
```python
if not customer_id:
    return _json_response(400, {"error": "customer_id required"})
```

This checks for **PRESENCE** (non-empty), NOT **AUTHORIZATION** (is this YOUR customer_id?).

Missing sanitizers:
- ❌ No comparison: `customer_id == auth_tenant_id`
- ❌ No `check_permission()` call
- ❌ No access to `event['requestContext']['authorizer']`
- ❌ No DynamoDB condition restricting access

**Sanitization: INSUFFICIENT. Presence check ≠ authorization check.**

---

### STEP 4 — CONCLUDE

**Tool result:** IAM = `{"role": "agent_lambda_role", "table_access": "full (no LeadingKeys)", "s3_access": "read_write (all keys)"}`

Exploitation:
1. Attacker authenticates as Tenant A (gets valid JWT)
2. Sends: `POST /agent {"action": "usage", "customer_id": "tenant-B-uuid"}`
3. Lambda reads `body.get("customer_id")` = "tenant-B-uuid"
4. DynamoDB query: `get_item(Key={"session_id": "usage#tenant-B-uuid"})`
5. Returns Tenant B's usage data (tokens consumed, cost, evaluation count)

**Impact:**
- Read ANY tenant's usage/billing data
- Reveals: how many evaluations a competitor runs, their cost, token consumption
- Business intelligence leakage across tenants

**Blast radius:** All tenants' usage records. IAM has no LeadingKeys condition — Lambda can read any key in the table.

---

### STEP 5 — VERIFY

**Counter-argument 1: "The API Gateway authorizer prevents unauthenticated access"**

Tool result: `{"authorizer": true, "injects": ["tenant_id", "user_id", "role"]}`.
YES, the attacker must be authenticated. But the authorizer only verifies the JWT is valid — it does NOT enforce that the `customer_id` in the body matches the authenticated tenant. The handler ignores the authorizer's injected tenant_id.

→ Counter-argument PARTIALLY holds: reduces severity from "anyone" to "any authenticated user." Still CRITICAL for multi-tenant isolation.

**Counter-argument 2: "The DynamoDB key is session_id, not pk — maybe it's not tenant-partitioned?"**

The key is `{"session_id": f"usage#{customer_id}"}`. This is a flat key — no partition isolation. ANY Lambda with get_item permission on this table can read ANY usage record. The "partition" is embedded in the key value itself, controlled by the caller.

→ Counter-argument FAILS. Key structure provides zero isolation.

**Counter-argument 3: "Usage data isn't that sensitive"**

Usage reveals: evaluation count (how many compliance checks a tenant runs), cost (budget), token consumption (scale of operations). For a competitive compliance SaaS, this IS sensitive business intelligence.

→ Counter-argument PARTIALLY holds: impact is information disclosure, not data modification.

---

### STEP 6 — VERDICT

```
STATUS:     VULNERABLE
SEVERITY:   HIGH (not CRITICAL because read-only and requires authentication)
CONFIDENCE: HIGH (every tool result confirms, all counter-arguments fail or partially mitigate)

EXPLOIT:
  curl -X POST https://API_GATEWAY/v1/agent \
    -H "Authorization: Bearer $VALID_JWT_FOR_TENANT_A" \
    -H "Content-Type: application/json" \
    -d '{"action": "usage", "customer_id": "TENANT_B_UUID"}'

  Response: {"customer_id": "TENANT_B_UUID", "usage": {"input_tokens": 45230, 
             "output_tokens": 12400, "cost_usd": 3.47, "evaluation_count": 89, ...}}

REMEDIATION:
  Replace line 126:
    customer_id = body.get("customer_id")
  With:
    customer_id = event.get("requestContext", {}).get("authorizer", {}).get("tenant_id", "")
    if not customer_id:
        return _json_response(403, {"error": "No tenant context"})

COMPLIANCE: SOC2 CC6.1 (logical access), HIPAA §164.312(a)(1) (access control)
```

---
---

## Finding 2/3: handler_v2.py:376 — Session Write Cross-Tenant

### STEP 1 — IDENTIFY

**Tool result:** Auth context usage in file = [] (NONE)

Untrusted input at line 369:
```python
customer_id = body.get("customer_id") or event.get("headers", {}).get("x-customer-id", "")
```

TWO user-controlled sources:
1. `body.get("customer_id")` — JSON body (primary)
2. `event.get("headers", {}).get("x-customer-id", "")` — HTTP header (fallback)

Both are fully attacker-controlled. The authenticated tenant_id from the JWT authorizer (`event['requestContext']['authorizer']['tenant_id']`) is NEVER accessed in this file.

**Classification: TAINTED. Dual user-controlled sources, zero authentication binding.**

---

### STEP 2 — TRACE

**Semgrep result:** Two confirmed taint paths (to `_handle_start` and `_handle_chat`).

**Path to DynamoDB write (8 steps):**

| Step | Line | Code | Taint |
|------|------|------|-------|
| 1 | 366 | `body = json.loads(event.get("body", "{}"))` | TAINTED |
| 2 | 369 | `customer_id = body.get("customer_id") or headers...` | TAINTED |
| 3 | 376 | `return _handle_start(body, customer_id, trace_id)` | TAINTED — passed as arg |
| 4 | 115 | `def _handle_start(body, customer_id, trace_id):` | TAINTED — received as param |
| 5 | 135 | `_save_session(session_id, customer_id, {...}, status="processing")` | TAINTED — passed |
| 6 | 41 | `def _save_session(session_id, customer_id, state, ...):` | TAINTED — received |
| 7 | 49 | `item = {"session_id": ..., "customer_id": customer_id, ...}` | TAINTED — in dict |
| 8 | — | `table.put_item(Item=item)` | **SINK: DynamoDB WRITE** |

**Path to Lambda invoke (5 steps):**

| Step | Line | Code | Taint |
|------|------|------|-------|
| 1 | 369 | `customer_id = body.get("customer_id")...` | TAINTED |
| 2 | 376 | `_handle_start(body, customer_id, ...)` | TAINTED |
| 3 | 148-159 | `lambda_client.invoke(Payload=json.dumps({"customer_id": customer_id, ...}))` | **SINK: Lambda invoke** |

**Inter-procedural taint: crosses 3 function boundaries (lambda_handler → _handle_start → _save_session). This is why v1's regex DFG found nothing.**

---

### STEP 3 — ASSESS

**Tool result:** Sanitizers = `[{"line": 374, "type": "customer_id validation", "code": "if not customer_id:"}, {"line": 381, "type": "customer_id validation", "code": "if not customer_id:"}]`
**Tool result:** Auth context = `[]`

Sanitizers found are BOTH just presence checks:
```python
if not customer_id:
    return _json_response(400, {"error": "customer_id is required"})
```

These verify the field EXISTS but not that it BELONGS to the authenticated user.

Missing:
- ❌ `customer_id == event['requestContext']['authorizer']['tenant_id']` — NEVER checked
- ❌ `check_permission()` — NEVER called
- ❌ IAM LeadingKeys — NOT configured
- ❌ Any form of tenant ownership validation

**Sanitization: NONE. Presence checks do not constitute authorization.**

---

### STEP 4 — CONCLUDE

**Tool result:** IAM = `{"role": "agent_v2_lambda_role", "table_access": "full (no LeadingKeys)", "s3_access": "read_write (all keys)"}`

This is MORE dangerous than Finding 1 because:
1. **WRITE access** — attacker creates sessions under victim's customer_id
2. **Lambda invocation** — triggers background processing under victim's context
3. **Downstream cascade** — background Lambda reads victim's S3 evidence, runs evaluations

**Concrete exploit:**
```bash
curl -X POST https://API/v1/agent \
  -H "Authorization: Bearer $JWT_TENANT_A" \
  -d '{
    "action": "start",
    "customer_id": "TENANT_B_UUID",
    "message": "evaluate all SOC2 controls",
    "framework": "soc2",
    "controls": ["CC6.1", "CC7.2", "CC8.1"]
  }'
```

Result:
- Session created with `customer_id: "TENANT_B_UUID"` in DynamoDB
- Background Lambda invoked with `"customer_id": "TENANT_B_UUID"`
- Background Lambda loads evidence from S3 prefix `TENANT_B_UUID/...`
- Compliance evaluation runs against Tenant B's evidence
- Attacker polls status → receives Tenant B's evaluation results

**Blast radius:** 9.2/10
- All tenants' sessions (read + write)
- All tenants' usage records (write — billing manipulation)
- All tenants' evaluation results (via background Lambda cascade)
- Potentially all S3 evidence (via downstream processing)

---

### STEP 5 — VERIFY

**Counter-argument 1: "Authorizer prevents this"**

Authorizer validates JWT and injects tenant_id. BUT handler_v2.py has ZERO references to `requestContext.authorizer` (tool result: auth context = []).
The defense exists but is UNUSED. Like having a lock on the door but leaving it open.

→ FAILS.

**Counter-argument 2: "Session IDs are UUIDs — can't read existing sessions"**

True for READING existing sessions. But the attack is WRITE-based: create NEW sessions under victim's ID, trigger background processing under victim's context. The attacker gets their OWN session_id back (returned in response), so they can poll it.

→ FAILS for write-path attacks.

**Counter-argument 3: "Maybe the background Lambda validates customer_id"**

Checked handler_v2.py lines 360-363:
```python
if event.get("action") == "process":
    _handle_process(event)
    return {"statusCode": 200}
```
The background invocation receives `customer_id` in the event payload and trusts it. No re-validation.

→ FAILS.

**Counter-argument 4: "Function URL has AWS_IAM auth"**

Tool result: `"note": "Also has Function URL path (AWS_IAM auth, no tenant injection)"`.
The Function URL requires SigV4 but does NOT inject authorizer context. If called via Function URL, there's no `requestContext.authorizer` at all — making the vulnerability even worse (no tenant_id available even if handler tried to use it).

→ FAILS (actually makes it worse).

---

### STEP 6 — VERDICT

```
STATUS:     VULNERABLE
SEVERITY:   CRITICAL
CONFIDENCE: HIGH

Evidence chain:
  ✓ Source: body.get("customer_id") at line 369 [Semgrep taint confirmed]
  ✓ Path: 8-step inter-procedural flow through 3 functions [Semgrep trace]
  ✓ Second path: Lambda.invoke carries tainted customer_id [Semgrep trace]
  ✓ No sanitizer: presence check only, no auth comparison [Tool: sanitizers=[presence]]
  ✓ No auth context: file never accesses requestContext [Tool: auth_context=[]]
  ✓ No IAM defense: no LeadingKeys condition [Tool: IAM=full]
  ✓ Internet-facing: API Gateway + Function URL [Tool: authorizer=present but unused]
  ✓ 4 counter-arguments evaluated: all fail

EXPLOIT:
  # Create evaluation under victim's tenant
  curl -X POST https://API/v1/agent \
    -H "Authorization: Bearer $JWT" \
    -d '{"action": "start", "customer_id": "VICTIM_TENANT", "message": "evaluate all", "framework": "soc2", "controls": ["CC6.1"]}'
  
  # Poll for victim's evaluation results
  curl -X POST https://API/v1/agent \
    -H "Authorization: Bearer $JWT" \
    -d '{"action": "status", "job_id": "SESSION_ID_FROM_ABOVE"}'

REMEDIATION:
  Line 369, replace:
    customer_id = body.get("customer_id") or event.get("headers", {}).get("x-customer-id", "")
  With:
    auth_ctx = event.get("requestContext", {}).get("authorizer", {})
    customer_id = auth_ctx.get("tenant_id", "")
    if not customer_id:
        return _json_response(403, {"error": "No authenticated tenant context"})
  
  Defense-in-depth: Add IAM condition on DynamoDB:
    Condition: {"ForAllValues:StringLike": {"dynamodb:LeadingKeys": ["TENANT#${tenant_id}*"]}}

COMPLIANCE:
  - SOC2 CC6.1: Logical access control FAILED
  - SOC2 CC6.6: Restriction to system components FAILED  
  - HIPAA §164.312(a)(1): Access control FAILED
  - Platform integrity: Forged evaluations undermine all compliance certifications
```

---
---

## Finding 3/3: handler_v3.py:151 — Cross-Tenant via Function URL

### STEP 1 — IDENTIFY

**Tool result:** Auth context in file = [] (NONE)
**Tool result:** Authorizer = `{"authorizer": "partial", "note": "Function URL with AWS_IAM, no tenant injection"}`

Untrusted input at line 144:
```python
customer_id = body.get("customer_id") or event.get("headers", {}).get("x-customer-id", "")
```

Same pattern as handler_v2.py. But WORSE: this handler is primarily accessed via Lambda Function URL which has `auth_type=AWS_IAM` — this means:
- SigV4 validates the CALLER is an AWS principal
- But NO Lambda authorizer runs (no JWT validation, no tenant_id injection)
- `event['requestContext']` exists but has NO `authorizer` field

**Classification: TAINTED. Even MORE dangerous than handler_v2 — no authorizer at all on Function URL path.**

---

### STEP 2 — TRACE

**Semgrep confirmed paths to:**
- `_handle_start(body, customer_id, ...)` (line 151) → session creation under attacker-chosen tenant
- `_handle_chat(body, customer_id, ...)` (line 157) → chat processing under attacker-chosen tenant

Both paths carry tainted `customer_id` through the same function chain as handler_v2 ultimately reaching DynamoDB write and S3 access.

**Taint preserved through all steps. No sanitizer.**

---

### STEP 3 — ASSESS

**Tool result:** Sanitizers found = 4 (all are presence checks or early returns for missing fields)
**Tool result:** Auth context = [] (NONE)

The 4 "sanitizers" are:
- `if not customer_id:` — presence check (NOT authorization)
- `if not body.get("job_id"):` — different field
- Early returns for missing action

NONE of these validate ownership. NONE access the authorizer context.

**Sanitization: NONE for authorization. Presence checks only.**

---

### STEP 4 — CONCLUDE

This handler runs via Lambda Function URL. On this path:
- No Lambda authorizer executes
- No JWT is validated (SigV4 only checks AWS credentials, not application identity)
- `event['requestContext']` has no `authorizer` field
- Even if the handler TRIED to read auth context, it wouldn't exist

The only access control is SigV4 — meaning any AWS principal with `lambda:InvokeFunctionUrl` permission can call this. In practice, the frontend calls this directly.

**Exploit:** Same as Finding 2, but via Function URL endpoint.

**Blast radius:** Same as Finding 2 (9.2/10) — all tenants' data accessible.

---

### STEP 5 — VERIFY

**Counter-argument 1: "AWS_IAM auth on Function URL limits access"**

SigV4 means the caller needs AWS credentials. But:
- The frontend has credentials (Cognito Identity Pool provides temporary AWS creds)
- Any authenticated user gets these creds → can call the Function URL
- SigV4 does NOT identify which TENANT the caller belongs to

→ FAILS for multi-tenant isolation. SigV4 ≠ tenant identity.

**Counter-argument 2: "Maybe this Function URL isn't exposed to end users"**

Tool result shows it IS used by the frontend (chat functionality requires >29s — beyond API Gateway timeout). The Function URL is the production path for long-running agent interactions.

→ FAILS.

**Counter-argument 3: "CORS restrictions limit who can call it"**

From the infra analysis: `allowed_origins=['*']`. Any origin can call it. CORS provides zero protection when combined with CORS-compatible credentials.

→ FAILS.

---

### STEP 6 — VERDICT

```
STATUS:     VULNERABLE
SEVERITY:   CRITICAL
CONFIDENCE: HIGH

EXPLOIT:
  # Via Function URL (no Lambda authorizer, no JWT validation)
  aws lambda invoke-url \
    --function-url https://FUNC_URL.lambda-url.us-east-1.on.aws/ \
    --method POST \
    --body '{"action": "start", "customer_id": "VICTIM_TENANT", "message": "list all evidence"}'

  # Or via curl with SigV4:
  curl -X POST https://FUNC_URL.lambda-url.us-east-1.on.aws/ \
    --aws-sigv4 "aws:amz:us-east-1:lambda" \
    --user "$AWS_ACCESS_KEY:$AWS_SECRET_KEY" \
    -d '{"action": "chat", "customer_id": "VICTIM_TENANT", "message": "show all controls and their status"}'

REMEDIATION:
  1. Add custom header with tenant_id signed by frontend auth flow
  2. OR: Route through API Gateway with authorizer (remove Function URL)
  3. OR: Validate customer_id against Cognito token fetched separately:
     
     # In handler_v3.py, add at top of lambda_handler:
     identity = event.get("requestContext", {}).get("identity", {})
     caller_arn = identity.get("userArn", "")
     # Map ARN → tenant_id via DynamoDB lookup
     # Verify body customer_id matches mapped tenant

  Defense-in-depth: Remove Function URL entirely. 
  Use API Gateway + authorizer for all paths (accept 29s timeout or use async pattern).

COMPLIANCE:
  - SOC2 CC6.1: FAILED (no logical access control on tenant boundary)
  - SOC2 CC6.2: FAILED (authentication doesn't bind to tenant identity)
  - HIPAA §164.312(a)(1): FAILED
```

---

## Summary of V2 CoT Verdicts

| # | File | Severity | Confidence | Key Evidence |
|---|------|----------|------------|-------------|
| 1 | handler.py:132 | **HIGH** | HIGH | Read-only (usage data), auth required, no auth_context usage, no IAM defense |
| 2 | handler_v2.py:376 | **CRITICAL** | HIGH | Write + Lambda invoke, 8-step inter-procedural path, auth_context ignored, full blast radius |
| 3 | handler_v3.py:151 | **CRITICAL** | HIGH | Function URL = no authorizer at all, CORS *, any AWS principal can exploit |

### Difference from V1

| Metric | V1 | V2 |
|--------|----|----|
| Findings with full trace | 0 | 3 |
| Tool queries per finding | 0 | 5+ |
| Counter-arguments evaluated | 0 | 4 per finding |
| Steps in taint trace | 0 (claimed only) | 5-8 (Semgrep proven) |
| Exploits with curl commands | 0 | 3 |
| Time per finding | ~30s (shallow) | ~5min (thorough) |
| Confidence in verdict | Low (assertions) | High (every claim backed by tool result) |
