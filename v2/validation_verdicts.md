# Validation Phase — Adversarial Analysis of WARNING Findings

## Persona: Security Skeptic

For each WARNING finding, I argue why it might NOT be exploitable.

---

## Finding 4: presigned-url-user-filename — handler.py:113

**Semgrep found:** `body.get("filename")` → `s3.generate_presigned_url()`

**ARGUING SAFE:**

Checking handler.py context:
- Line 104: `customer_id = body.get("customer_id", "unknown")` — customer_id FROM BODY
- Line 107: `filename = body.get("filename", "file")`
- Line 108: `key = f"{customer_id}/{framework}/{control_id}/{filename}"`
- Line 113: `presigned_url = s3.generate_presigned_url('put_object', Params=...Key=key...)`

The key is `{customer_id}/{framework}/{control_id}/{filename}`.

**Counter-argument attempt:** "S3 keys are flat — `../` doesn't traverse."

TRUE. S3 treats keys as opaque strings. `tenant-A/../../tenant-B/file.pdf` is literally stored as that string — it does NOT resolve to `tenant-B/file.pdf`. So path traversal in the traditional sense doesn't work.

**BUT:** The `customer_id` comes from body (not auth context). So the REAL vulnerability here isn't path traversal — it's the SAME cross-tenant issue as Finding 1-3. The filename is a red herring. The customer_id in the S3 key prefix is the problem.

**VERDICT: CONFIRMED (but reclassified)**
- Not a path traversal (CWE-22) — S3 is flat
- IS a cross-tenant issue (CWE-639) — customer_id from body controls the S3 prefix
- Severity: **HIGH** (write to any tenant's S3 prefix)
- This is actually a duplicate of the cross-tenant findings, manifesting in S3 instead of DynamoDB

---

## Finding 5: presigned-url-user-filename — data_handler.py:174

**Semgrep found:** `body.get("filename")` → `s3_client.generate_presigned_url()`

**ARGUING SAFE:**

Checking data_handler.py context:
- Line 30: `tenant_id = rc.get('authorizer', {}).get('tenant_id', '')` — **FROM AUTH CONTEXT**
- Line 171: `s3_key = f'{tenant_id}/{framework}/{control_id}/{filename}'`
- Line 174: `upload_url = s3_client.generate_presigned_url('put_object', Params={'Key': s3_key})`

The S3 key prefix is `{tenant_id}/` where `tenant_id` comes from the AUTHORIZER (line 30). Even if filename contains malicious content, the tenant prefix is enforced from JWT.

**Counter-argument:** "S3 keys are flat. tenant_id from auth context. Even if filename is `../../other/file`, the actual stored key is `tenant-A/../../other/file` — which is just a weird-looking key in tenant-A's conceptual space."

**Additional protection:** This handler has `if not tenant_id: return resp(403, ...)` at line 34.

**VERDICT: DISMISSED**
- tenant_id from auth context (line 30) — enforced
- S3 keys are flat — no real traversal possible
- Filename manipulation only affects key WITHIN the authenticated tenant's prefix
- Severity: **ACCEPTABLE** (no cross-tenant impact, no real traversal)

---

## Finding 6: cognito-create-user-from-body — tenant_management.py:148

**Semgrep found:** `body.get("admin_email")` → `cognito_client.admin_create_user()`

**ARGUING SAFE:**

Context from tool results:
- Auth context in file: **YES** (auth context IS accessed)
- Authorizer: **YES** (requires `platform_admin` role)

Checking tenant_management.py:
- This is the TENANT CREATION endpoint
- Only callable by `platform_admin` role (CDK: `admin_res` with `auth_opts`)
- Creates a NEW tenant (not joining existing)
- The admin_email from body becomes the first user of the new tenant
- tenant_id is generated server-side: `str(uuid.uuid4())`
- Role for created user is hardcoded to `admin` (first user of new tenant — expected)

**Counter-argument:**
- Only platform_admins can reach this endpoint (authorizer + role check)
- tenant_id is UUID (server-generated, not from body)
- This IS the intended flow: platform admin creates tenants for customers
- The email from body is necessary (you need to know WHO to create the account for)

**VERDICT: DISMISSED**
- Endpoint is gated by `platform_admin` role (highest privilege, trusted)
- tenant_id generated server-side (not user-controlled)
- This is working-as-designed (admin creates tenants)
- Severity: **ACCEPTABLE**

---

## Finding 7: cognito-create-user-from-body — user_management.py:124

**Semgrep found:** `body["email"]`, `body.get("role")` → `cognito.admin_create_user()`

**ARGUING SAFE:**

Context from tool results:
- Auth context in file: **YES**
- Authorizer: **YES** (requires `admin` role within tenant)

Checking user_management.py:
- This is the USER INVITATION endpoint (admin invites users to their tenant)
- Line 121: `email, role = body['email'], body.get('role', 'viewer')`
- Role comes from body — admin specifies what role the invited user gets

**Counter-argument attempt:** "Admin can set any role for invited user."

YES — but the admin is already the highest role WITHIN the tenant. They're supposed to be able to assign roles. The RBAC system allows admins to invite with any role ≤ admin.

**However:** Can a `compliance_manager` call this endpoint?
- Tool result: requires `admin` role
- So only admins can invite. compliance_managers/auditors/viewers cannot.

**Is the role validated against allowed roles?**
- Line 121: `role = body.get('role', 'viewer')` — if admin sends `role: "platform_admin"`, does it work?
- Platform_admin is a DIFFERENT role system (org-level, not tenant-level)
- The Cognito custom:role would be set to whatever the admin specifies
- BUT: the authorizer checks this claim against tenant policies, not global privileges

**VERDICT: UNCERTAIN (downgrade to LOW)**
- Admin CAN set any role string for invited users
- If admin sets `role: "platform_admin"` for a user, the authorizer would need to reject it
- This is a tenant-admin privilege issue, not a cross-tenant issue
- Severity: **LOW** (admin is already trusted within tenant, limited blast radius)
- Recommendation: Validate role is in allowed list `['admin', 'compliance_manager', 'auditor', 'viewer']`

---

## Validation Summary

| Finding | Original | Validated | Reason |
|---------|----------|-----------|--------|
| 4. handler.py presigned URL | WARNING (CWE-22) | **HIGH** (reclassified CWE-639) | Not path traversal — customer_id from body controls prefix |
| 5. data_handler.py presigned URL | WARNING (CWE-22) | **DISMISSED** | tenant_id from auth context, S3 flat keys, no cross-tenant |
| 6. tenant_management.py cognito | WARNING (CWE-284) | **DISMISSED** | Platform_admin only, tenant_id server-generated, by-design |
| 7. user_management.py cognito | WARNING (CWE-284) | **LOW** | Admin-only, validate role allowlist recommended |

**FP reduction: 2 of 4 dismissed (50%).** 1 reclassified (higher severity), 1 downgraded.
