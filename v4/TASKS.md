# V4 Tasks — Deep Analysis Security Scanner

Goal: Close the quality gap with AWS Security Agent. V3 produces breadth (135 candidates in 3.6s)
but shallow evidence. V4 produces depth — evidence walks, differential analysis, missing-control
detection, and attack chain synthesis. Optimize for analyst-actionable output, not speed.

## Architecture Overview

V4 builds on V3's three-stage pipeline but replaces the shallow Stage 2 (debate) and Stage 3 (template proofs)
with deep analysis engines. The key additions:

```
V3: Generator → Debate (prompts only) → Template Exploits
V4: Generator → Evidence Walker → Differential Analyzer → Absence Detector → Chain Synthesizer → Report
```

Each new component operates on the CPG and finding list, enriching findings with context before final output.

---

## Task 1: Evidence Walk Generator

**Problem**: V3 produces `"evidence": "requires login"`. AWS SA produces 10-step source-to-sink traces
with semantic annotations at each hop.

**Approach**: BFS from source to sink on CPG, then compress and annotate each step.

**Implementation**:

1. `v4/analysis/evidence_walker.py` — Core engine:
   - Input: a finding (file, line, category) + the CPG
   - BFS/shortest-path from the source node to the sink node on CPG edges
   - For each node on the path:
     - Read the source line from disk
     - Classify the step: `entry_point | assignment | call_boundary | sink | missing_check`
     - Extract the tainted variable name at that point
     - Annotate security context (what the variable contains, trust boundary crossings)
   - Compress: merge consecutive same-function nodes without branching into one step
   - Target: 5-9 steps per walk (collapse paths longer than 9)

2. `v4/analysis/step_annotator.py` — Semantic annotation per step:
   - Entry points: extract HTTP method, route, auth status from handler signature
   - Assignments: "attacker-controlled `X` assigned from `body.get("X")`"
   - Call boundaries: "passes tainted value `X` to `function_name()`"
   - Sinks: "reaches `operation` without `expected_guard`"
   - Missing checks: "no sanitizer/guard between here and sink" (negative evidence)

3. Cross-file trace handling:
   - When path crosses function boundary, emit a call-step showing argument mapping
   - Use CALL edges in CPG to resolve parameter binding across files
   - Track which module/function owns each step for display grouping

4. Output format per finding:
   ```
   Entry: POST /v2 {action: "status", job_id: "<any-uuid>"} (no auth at API GW)
   → lambda_handler (handler_v2.py:222)
   → _handle_status(body) (line 232) — tainted job_id passed
   → _load_session(job_id) (line 137) — no tenant filter
   → table.get_item(Key={"session_id": job_id}) (line 38) — DynamoDB query with user-controlled key
     ✗ MISSING: ownership check (session.customer_id != requester.tenant_id)
   → Returns evaluation JSON (lines 141-156) — all tenant data exposed
   ```

**Acceptance criteria**: For the cross-tenant finding in the compliance repo, the walker produces a
trace equivalent in detail to AWS SA Finding 6's evidence section.

---

## Task 2: Differential Path Analyzer

**Problem**: V3 cannot detect "agent_proxy bypasses permission controls that agent_chat enforces"
(AWS SA Finding 4). This requires comparing two code paths to the same operation and identifying
missing guards on one path.

**Approach**: Sink-equivalence clustering + guard-set differencing.

**Implementation**:

1. `v4/analysis/differential_analyzer.py` — Core engine:
   - **Sink clustering**: Group all CPG paths by terminal sink's semantic identity
     - Normalize sink names: strip module aliases, resolve imports to canonical form
     - Key = normalized operation name (`dynamodb.put_item`, `s3.put_object`, `_call_auth_api`)
   - **Guard-set extraction**: For each path from handler entry to sink:
     - Collect all gate/sanitizer nodes on or dominating the path
     - Classify guards: `{auth_check, input_validation, role_check, approval_workflow, sanitization, rate_limit}`
     - Use `nx.immediate_dominators()` to identify guards that MUST be passed
   - **Differential report**: For each cluster with 2+ paths:
     - Compute `missing_guards = stronger_path.guards - weaker_path.guards`
     - Rank by: severity of unguarded sink × number of missing guards × internet-reachability
   - **Output**: "Path A (agent_chat) has {check_permission, check_approval, _safe_id}; Path B (agent_proxy) has {}; MISSING: all 3 guards"

2. `v4/analysis/guard_classifier.py` — Pattern-based guard classification:
   - Auth check patterns: `check_permission`, `verify_token`, `authorizer`, `@requires_auth`
   - Input validation: `sanitize`, `validate`, `_safe_id`, `.replace("/", "_")`, regex patterns
   - Approval workflow: `check_approval`, `confirm`, `require_confirmation`
   - Role check: `role in`, `role ==`, `WRITE_ROLES`, `ADMIN_ROLES`
   - Rate limiting: `throttle`, `rate_limit`, `token_bucket`

3. CPG enhancements needed:
   - New edge type: `cross_module_equiv` linking semantically equivalent sinks across files
   - Add `handler_entry` role for top-level Lambda handlers / API route functions
   - Tag each handler with its authentication context from infra (authorizer attached? API key required?)

**Acceptance criteria**: Detects the agent_proxy vs agent_chat inconsistency (3 missing guards)
and the data_handler vs handler filename sanitization inconsistency.

---

## Task 3: Missing-Functionality Detector (Absence Analysis)

**Problem**: V3 cannot detect "no audit logging for CRUD" or "no ownership verification after
loading a record" — things that SHOULD exist but don't.

**Approach**: Specification-driven must-precede checks + statistical pattern mining.

**Implementation**:

1. `v4/analysis/absence_detector.py` — Specification engine:
   - Define must-guard specs as declarative rules:
     ```python
     MustGuard(sink="dynamodb.put_item", guard="audit_log", scope="same_handler")
     MustGuard(sink="dynamodb.get_item", guard="ownership_check", between=("get_item", "return"))
     MustGuard(sink="dynamodb.delete_item", guard="audit_log", scope="same_handler")
     MustGuard(sink="dynamodb.delete_item", guard="role_check", scope="before_sink")
     MustGuard(entry="auth_endpoint", guard="rate_limiter", scope="infra_or_code")
     MustGuard(resource="secret", guard="rotation_config", scope="infra")
     ```
   - For each spec, traverse CPG paths from handler entries to matching sinks
   - Check guard presence using pattern matching on intermediate nodes
   - Report: "Handler `_handle_delete` reaches `table.delete_item` without `audit_log` on any path"

2. `v4/analysis/specs/` — Specification files (YAML):
   - `audit_logging.yaml` — which operations require audit trails
   - `ownership_verification.yaml` — which data loads require tenant/user ownership checks
   - `rate_limiting.yaml` — which endpoints need throttling
   - `input_sanitization.yaml` — which user inputs need validation before specific sinks
   - `credential_hygiene.yaml` — secrets need rotation, keys need scoping

3. `v4/analysis/pattern_miner.py` — Statistical pattern learning:
   - For each sink type, collect all reaching paths in the CPG
   - Extract "common predecessors" (functions/checks present on >70% of paths)
   - Flag paths missing common predecessors as likely bugs
   - Inspired by Engler et al.'s "Bugs as Deviant Behavior" (SOSP 2001)
   - Example: if 8/10 calls to `table.get_item` are preceded by `_verify_tenant()`, the 2 without are flagged

4. Cross-boundary checks (infra + app):
   - Missing rate limiting: check API Gateway config for throttling settings
   - Missing rotation: check Secrets Manager resources for `rotation_schedule`
   - Missing encryption: check DynamoDB tables for SSE configuration
   - Missing auth: check API Gateway routes for authorizer attachment (already partially done in V3)

**Acceptance criteria**: Detects missing audit logging on data_handler CRUD operations,
missing ownership verification on handler_v2 status polling, and missing rate limiting on auth endpoints.

---

## Task 4: Attack Chain Synthesizer

**Problem**: V3's compound scanner uses hardcoded pattern matching (V2 correlator) and produced
zero results on the last run. AWS SA connects individual findings into multi-step exploit narratives.

**Approach**: Model findings as nodes with preconditions/postconditions, build a composition graph,
find maximal-impact paths.

**Implementation**:

1. `v4/analysis/chain_synthesizer.py` — Core engine:
   - **Capability vocabulary** (finite, enumerable):
     ```
     unauthenticated_access:{endpoint}
     authenticated_access:{endpoint}
     knows:{data_type}  (session_id, tenant_id, api_key)
     admin_role
     write_access:{resource}
     read_access:{resource}
     cross_origin_request
     iam_role:{role_name}
     ```
   - **Finding annotation**: Map each finding category to pre/postconditions:
     ```python
     CAPABILITY_MAP = {
         "missing_auth": ({"network_reach"}, {"unauthenticated_access:{endpoint}"}),
         "info_disclosure": ({"access:{endpoint}"}, {"knows:{data_type}"}),
         "missing_authz_check": ({"authenticated_access"}, {"write_access:{resource}"}),
         "self_signup_admin": ({"unauthenticated_access"}, {"admin_role"}),
         "idor": ({"authenticated_access", "knows:{id_type}"}, {"read_access:any_tenant"}),
         "cors_wildcard": (set(), {"cross_origin_request"}),
         "api_key_exposed": (set(), {"authenticated_access"}),
         "log_exposure": ({"access:{endpoint}"}, {"knows:session_id", "knows:tenant_id"}),
     }
     ```
   - **Composition graph**: Build nx.DiGraph where edge A→B exists when `A.postconditions ∩ B.preconditions ≠ ∅`
   - **Chain discovery**: Find all simple paths from entry nodes (low preconditions) to terminal nodes (high-value postconditions), bounded at depth 5
   - **Composite severity**: Escalate when chain crosses auth boundary or reaches cross-tenant data

2. `v4/analysis/chain_narrator.py` — Natural language narrative generation:
   - Template-based: step number, finding title, capability gained at each step
   - Impact sentence: what the full chain achieves that no single finding does
   - Example output:
     ```
     Attack Chain: Unauthenticated Cross-Tenant Data Exfiltration (CRITICAL)
     
     1. [MEDIUM] Observer endpoint unauthenticated → attacker gains: unauthenticated_access:/observer
     2. [MEDIUM] Observer queries CloudWatch logs → attacker gains: knows:session_id
     3. [MEDIUM] Status endpoint has no ownership check → attacker gains: read_access:any_tenant
     
     Combined impact: Unauthenticated attacker discovers session IDs via observer CloudWatch queries,
     then reads any tenant's compliance assessment data via /v2 status polling.
     Individual: MEDIUM+MEDIUM+MEDIUM → Combined: CRITICAL (crosses auth boundary + cross-tenant data access)
     ```

3. Pruning combinatorial explosion:
   - **Scope locality**: Only compose findings sharing an endpoint, resource, or InfraGraph connection
   - **Depth bound**: cutoff=5 on path search
   - **Subsumption**: If chain A is a sub-path of chain B, discard A
   - **Capability monotonicity**: Only follow edges that strictly increase attacker capabilities

**Acceptance criteria**: Synthesizes the observer→session_id→status_polling chain and the
self_signup→admin→wildcard_cors→data_write chain that AWS SA described.

---

## Task 5: Contextual Fix Generator

**Problem**: V3 generates template fixes ("use authorizer context"). AWS SA references existing
secure patterns in the same codebase and provides specific line-number patches.

**Implementation**:

1. `v4/analysis/fix_generator.py` — Context-aware fix generation:
   - **Step 1**: Search the same codebase for "how is this done correctly elsewhere?"
     - For path traversal: grep for `replace("/", "_")`, `sanitize`, `_safe_id` patterns
     - For auth checks: grep for `check_permission`, `verify_tenant`, `ownership_check`
     - For audit: grep for `audit_log`, `log_event` patterns
   - **Step 2**: If a secure pattern exists elsewhere, reference it:
     "Apply the same sanitization used in handler.py:116-117 to data_handler.py:153"
   - **Step 3**: Generate a concrete diff showing the fix at the exact location
   - **Step 4**: For structural fixes (DynamoDB key redesign), provide short-term (ownership check)
     AND long-term (schema change) recommendations

2. `v4/analysis/secure_pattern_finder.py` — Locate existing good patterns:
   - For each finding category, define "known secure patterns" to search for
   - Search the CPG for sanitizer/gate nodes matching those patterns
   - Return file:line references to existing secure implementations

**Acceptance criteria**: Fix for data_handler path traversal references handler.py's existing sanitization.
Fix for missing ownership check references handler.py:141's existing session ownership check.

---

## Task 6: Verified/Unverified Evidence Annotations

**Problem**: AWS SA explicitly separates "Verified" (read from code) from "Could not verify"
(depends on external behavior like deployment config, WAF rules, bucket policies). V3 makes no
such distinction.

**Implementation**:

1. `v4/analysis/confidence_annotator.py`:
   - For each claim in an evidence walk, classify as:
     - **Verified**: code was read and behavior confirmed (variable assignment, function call, missing check)
     - **Assumed**: depends on framework behavior, external service, or runtime config
     - **Could not verify**: requires deployment knowledge (WAF, VPC, bucket policies, API GW config)
   - Heuristic: if the evidence comes from reading a `.py` file → verified.
     If it depends on CDK runtime synthesis → assumed. If it depends on deployed state → could not verify.
   - Output each finding with explicit confidence bounds:
     ```
     Verified: data_handler.py:153 has no sanitization
     Verified: handler.py:116-117 correctly sanitizes (contrast)
     Could not verify: Whether S3 bucket policies restrict key prefixes
     Could not verify: Whether WAF blocks path traversal patterns
     ```

2. Impact on severity:
   - Findings where the full chain is verified → HIGH confidence
   - Findings with one "assumed" link → MEDIUM confidence  
   - Findings with "could not verify" on a mitigating control → note as "exploitable IF..."

---

## Task 7: Report Generator (Analyst-Grade Output)

**Problem**: V3 outputs raw JSON. AWS SA produces a structured 47-page report with executive summary,
methodology, severity distribution, and detailed findings with evidence.

**Implementation**:

1. `v4/report/generator.py` — Multi-format report generation:
   - Markdown report (primary — readable by Claude in conversation)
   - JSON (machine-readable, for CI/CD integration)
   - Per-finding structure:
     ```
     ## Finding N: {title}
     Severity: {severity} | Confidence: {confidence} | Risk Type: {category}
     
     ### Description
     {2-3 paragraph description explaining the vulnerability, its impact, and exploitation}
     
     ### Evidence Walk
     {step-by-step trace from entry to sink}
     
     ### Verified / Could Not Verify
     {explicit confidence annotations}
     
     ### Code Locations
     {file:line — description of what's at that location}
     
     ### Suggested Fix
     {concrete fix with reference to existing secure patterns}
     ```

2. `v4/report/executive_summary.py` — Top-level summary:
   - Finding count by severity
   - Top attack chains
   - Most critical findings (one sentence each)
   - Scope (what was analyzed)

3. Deduplication in output:
   - Group findings by root cause (e.g., 6 cross-tenant findings → 1 finding with 6 affected locations)
   - List affected files/lines under a single finding entry

---

## Task 8: Enhanced CPG Construction

**Problem**: Current CPG builder (regex-based) produces weak cross-file DFG edges.
Evidence walks and differential analysis depend on accurate data flow.

**Implementation**:

1. `v4/cpg/enhanced_builder.py` — Improved CPG construction:
   - **Intra-procedural**: Use tree-sitter AST to get accurate variable assignments, function calls, returns
   - **Inter-procedural**: Build call graph, propagate taint across function boundaries via parameter binding
   - **Framework-aware**: Recognize Lambda handler patterns (event → body → fields), DynamoDB patterns
     (get_item response → Item), API Gateway patterns (authorizer context)
   - **Handler entry classification**: Tag each handler with auth context from matched infra config

2. New node roles:
   - `handler_entry` — top-level Lambda/API handler with auth metadata
   - `trust_boundary` — points where trust level changes (e.g., after authorizer verification)
   - `data_load` — database read operations (important for ownership check detection)

3. New edge types:
   - `param_binding` — tracks which argument maps to which parameter across function calls
   - `return_flow` — tracks data returned from callees back to callers
   - `cross_module_equiv` — links semantically equivalent operations across files

---

## Task 9: JWT/Crypto Pattern Detection

**Problem**: V3 missed "unverified JWT decode" (AWS SA Finding 1) — base64 decoding JWT
without signature verification. Also missed "custom RSA instead of library" (Finding 13).

**Implementation**:

1. New semgrep rules in `v4/rules/crypto_auth.yaml`:
   - `jwt-base64-decode-no-verify`: detect `base64.b64decode` on JWT-shaped strings without
     preceding `jwt.decode()` or signature verification library call
   - `custom-crypto-implementation`: detect manual RSA/signature operations without using
     `cryptography`, `PyJWT`, `python-jose` libraries
   - `jwt-comment-verified-but-not`: detect patterns where comments say "already verified"
     but no verification is visible in the call path

2. New CPG pattern in absence detector:
   - Spec: `MustGuard(sink="base64.b64decode(jwt_payload)", guard="jwt_verify", scope="calling_chain")`
   - Detect: token split by `.`, second element base64 decoded, claims extracted — without
     any call to verification library

---

## Task 10: Frontend Secret Detection

**Problem**: V3's frontend scanner focused exclusively on DOM XSS (innerHTML). Missed API key
hardcoded in client-side JavaScript (AWS SA Finding 9).

**Implementation**:

1. Add to `v4/rules/frontend_secrets.yaml`:
   - Hardcoded API keys: `const API_KEY = "..."`, `x-api-key: "..."` in JS/TS files
   - Embedded credentials: AWS access keys, bearer tokens in client code
   - Unrotated secrets: API keys with no rotation mechanism visible

2. Extend frontend scanner to run both XSS and secret rules against JS/TS directories.

---

## Implementation Order

1. **Task 8** (Enhanced CPG) — foundation for everything else
2. **Task 1** (Evidence Walker) — most impactful quality improvement
3. **Task 3** (Absence Detector) — catches entire category V3 misses
4. **Task 2** (Differential Analyzer) — catches bypass paths
5. **Task 4** (Chain Synthesizer) — composes findings into narratives
6. **Task 9** (JWT/Crypto rules) — quick win, new detection rules
7. **Task 10** (Frontend secrets) — quick win, new detection rules
8. **Task 5** (Contextual Fix Generator) — polish
9. **Task 6** (Confidence Annotations) — polish
10. **Task 7** (Report Generator) — final output format

---

## Success Metric

Run V4 against `/Users/indukuk/compliance` and produce a report that:
- Detects all 15 findings from the AWS SA report (or explains why each missed one is out of scope)
- Provides evidence walks comparable in depth to AWS SA's evidence sections
- Identifies at least 2 attack chains (observer→session_id→data, signup→admin→write)
- Separates verified from unverified evidence
- References existing secure patterns in suggested fixes
- Produces a structured report readable by a security analyst without further investigation
