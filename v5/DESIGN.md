# V5 Design — Expert Security Code Reviewer

## Goal

Produce security analysis output that exceeds AWS Security Agent quality by combining:
- **V4's deterministic foundation** (CPG, Z3, absence detection, differential analysis, chain synthesis)
- **V3's agent architecture** (specialized LLM agents with domain expertise)
- **Zero trust analysis** (blast radius, network isolation, lateral movement)
- **Unlimited reasoning** (no token budgets, no time constraints, extended thinking)

The fundamental principle: **deterministic analysis for recall, LLM reasoning for depth.**

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              V5 PIPELINE                                         │
│                                                                                  │
│   Layer 0: Deterministic Evidence Collection (no LLM)                            │
│   Layer 1: Deep Investigation Agents (LLM — domain experts)                      │
│   Layer 2: Chain-of-Thought Evidence Synthesis (LLM — per finding)               │
│   Layer 3: Adversarial Grounded Debate (LLM — HIGH/CRITICAL only)                │
│   Layer 4: Exploit Proof & Fix Verification (LLM + deterministic)                │
│   Layer 5: Narrative Synthesis (LLM — final report authoring)                    │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Layer 0: Deterministic Evidence Collection

**Purpose:** Build the complete evidence corpus that LLM agents will reason over. 100% recall, zero LLM cost. This is V4 extended with zero trust analysis.

**Runtime:** ~20 seconds
**LLM calls:** 0

### 0A. Code Analysis (from V4)

```
Input: Target repo Python files
Output: Structured evidence package

Components:
├── Enhanced CPG Builder (v4/cpg/enhanced_builder.py)
│   • Tree-sitter AST parsing
│   • Inter-procedural call graph with parameter binding
│   • Framework-aware source/sink/sanitizer/gate classification
│   • Handler detection with auth context from infra
│   • 10K+ nodes, 9K+ edges
│
├── Semgrep Scanner (v2 rules + v4 rules)
│   • Python taint rules (cross-tenant, path traversal, privilege escalation)
│   • Gap coverage rules (session access, info disclosure)
│   • Frontend rules (DOM XSS, innerHTML)
│   • Crypto/auth rules (JWT unsigned decode, custom crypto)
│   • Frontend secrets (hardcoded API keys)
│   Output: 119 raw findings with file:line locations
│
├── Evidence Walker (v4/analysis/evidence_walker.py)
│   • BFS source→sink on CPG
│   • 5-9 step annotated traces
│   • Missing-control annotations
│   • Cross-file trace handling
│   Output: 20+ evidence walks
│
├── Absence Detector (v4/analysis/absence_detector.py)
│   • Must-guard specifications (audit, ownership, role, rate limit, sanitization)
│   • Deviant behavior mining (Engler's "bugs as deviation")
│   Output: ~10 missing-control findings
│
├── Differential Analyzer (v4/analysis/differential_analyzer.py)
│   • Sink-equivalence clustering
│   • Guard-set extraction via dominators
│   • Set subtraction to find bypass paths
│   Output: ~10 inconsistency findings
│
└── Chain Synthesizer (v4/analysis/chain_synthesizer.py)
    • Precondition/postcondition capability graph
    • Composition via graph reachability (depth 5)
    • Composite severity escalation
    Output: 10+ attack chains
```

### 0B. Infrastructure & Zero Trust Analysis (NEW)

```
Input: CDK stacks, CloudFormation, Terraform files
Output: Zero trust assessment with formal proofs

Components:
├── InfraGraph Builder (src/agents/infrastructure/cfn_parser.py)
│   • Parse CDK/CFN into network + IAM + data graph
│   • Identify all compute resources, databases, storage
│   • Map API Gateway routes to Lambdas with auth config
│   Output: InfraGraph (network, iam, data layers)
│
├── Z3 IAM Formal Verification (src/agents/infrastructure/z3_iam_analyzer.py)
│   • Missing DynamoDB LeadingKeys → proves cross-tenant access possible
│   • Unscoped wildcards → proves admin actions reachable
│   • Deny effectiveness → proves deny covers (or doesn't cover) allow
│   Output: CRITICAL findings with mathematical proofs
│
├── Zero Trust Analyzer (v5/analysis/zero_trust_analyzer.py) ← NEW
│   │
│   ├── Blast Radius Computation
│   │   • For each compute resource: enumerate ALL permissions (transitive)
│   │   • Enumerate ALL network-reachable resources
│   │   • Compute: effective_access = iam_permissions ∩ network_reach
│   │   • Score: blast_radius = |effective_access| / |total_resources|
│   │   • Flag: blast_radius > 30% → UNCONTAINED
│   │
│   ├── Z3 Containment Proofs
│   │   • For each (compromised, target) pair:
│   │   • Encode: allow ∧ ¬deny ∧ network_reachable ∧ action_is_harmful
│   │   • SAT → containment VIOLATED (proven)
│   │   • UNSAT → isolation PROVEN ✓
│   │   • Report: "If observer compromised, can it access sessions table?"
│   │     Answer: "YES — Z3 satisfying assignment: table.get_item with any key"
│   │
│   ├── Network Path Analysis
│   │   • Parse VPC, subnet, security group, NACL from CDK
│   │   • Parse VPC endpoints (interface + gateway type)
│   │   • Lambda VPC config (or no-VPC = internet access)
│   │   • Prove: "Lambda cannot egress to internet" (data exfil prevention)
│   │   • Prove: "No path from public subnet to database subnet"
│   │   • Flag: Lambda without VPC (can reach any internet endpoint)
│   │
│   └── Lateral Movement Graph
│       • Nodes: compute resources + their IAM roles
│       • Edges (compromise paths):
│       │   • sts:AssumeRole (direct trust chain)
│       │   • Shared secrets (same secret accessed by 2+ roles)
│       │   • Shared data (role A writes data that role B trusts)
│       │   • Network adjacency + missing inter-service auth
│       │   • Session/token reuse across services
│       • Find: all paths from internet-facing to high-value targets
│       • Report: longest lateral movement chain + severity
│
└── Toxic Combination Detector (src/agents/infrastructure/toxic_combos.py)
    • Cross-layer: app vulnerability + infra misconfiguration
    • "Unauthenticated endpoint" + "overpermissive IAM" = CRITICAL
    Output: Compound risk findings
```

### 0C. Layer 0 Output: The Evidence Package

All Layer 0 outputs are collected into a single **structured evidence package** that becomes the working memory for Layer 1 agents:

```python
@dataclass
class EvidencePackage:
    # Code analysis
    cpg: CodePropertyGraph              # Full inter-procedural graph
    semgrep_findings: list[Finding]     # Raw pattern matches
    evidence_walks: list[EvidenceWalk]  # Annotated source→sink traces
    absence_findings: list[Finding]     # Missing controls
    differential_findings: list[Finding] # Bypass paths
    attack_chains: list[AttackChain]    # Composed multi-step exploits
    
    # Infrastructure
    infra_graph: InfraGraph             # Network + IAM + data
    z3_proofs: list[Z3Proof]           # Formal IAM property proofs
    blast_radii: dict[str, BlastRadius] # Per-resource containment scores
    lateral_paths: list[LateralPath]    # Lateral movement chains
    network_violations: list[Finding]   # Network isolation failures
    
    # Source code (full text, not snippets)
    file_contents: dict[str, str]       # All analyzed files
    handler_map: dict[str, HandlerInfo] # Handler metadata + auth context
    
    # Infra source
    cdk_stacks: dict[str, str]          # CDK stack source code
```

---

## Layer 1: Deep Investigation Agents

**Purpose:** Domain expert LLM agents that deeply investigate specific vulnerability classes. Each reads the full evidence package + can request additional files.

**Runtime:** 2-5 minutes (parallel)
**LLM calls:** 5 agents × 1 call each (with tool use for file reads)
**Token budget:** Unlimited (extended thinking enabled)

### Agent Roster

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ AGENT 1: Multi-Tenant Isolation Expert                                       │
│                                                                              │
│ Input from Layer 0:                                                          │
│   • All handler source code where customer_id/tenant_id appears              │
│   • CPG taint paths showing tenant identifier flow                           │
│   • Z3 proofs of missing LeadingKeys conditions                              │
│   • Differential: which handlers check ownership, which don't                │
│   • Infra: which routes have authorizers, which don't                        │
│                                                                              │
│ Investigation mandate:                                                       │
│   Follow EVERY path tenant identifiers take through the codebase.            │
│   For each path determine: origin (trusted vs untrusted), verification       │
│   status, substitutability, and blast radius if spoofed.                     │
│                                                                              │
│ Tools: read_file, grep_codebase, query_cpg, query_z3                         │
│ Extended thinking: YES (unlimited scratchpad)                                 │
│ Output: Investigation report with specific code citations                    │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ AGENT 2: Authentication & Authorization Expert                               │
│                                                                              │
│ Input from Layer 0:                                                          │
│   • CDK stack with all authorizer/route configurations                       │
│   • JWT decode code in all handlers                                          │
│   • Differential: which paths have permission checks, which bypass           │
│   • Absence: missing role checks on CRUD operations                          │
│   • Infra auth map (route → auth mechanism)                                  │
│                                                                              │
│ Investigation mandate:                                                       │
│   Map the COMPLETE auth architecture. For each endpoint: what auth,          │
│   what authz, what bypass paths exist, what happens on JWT fallback.         │
│   Identify the "weakest link" in the auth chain.                             │
│                                                                              │
│ Tools: read_file, grep_codebase, get_infra_config, check_auth_on_route       │
│ Extended thinking: YES                                                       │
│ Output: Auth architecture map + bypass findings                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ AGENT 3: Data Flow & Input Validation Expert                                 │
│                                                                              │
│ Input from Layer 0:                                                          │
│   • Evidence walks for all path traversal / injection findings               │
│   • Differential: handler.py sanitizes, data_handler doesn't                 │
│   • All presigned URL generation code                                        │
│   • All DynamoDB key construction patterns                                   │
│   • CPG showing all user-input → dangerous-sink paths                        │
│                                                                              │
│ Investigation mandate:                                                       │
│   For every user-controlled input reaching a sensitive sink, determine       │
│   the COMPLETE validation chain. Are there bypasses? What's the exact        │
│   curl command that exploits each path?                                      │
│                                                                              │
│ Tools: read_file, grep_codebase, query_cpg                                   │
│ Extended thinking: YES                                                       │
│ Output: Per-input validation analysis + concrete exploit commands             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ AGENT 4: Infrastructure & Blast Radius Expert                                │
│                                                                              │
│ Input from Layer 0:                                                          │
│   • Full CDK stack source code                                               │
│   • InfraGraph (network + IAM layers)                                        │
│   • Z3 proofs of overpermissive IAM                                          │
│   • Blast radius scores per resource                                         │
│   • Lateral movement paths                                                   │
│   • Network isolation violations                                             │
│                                                                              │
│ Investigation mandate:                                                       │
│   For each compute resource: what can it access if compromised?              │
│   Is it internet-reachable? What's the most dangerous action?                │
│   How does IAM overpermission amplify app-layer vulnerabilities?             │
│   Map the complete "assume breach" scenario for the most exposed resource.   │
│                                                                              │
│ Tools: read_file, query_z3, get_blast_radius, get_lateral_paths              │
│ Extended thinking: YES                                                       │
│ Output: Zero trust assessment with blast radius analysis                     │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ AGENT 5: Business Logic & Design Flaw Expert                                 │
│                                                                              │
│ Input from Layer 0:                                                          │
│   • Full application source code                                             │
│   • Handler routing logic (what does each endpoint do?)                      │
│   • Database schema (DynamoDB key structure)                                 │
│   • Session management code                                                  │
│   • Signup/registration flow                                                 │
│   • Absence findings (missing audit, missing rate limit)                     │
│                                                                              │
│ Investigation mandate:                                                       │
│   Understand what this application IS and what it SHOULD enforce.            │
│   Identify design-level flaws: auto-admin on signup, session table           │
│   without tenant key, no audit trail for destructive operations.             │
│   These aren't code bugs — they're architecture mistakes.                    │
│                                                                              │
│ Tools: read_file, grep_codebase                                              │
│ Extended thinking: YES                                                       │
│ Output: Design flaw analysis with business impact assessment                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Agent Execution Model

```python
class InvestigationAgent:
    """
    Each investigation agent runs with:
    - Full evidence package as system context
    - Unlimited extended thinking (scratchpad)
    - Tool access to read files and query graphs
    - No token budget (run until investigation is complete)
    - Multi-round deepening (follow-up questions to itself)
    """
    
    def investigate(self, evidence_package: EvidencePackage) -> InvestigationReport:
        # Round 1: Initial analysis based on evidence package
        # Round 2: Read additional files discovered during round 1
        # Round 3: Cross-reference findings, check mitigations
        # Round N: Continue until no new insights
        ...
```

---

## Layer 2: Chain-of-Thought Evidence Synthesis

**Purpose:** For each candidate finding that survived Layer 1, run a structured 7-step CoT analysis that becomes the finding's evidence section.

**Runtime:** 1-3 minutes
**LLM calls:** 1 per finding (~15-25 findings)
**Token budget:** Unlimited thinking per finding

### CoT Protocol

```
For each finding, the agent reasons through these steps sequentially.
The THINKING becomes the evidence. Not a summary — the actual reasoning.

┌─────────────────────────────────────────────────────────────────────────────┐
│ STEP 1: ENTRY POINT ANALYSIS                                                 │
│                                                                              │
│ "What is the attacker's entry point? What HTTP method/route?                 │
│  Is it internet-reachable? What authentication is required at the            │
│  infrastructure level? Can it be bypassed?"                                  │
│                                                                              │
│ Cite: infra_auth_map, CDK route definitions, Z3 proofs                       │
├──────────────────────────────────────────────────────────────────────────────┤
│ STEP 2: DATA FLOW TRACE                                                      │
│                                                                              │
│ "Trace the attacker-controlled value from entry to sink.                     │
│  At each hop: what function? what file? what transformation?                 │
│  What is the variable named? What does it contain?"                          │
│                                                                              │
│ Cite: CPG evidence walk, actual source code lines                            │
├──────────────────────────────────────────────────────────────────────────────┤
│ STEP 3: CONTROL FLOW CONTEXT                                                 │
│                                                                              │
│ "What conditions must be true for this path to execute?                      │
│  Are there early returns, error handlers, or gates that prevent              │
│  reaching the sink? What's the branching logic?"                             │
│                                                                              │
│ Cite: if-statements and gates on the CPG path                                │
├──────────────────────────────────────────────────────────────────────────────┤
│ STEP 4: CROSS-REFERENCE VERIFICATION                                         │
│                                                                              │
│ "Does any other part of the system compensate for this?                      │
│  - Framework behavior (API Gateway, Lambda runtime)?                         │
│  - Middleware or decorator not visible in the handler?                        │
│  - CDK-level config (WAF, VPC, bucket policies)?                             │
│  - Other handler that does the same thing securely?"                         │
│                                                                              │
│ Cite: differential analysis, CDK config, absence detector results            │
├──────────────────────────────────────────────────────────────────────────────┤
│ STEP 5: EXPLOIT CONSTRUCTION                                                 │
│                                                                              │
│ "What is the EXACT HTTP request that exploits this?                          │
│  What preconditions must the attacker satisfy first?                          │
│  What does the attacker observe if successful?                               │
│  What data do they get access to?"                                           │
│                                                                              │
│ Output: Concrete curl command or request sequence                            │
├──────────────────────────────────────────────────────────────────────────────┤
│ STEP 6: CONFIDENCE CALIBRATION                                               │
│                                                                              │
│ "Verified (read from code): [list specific claims backed by code]            │
│  Assumed (framework behavior): [list claims depending on runtime]            │
│  Could not verify (deployment): [list claims requiring infra access]"        │
│                                                                              │
│ This becomes the finding's Verified / Could Not Verify section               │
├──────────────────────────────────────────────────────────────────────────────┤
│ STEP 7: SEVERITY & BLAST RADIUS ASSESSMENT                                   │
│                                                                              │
│ "Given: exploitability (how easy?), impact (what data?),                     │
│  blast radius (how many tenants?), and detectability (is it logged?),        │
│  what is the final severity? Justify with specifics."                        │
│                                                                              │
│ Cite: Z3 blast radius proof, lateral movement analysis                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Layer 3: Adversarial Grounded Debate

**Purpose:** Final validation for HIGH/CRITICAL findings. Reduces false positives by forcing claims to cite evidence. Discovers mitigating factors that investigation agents missed.

**Runtime:** 1-3 minutes
**LLM calls:** 3 per debated finding (prosecutor + defender + judge) × ~8 findings = 24
**Token budget:** Unlimited

### Debate Protocol

```
Only findings rated HIGH or CRITICAL after Layer 2 are debated.
Lower severity findings pass through with Layer 2's assessment.

┌─────────────────────────────────────────────────────────────────────────────┐
│ EVIDENCE BUNDLE (immutable, shared by both sides)                            │
│                                                                              │
│ Compiled from Layer 0 + Layer 1 + Layer 2:                                   │
│ [1] CPG taint path with annotated steps                                      │
│ [2] Z3 proof (if applicable — formal verification result)                    │
│ [3] Source code lines at entry, sink, and intermediate points                │
│ [4] Infra config (auth, IAM, network)                                        │
│ [5] Secure contrast (how other code handles this correctly)                  │
│ [6] Layer 1 investigation findings relevant to this                          │
│ [7] Blast radius / lateral movement data                                     │
│ [8] Layer 2 CoT reasoning chain                                              │
│                                                                              │
│ ALL claims MUST cite [N]. Uncited claims are discarded by the judge.         │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ PROSECUTOR                                                                   │
│                                                                              │
│ Persona: Attack-focused security researcher                                  │
│ Goal: Demonstrate exploitability                                             │
│                                                                              │
│ Must argue (citing evidence):                                                │
│ • The attack path is feasible end-to-end                                     │
│ • No mitigation blocks exploitation                                          │
│ • Impact is significant (data, scope, tenants affected)                      │
│ • The finding deserves its severity rating or higher                         │
│                                                                              │
│ Extended thinking: YES (build the strongest possible case)                   │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ DEFENDER                                                                     │
│                                                                              │
│ Persona: Application developer who built this system                         │
│ Goal: Identify mitigating factors                                            │
│                                                                              │
│ Must argue (citing evidence):                                                │
│ • Mitigating controls (framework, deployment, compensating)                  │
│ • Preconditions that limit exploitability                                    │
│ • Reduced scope or impact                                                    │
│ • Detection/monitoring that would catch exploitation                         │
│                                                                              │
│ RULE: Defender CANNOT make up mitigations not in the evidence bundle.        │
│ Can only cite what IS there, or explicitly note "could not verify"           │
│ as a point that MIGHT mitigate but is unconfirmed.                           │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ JUDGE                                                                        │
│                                                                              │
│ Persona: Principal security engineer with 15 years experience                │
│ Goal: Render fair verdict based on citation quality                          │
│                                                                              │
│ Process:                                                                     │
│ 1. Score each argument by citation density and quality                       │
│ 2. Discard any claim not backed by [N] citation                              │
│ 3. Weigh: Z3 proofs > code evidence > inferred behavior                     │
│ 4. Determine if prosecution proved exploitability end-to-end                 │
│ 5. Determine if defense found genuine mitigation (not hypothetical)          │
│                                                                              │
│ Verdict:                                                                     │
│ • CONFIRMED (original severity) — prosecution fully proved                   │
│ • CONFIRMED (adjusted severity) — partially mitigated                        │
│ • DISMISSED — defense proved compensation exists                             │
│                                                                              │
│ Output includes:                                                             │
│ • Strongest prosecution point                                                │
│ • Strongest defense point                                                    │
│ • Final "Verified" / "Could not verify" lists                                │
│ • Adjusted severity with reasoning                                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Layer 4: Exploit Proof & Fix Verification

**Purpose:** For confirmed findings, generate executable exploits and verified fixes. Closes the loop — proving the vulnerability is real AND the fix works.

**Runtime:** 2-5 minutes
**LLM calls:** 2 per confirmed finding × ~12 = 24
**Token budget:** Unlimited

### Exploit Prover

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ EXPLOIT GENERATION AGENT                                                     │
│                                                                              │
│ Input:                                                                       │
│ • Confirmed finding with full CoT + debate verdict                           │
│ • Layer 2 Step 5 (exploit construction reasoning)                            │
│ • Full source code of relevant handlers                                      │
│ • API endpoint details (route, method, auth requirements)                    │
│                                                                              │
│ Output requirements:                                                         │
│ • EXECUTABLE exploit (curl commands, Python scripts, request sequences)      │
│ • Step-by-step exploitation procedure                                        │
│ • Expected response showing success                                          │
│ • Preconditions (what attacker needs before starting)                        │
│                                                                              │
│ Validation:                                                                  │
│ • AST-parse the exploit to confirm it targets the correct endpoint           │
│ • Verify payload matches the vulnerability type                              │
│ • Confirm the exploit uses the identified entry point                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Fix Generator + Verifier

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ FIX GENERATION & VERIFICATION                                                │
│                                                                              │
│ Step 1: SECURE PATTERN SEARCH (deterministic)                                │
│   Query CPG: "Where is this done correctly in the same codebase?"            │
│   • Find sanitizers protecting similar sinks                                 │
│   • Find gates on parallel code paths (from differential analyzer)           │
│   • Find ownership checks in other handlers                                  │
│   Output: Reference to existing secure pattern                               │
│                                                                              │
│ Step 2: FIX GENERATION (LLM)                                                 │
│   Generate unified diff that:                                                │
│   • Fixes the vulnerability                                                  │
│   • References the existing secure pattern                                   │
│   • Preserves functionality                                                  │
│   • Handles edge cases                                                       │
│   Also generate:                                                             │
│   • Short-term fix (code patch)                                              │
│   • Long-term fix (architectural recommendation)                             │
│                                                                              │
│ Step 3: FIX VERIFICATION (deterministic — iterative)                         │
│   Loop (max 3 attempts):                                                     │
│     1. Apply patch to copy of file                                           │
│     2. Re-run semgrep → does the finding disappear?                          │
│     3. Re-run Z3 → is the property now satisfied?                            │
│     4. Re-run absence detector → is the guard now present?                   │
│     5. Re-build CPG → is the taint path broken?                              │
│     If any check fails → feed failure reason back to LLM → regenerate        │
│                                                                              │
│ Output:                                                                      │
│   • Verified fix (confirmed by re-scan)                                      │
│   • Fix description with reference to secure pattern                         │
│   • Before/after comparison                                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Layer 5: Narrative Synthesis

**Purpose:** One senior-analyst agent reads ALL outputs and produces the final report. This is the only agent that writes user-facing text.

**Runtime:** 1-2 minutes
**LLM calls:** 1 (large context)
**Token budget:** Unlimited

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ NARRATIVE SYNTHESIS AGENT                                                    │
│                                                                              │
│ Persona: Principal security consultant writing for a CISO.                   │
│                                                                              │
│ Input (everything from prior layers):                                        │
│ • Layer 1 investigation reports (5 domain experts)                           │
│ • Layer 2 CoT reasoning chains (per finding)                                 │
│ • Layer 3 debate verdicts + confidence annotations                           │
│ • Layer 4 exploit proofs + verified fixes                                    │
│ • Zero trust assessment (blast radius, lateral movement)                     │
│ • Attack chains with narratives                                              │
│                                                                              │
│ Output structure:                                                            │
│                                                                              │
│ 1. EXECUTIVE SUMMARY                                                         │
│    • Business impact in non-technical terms                                  │
│    • Top 3 risks requiring immediate action                                  │
│    • Overall security posture assessment                                     │
│                                                                              │
│ 2. ZERO TRUST ASSESSMENT                                                     │
│    • Blast radius map (visual: which resources can reach what)               │
│    • Lateral movement paths                                                  │
│    • "Assume breach" scenarios with proven impact                            │
│    • Containment recommendations                                             │
│                                                                              │
│ 3. FINDINGS (grouped by theme, not just severity)                            │
│    Themes: Tenant Isolation, Authentication, Authorization,                  │
│    Input Validation, Secrets Management, Audit & Monitoring                  │
│                                                                              │
│    Per finding:                                                               │
│    ┌───────────────────────────────────────────────────────────────────┐     │
│    │ Title (specific, includes impact — not generic)                    │     │
│    │ Severity | Confidence | Risk Type | CWE                           │     │
│    │                                                                   │     │
│    │ Description                                                       │     │
│    │   2-3 paragraphs: what's wrong, why it matters, how to exploit    │     │
│    │   Written so a senior engineer can act without further research   │     │
│    │                                                                   │     │
│    │ Evidence Walk                                                     │     │
│    │   Entry: POST /v2 {action: "status", job_id: "<uuid>"} (no auth) │     │
│    │   → lambda_handler (handler_v2.py:222)                            │     │
│    │   → _handle_status(body) (line 232)                               │     │
│    │   → _load_session(job_id) (line 137)                              │     │
│    │   → table.get_item(Key={"session_id": job_id}) (line 38)          │     │
│    │     ✗ MISSING: ownership check                                    │     │
│    │   → Returns evaluation JSON (lines 141-156)                       │     │
│    │                                                                   │     │
│    │ Verified:                                                         │     │
│    │   • data_handler.py:153 has no sanitization (code read)           │     │
│    │   • Z3: SAT(allow ∧ ¬leading_keys) — formally proven             │     │
│    │ Could not verify:                                                 │     │
│    │   • Whether WAF blocks path traversal patterns                    │     │
│    │   • Whether VPC endpoints restrict access                         │     │
│    │                                                                   │     │
│    │ Attack Chains involving this finding:                             │     │
│    │   Chain 1: Observer → session_id → this finding → data access     │     │
│    │                                                                   │     │
│    │ Suggested Fix:                                                    │     │
│    │   Short-term: [verified code patch + diff]                        │     │
│    │   Long-term: [architectural recommendation]                       │     │
│    │   Reference: handler.py:141 does this correctly                   │     │
│    └───────────────────────────────────────────────────────────────────┘     │
│                                                                              │
│ 4. ATTACK CHAINS                                                             │
│    Full narrative for each multi-step exploit                                │
│    With composite severity justification                                     │
│                                                                              │
│ 5. RECOMMENDATIONS                                                           │
│    Prioritized by: effort × impact                                           │
│    Grouped: immediate (code fixes), short-term (arch), long-term (redesign)  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Cost & Performance Summary

```
┌──────────┬─────────────────────┬────────────┬──────────────────────────────┐
│ Layer    │ LLM Calls           │ Est. Time  │ Purpose                      │
├──────────┼─────────────────────┼────────────┼──────────────────────────────┤
│ 0        │ 0                   │ ~20s       │ Evidence collection          │
│ 1        │ 5 (parallel)        │ ~3min      │ Deep investigation           │
│ 2        │ ~15 (parallel)      │ ~2min      │ CoT synthesis per finding    │
│ 3        │ ~24 (3 per finding) │ ~3min      │ Adversarial debate           │
│ 4        │ ~24 (2 per finding) │ ~3min      │ Exploit + fix verification   │
│ 5        │ 1                   │ ~2min      │ Final report synthesis       │
├──────────┼─────────────────────┼────────────┼──────────────────────────────┤
│ TOTAL    │ ~70 LLM calls       │ ~13min     │                              │
│          │ ~2M input tokens    │            │ (layers 1-4 parallelizable)  │
│          │ ~500K output tokens  │            │                              │
│          │ ~$20-40 at Opus     │            │                              │
└──────────┴─────────────────────┴────────────┴──────────────────────────────┘
```

---

## Why This Exceeds AWS Security Agent

| Dimension | AWS SA | V5 |
|-----------|--------|-----|
| **Evidence grounding** | Agent reads code | CPG + Z3 proofs + agent reads code |
| **Formal proofs** | None | Z3 proves IAM properties mathematically |
| **Zero trust** | Not assessed | Blast radius + containment proofs + lateral movement |
| **False positive control** | Agent judgment | Grounded debate (uncited claims discarded) |
| **Fix verification** | Suggested only | Re-scanned to confirm finding eliminated |
| **Attack chains** | Implicit in narrative | Explicit composition graph with formal severity |
| **Depth per finding** | 1-2 pages | 7-step CoT + investigation + debate + proof |
| **Contrastive analysis** | Manual | Automated differential analyzer + agent reasoning |
| **Business context** | Inferred | Dedicated business logic agent reads full app |
| **Confidence** | Self-reported | Structured verified/assumed/unverified |
| **Blast radius** | Mentioned per finding | Formally proven per resource |
| **Lateral movement** | Not assessed | Graph with compromise paths |
| **Network isolation** | Not assessed | VPC/SG/endpoint reachability proofs |

---

## Implementation Order

```
Phase 1: Zero Trust Foundation (builds on V4)
  ├── v5/analysis/zero_trust_analyzer.py
  │   ├── Blast radius computation
  │   ├── Z3 containment proofs (extend z3_iam_analyzer.py)
  │   ├── Network path analysis
  │   └── Lateral movement graph
  └── Test: run against compliance repo, verify blast radius findings

Phase 2: Investigation Agents (Layer 1)
  ├── v5/agents/investigation/base.py (agent framework with tool use)
  ├── v5/agents/investigation/tenant_isolation.py
  ├── v5/agents/investigation/auth_architecture.py
  ├── v5/agents/investigation/data_flow.py
  ├── v5/agents/investigation/infra_blast_radius.py
  ├── v5/agents/investigation/business_logic.py
  └── Test: run one agent, verify investigation depth

Phase 3: CoT Synthesis (Layer 2)
  ├── v5/agents/cot_synthesizer.py (7-step protocol)
  └── Test: verify CoT output matches AWS SA evidence quality

Phase 4: Grounded Debate (Layer 3) — upgrade from V3
  ├── v5/agents/debate/prosecutor.py
  ├── v5/agents/debate/defender.py
  ├── v5/agents/debate/judge.py
  └── Test: verify debate reduces false positives

Phase 5: Exploit & Fix (Layer 4)
  ├── v5/agents/prover/exploit_generator.py
  ├── v5/agents/prover/fix_generator.py
  ├── v5/agents/prover/fix_verifier.py (re-scan loop)
  └── Test: verify fix eliminates finding on re-scan

Phase 6: Narrative Synthesis (Layer 5)
  ├── v5/agents/narrator.py
  └── Test: compare output to AWS SA report side-by-side

Phase 7: Orchestrator
  ├── v5/run_v5.py (ties all layers together)
  └── Final validation against compliance repo
```

---

## File Structure

```
v5/
├── DESIGN.md                          (this file)
├── run_v5.py                          (orchestrator)
├── evidence_package.py                (Layer 0 output dataclass)
│
├── analysis/                          (Layer 0 — deterministic)
│   ├── zero_trust_analyzer.py         (blast radius, containment, lateral)
│   ├── network_analyzer.py            (VPC/SG/endpoint parsing)
│   └── ... (reuses v4/analysis/* via imports)
│
├── agents/                            (Layers 1-5 — LLM)
│   ├── base.py                        (agent framework: tools, thinking, rounds)
│   ├── investigation/                 (Layer 1)
│   │   ├── tenant_isolation.py
│   │   ├── auth_architecture.py
│   │   ├── data_flow.py
│   │   ├── infra_blast_radius.py
│   │   └── business_logic.py
│   ├── cot_synthesizer.py             (Layer 2)
│   ├── debate/                        (Layer 3)
│   │   ├── prosecutor.py
│   │   ├── defender.py
│   │   └── judge.py
│   ├── prover/                        (Layer 4)
│   │   ├── exploit_generator.py
│   │   ├── fix_generator.py
│   │   └── fix_verifier.py
│   └── narrator.py                    (Layer 5)
│
├── tools/                             (shared tool implementations)
│   ├── file_tools.py                  (read_file, grep_codebase)
│   ├── cpg_tools.py                   (query_cpg, get_taint_paths)
│   ├── z3_tools.py                    (query_z3, prove_containment)
│   └── infra_tools.py                 (get_blast_radius, check_auth_on_route)
│
└── report/                            (Layer 5 output)
    ├── generator.py                   (markdown + JSON + PDF)
    └── templates/                     (report structure templates)
```
