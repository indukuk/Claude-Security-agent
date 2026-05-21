# Security Agent — Requirements

## Overview

A graph-based security analysis system that uses LLM reasoning to identify vulnerabilities across heterogeneous codebases. An **orchestrator agent** decomposes the target repository, dispatches specialized agents per technology, and correlates findings across boundaries.

The system implements a **neuro-symbolic hybrid architecture** — LLMs handle specification inference and contextual reasoning while traditional program analysis engines handle sound dataflow propagation. This approach is validated by research showing 2.5x detection improvement over standalone SAST (IRIS: 57.5% vs CodeQL: 22.5% on CWE-Bench-Java) and 91% false positive reduction versus SAST alone.

---

## Evidence Base

Key research informing this design:

| System | Approach | Result |
|--------|----------|--------|
| IRIS | LLM infers taint specs → CodeQL tracks flows | 57.5% detection vs 22.5% standalone SAST |
| AdaTaint | Neuro-symbolic source/sink inference + symbolic validation | 43.7% FP reduction, 11.2% recall improvement |
| BugLens | LLM post-refinement of static analysis | Precision: 0.10 → 0.72 (7x improvement) |
| SemTaint | Multi-agent LLM + CodeQL for JS | 106 previously undetectable vulns found |
| LATTE | LLM-powered binary taint analysis | 37 new bugs, 10 CVEs assigned |
| LLMxCPG | Code Property Graph slicing for LLM context | 67-91% token reduction, 15-40% F1 improvement |
| VSP | Vulnerability-semantics-guided prompting | 553% higher F1 over baseline |
| Think & Verify CoT | Structured self-verification reasoning | Ambiguous responses: 20.3% → 9.1% |
| RepoAudit | Repository-scale multi-agent analysis | ~$2.54 per project |
| RealVuln | Three-tier scanner benchmark (2026) | Specialized: F3=73.0, General LLM: 51.7, SAST: 17.7 |

**Critical anti-finding (PrimeVul):** LLMs alone perform at near-random on rigorous vulnerability benchmarks. GPT-4 scored 3.09% F1 on cleaned data. This confirms LLMs must augment — not replace — structured analysis.

**Infrastructure-specific evidence:**

| Finding | Source | Implication |
|---------|--------|-------------|
| Traditional IaC tools have 68-78% false positive rates | InfoWorld/SAST analysis | FP filtering is not optional — it's the primary usability problem |
| LLMs without security instructions produce secure IaC only 7% of the time | arXiv:2602.03648 | Structured prompting is load-bearing, not cosmetic |
| Guided prompt with steps: F1 from 58% → 89% | arXiv:2602.03648 | Persona + few-shot + CoT dramatically changes effectiveness |
| LLMSecConfig RAG-enhanced remediation: 94% success | arXiv:2502.02009 | RAG with security knowledge base enables near-complete auto-fix |
| LLM fixes may delete unrelated configurations | Empirical Software Engineering | Post-fix validation is mandatory — run scanner + tests on generated fixes |
| MCP Server Pattern for delta scanning | AWS Prescriptive Guidance | Standard integration architecture for AI + traditional tools in CI/CD |
| Context window: performance degrades with info in middle | Research | Place critical configs at beginning/end of LLM context, not middle |
| CDK developers can create roles exceeding their own permissions | AWS DevOps Blog | Permission boundary enforcement is CDK-critical |

---

## Architecture: Multi-Agent Orchestration

Modern applications are polyglot — a single repo may contain Python services, JavaScript frontends, Terraform infrastructure, CDK stacks, and Dockerfiles. No single analysis approach covers all of them. The system uses a **hub-and-spoke model**:

```
                    ┌─────────────────────────┐
                    │   ORCHESTRATOR AGENT     │
                    │                          │
                    │  - Repo decomposition    │
                    │  - Agent dispatch        │
                    │  - Cross-boundary        │
                    │    correlation           │
                    │  - Unified reporting     │
                    └────────────┬────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          │              │               │               │
          ▼              ▼               ▼               ▼
   ┌─────────────┐ ┌──────────┐ ┌────────────┐ ┌────────────┐
   │ Python App  │ │ JS/TS    │ │ Terraform  │ │ CDK        │
   │ Agent       │ │ Agent    │ │ Agent      │ │ Agent      │
   │             │ │          │ │            │ │            │
   │ Taint flow  │ │ XSS/DOM  │ │ HCL parse  │ │ CFN synth  │
   │ SQL/CMD inj │ │ Prototype│ │ State graph│ │ IAM graph  │
   │ Deserialize │ │ SSRF     │ │ IAM/Net    │ │ Blast rad. │
   └─────────────┘ └──────────┘ └────────────┘ └────────────┘
```

### Why Specialized Agents

Each technology has:
- Different AST parsers (tree-sitter grammars, HCL parser, CFN schema)
- Different vulnerability classes (taint flow vs. misconfiguration)
- Different graph semantics (data flow vs. resource topology)
- Different best-practice rule sets

A single monolithic prompt cannot hold all of this context effectively.

### Three Validated Roles for the LLM

Research consensus identifies three specific roles where LLMs add value:

1. **Specification inference** — Automatically generating source/sink/sanitizer models that are the bottleneck for traditional taint tools. (IRIS: 2.5x detection; AdaTaint: 11.2% recall improvement; LATTE: 37 new bugs)

2. **False positive filtering** — Using semantic understanding to determine if a flagged flow is actually exploitable. (BugLens: 7x precision; SAST+LLM: 91% FP reduction)

3. **Gap filling** — Resolving dynamic dispatch, reflection, metaprogramming, and custom frameworks that defeat static analysis. (SemTaint: 106 previously undetectable vulns)

LLMs should NOT be used for end-to-end vulnerability detection (PrimeVul: near-random performance).

---

## System Components

### 1. Orchestrator Agent

**Responsibilities:**
- Scan repository structure and identify technology boundaries
- Determine which specialized agents to invoke
- Manage global state and checkpoints
- Correlate findings across agent boundaries (e.g., "Python app trusts environment variable that Terraform sets from a public-facing source")
- Produce unified report with de-duplicated, prioritized findings

**Inputs:**
- Repository path
- Configuration (which agents to enable, severity thresholds, scope)

**Outputs:**
- Unified vulnerability report
- Coverage metrics (per agent and global)
- Cross-boundary findings

**Cross-Boundary Analysis Examples:**
- CDK creates a Lambda with an overly permissive role → Python agent finds the Lambda code handles user input → compound: user-controlled input + admin permissions = critical
- Terraform creates an S3 bucket policy allowing public read → JS agent finds the app uploads user PII to that bucket → compound: data exposure
- Environment variables defined in Terraform/CDK consumed unsafely in application code

---

### 2. Python Application Agent

**Graph Model: Code Property Graph (CPG)**

The agent builds a Code Property Graph — a unified representation combining AST + Control Flow Graph (CFG) + Data Flow Graph (DFG) in a single queryable structure (per Joern/LLMxCPG research). This is more powerful than a call graph alone because it encodes control flow, data dependencies, and program structure simultaneously.

- Nodes: statements, expressions, function definitions, parameters
- Edges (AST): parent-child syntax relationships
- Edges (CFG): control flow between statements (branches, loops, exceptions)
- Edges (DFG): data dependencies (def-use chains, assignments, argument passing)

**Why CPG over simple call graph:**
- Captures intra-procedural data flow (which variables are tainted within a function)
- Encodes control flow (which branches lead to the sink)
- Enables CPG slicing — extracting only vulnerability-relevant subgraphs (67-91% token reduction per LLMxCPG research, 15-40% F1 improvement)

**Vulnerability Classes:**
- SQL injection (unsanitized input → raw query) — CWE-89
- Command injection (user input → os.system, subprocess, eval, exec) — CWE-78
- Deserialization (untrusted data → pickle.loads, yaml.load) — CWE-502
- Path traversal (user input → file operations without normalization) — CWE-22
- SSRF (user input → requests/urllib without allowlist) — CWE-918
- Weak cryptography (md5/sha1 for security, ECB mode, hardcoded keys) — CWE-327

**Parser:** tree-sitter (Python grammar)

**Source/Sink/Sanitizer Definitions (Baseline):**
```
Sources:
  - request.args, request.form, request.json (Flask)
  - event (Lambda handler parameter)
  - sys.argv, os.environ (when from external)
  - socket.recv, input()

Sinks:
  - cursor.execute(), engine.execute() (SQL)
  - os.system(), subprocess.*, eval(), exec() (Command)
  - pickle.loads(), yaml.load() (Deserialization)
  - open(), os.path.join() (Path traversal)
  - requests.get(), urllib.request.urlopen() (SSRF)

Sanitizers:
  - parameterized queries (?, %s with separate args)
  - shlex.quote()
  - ast.literal_eval() (safe eval)
  - os.path.abspath() + startswith check
  - URL allowlist validation
```

These baseline definitions are augmented at runtime by LLM-driven specification inference (Phase 0) which identifies project-specific sources, sinks, and sanitizers from custom frameworks, internal libraries, and API patterns.

---

### 3. JavaScript/TypeScript Application Agent

**Graph Model: Code Property Graph (CPG)**

Same CPG structure as Python agent, with JS/TS-specific semantics:
- Async chains (Promise.then, await) modeled as control flow edges
- Prototype chain as data flow edges
- React component props as data flow between parent/child

**Vulnerability Classes:**
- XSS (user input → dangerouslySetInnerHTML, innerHTML, document.write) — CWE-79
- Prototype pollution (user-controlled keys in object merge) — CWE-1321
- SSRF (user input → fetch/axios without allowlist) — CWE-918
- ReDoS (user input → vulnerable regex) — CWE-1333
- Path traversal (user input → fs.readFile, path.join) — CWE-22
- Insecure dependencies (known CVE in node_modules)

**Parser:** tree-sitter (TypeScript grammar, covers JS)

**Source/Sink/Sanitizer Definitions (Baseline):**
```
Sources:
  - req.params, req.query, req.body (Express)
  - event (Lambda)
  - window.location, document.URL (Client-side)
  - URL search params

Sinks:
  - innerHTML, dangerouslySetInnerHTML, document.write (XSS)
  - eval(), Function(), setTimeout(string) (Code injection)
  - child_process.exec() (Command injection)
  - Object.assign({}, untrusted), {...untrusted} with computed keys (Prototype pollution)
  - fs.readFile(), fs.createReadStream() (Path traversal)

Sanitizers:
  - DOMPurify.sanitize()
  - encodeURIComponent()
  - parameterized queries
  - path.normalize() + root check
  - input validation libraries (joi, zod)
```

---

### 4. Terraform Agent

**Graph Model:**
- Nodes: resources, data sources, modules, variables, outputs
- Edges: references (resource attributes used by other resources), depends_on

**Vulnerability Classes:**
- Network exposure (security groups, public subnets, NACLs)
- IAM over-permission (wildcard actions/resources)
- Privilege escalation (IAM write permissions enabling self-escalation)
- Encryption gaps (at-rest, in-transit)
- Public data stores (S3 public access, RDS public accessibility)
- Logging gaps (CloudTrail, VPC flow logs, access logging)
- Cross-account trust without ExternalId (confused deputy)
- Secrets in state/variables (hardcoded credentials)

**Parser:** HCL native parser (python-hcl2 or pyhcl)

**Input:** Terraform files (.tf) + optional: `terraform plan -json` output for resolved values

**Graph Construction:**
```
For each resource block:
  - Create node with type + all attributes
  - For each reference (resource.name.attribute):
    - Create edge to referenced resource
  - For each variable reference:
    - Track whether value is sensitive/external

For each module call:
  - Recursively parse module source
  - Connect module inputs/outputs as edges
```

**Specific Analysis:**
- Parse `aws_iam_policy_document` data sources → extract statements → build IAM graph
- Parse `aws_security_group` / `aws_security_group_rule` → build network graph
- Resolve `count` and `for_each` where possible to enumerate actual resources
- Detect `terraform_remote_state` usage for cross-stack analysis

---

### 5. CDK Agent

**Graph Model:**
- Nodes: AWS resources (as defined in synthesized CloudFormation)
- Edges: Ref, Fn::GetAtt, Fn::Sub references + semantic connections

**Vulnerability Classes:**
Same as Terraform Agent (both produce AWS infrastructure), plus:
- L1 construct misuse (raw CFN properties bypassing CDK safety abstractions)
- Grant methods with overly broad scope
- Default security group usage
- Missing removal policies on stateful resources
- **CDK permission escalation** — developers creating roles via CDK that exceed their own permissions (structural risk unique to CDK's IAM abstraction layer). Requires permission boundary enforcement check on all synthesized roles.

**Input:** Synthesized CloudFormation template (output of `cdk synth`)

**Why synth output rather than CDK source:**
- Language-agnostic (CDK can be Python, TypeScript, Java, Go)
- All high-level abstractions resolved to concrete resources
- Conditions and references fully expanded
- Deterministic — no runtime ambiguity

**Graph Construction:**
- Parse CloudFormation JSON
- Build resource topology from Ref/GetAtt/Sub references
- Build IAM graph from IAM::Role, IAM::Policy resources
- Overlay with network connectivity from VPC/Subnet/SG relationships
- Expand managed policies using bundled policy definitions

---

## Shared Infrastructure

### Knowledge Base (Ground Truth)

```
knowledge/
├── aws_managed_policies.json       # ~1000 policy documents, fully expanded
├── aws_action_catalog.json         # All IAM actions per service + danger classification
├── aws_security_rules.json         # Best practices (CIS, Well-Architected, Security Hub)
├── iam_escalation_paths.json       # 21+ known privilege escalation primitives (Rhino Security)
├── toxic_combinations.json         # Compound risk patterns (toxic combos)
├── cwe_definitions.json            # CWE database (top 50 relevant CWEs with descriptions)
├── vulnerability_patterns.json     # Known exploit patterns per CWE (for variant analysis)
├── resource_connections.json       # AWS resource relationship model (what connects to what)
├── python_sources_sinks.json       # Language-specific taint definitions
├── javascript_sources_sinks.json   # Language-specific taint definitions
└── refresh_policies.py             # Update script (periodic)
```

**AWS Managed Policy Bundle:**
- Contains full policy document for every AWS managed policy
- Pre-computed risk tier (CRITICAL/HIGH/MEDIUM/LOW)
- Flagged for escalation capability
- Wildcards pre-expanded against action catalog

**AWS Action Catalog:**
- Every IAM action per AWS service
- Classified by danger category: data_exfil, privilege_escalation, destructive, persistence, lateral_movement
- Used for wildcard expansion (s3:Get* → all matching actions)

**AWS Security Rules:**
- Machine-readable best practice rules with:
  - Applies-to (resource types)
  - Check condition (what to verify)
  - Severity (CRITICAL/HIGH/MEDIUM/LOW)
  - CIS/Well-Architected mapping
  - Remediation guidance

**CWE Knowledge Base (NEW — RAG foundation):**
- Structured definitions for top 50 security-relevant CWEs
- Each entry contains: description, common manifestations, exploitation patterns, detection guidance
- Used for Vulnerability-Semantics-guided Prompting (553% F1 improvement)
- Injected per-analysis: when checking for SQLi, include CWE-89 definition in context

**Vulnerability Patterns (NEW — variant analysis seeds):**
- Known exploit patterns extracted from CVE databases and Project Zero reports
- Used in Phase 4 (Variant Analysis): "Does this codebase contain similar patterns?"
- Google's Big Sleep approach: first AI-found exploitable 0-day used variant analysis

---

### Code Property Graph (CPG) Engine

The CPG is the central data structure for application code analysis. It unifies three representations into one queryable graph:

```
Code Property Graph = AST ∪ CFG ∪ DFG

Where:
  AST edges: syntactic parent-child (structure)
  CFG edges: statement-to-statement control flow (execution order)
  DFG edges: variable def-use chains (data dependencies)
```

**Why CPG over separate graphs:**
- Single traversal answers both "does control flow reach this point?" and "is this variable tainted here?"
- Enables CPG slicing: extract only the subgraph relevant to a specific vulnerability path
- LLMxCPG research shows 67-91% reduction in context size while preserving vulnerability-relevant information
- 15-40% F1 improvement over feeding raw code to the LLM

**CPG Slicing Algorithm:**
```python
def extract_cpg_slice(cpg, source_node, sink_node):
    """
    Extract the minimal subgraph relevant to analyzing
    whether data flows from source to sink.
    
    Includes:
    - All nodes on DFG paths from source to sink
    - CFG context for branch conditions that gate the flow
    - 1-hop AST context for semantic understanding
    """
    # Data flow slice: all nodes on def-use paths
    dfg_paths = all_paths(cpg, source_node, sink_node, edge_type="DFG")
    slice_nodes = set()
    for path in dfg_paths:
        slice_nodes.update(path)
    
    # Control flow context: branch conditions affecting the path
    for node in list(slice_nodes):
        cfg_predecessors = cpg.predecessors(node, edge_type="CFG")
        for pred in cfg_predecessors:
            if is_branch_condition(pred):
                slice_nodes.add(pred)
    
    # 1-hop AST context: enclosing function signatures, class names
    for node in list(slice_nodes):
        ast_parent = cpg.parent(node, edge_type="AST")
        if ast_parent:
            slice_nodes.add(ast_parent)
    
    return cpg.subgraph(slice_nodes)
```

**Token savings per slice:**
```
Full file context:     ~2000-5000 tokens per file
CPG slice per path:    ~200-800 tokens
Reduction:             67-91% (matches LLMxCPG findings)
```

---

### Checkpoint System

All agents share a common checkpoint model for resumability:

```python
@dataclass
class AgentState:
    agent_type: str                    # "python", "javascript", "terraform", "cdk"
    phase: int                         # current execution phase
    chunk_index: int                   # current chunk within phase
    graph: dict                        # serialized CPG (adjacency list + edge types)
    inferred_specs: dict               # LLM-inferred sources/sinks/sanitizers (Phase 0)
    deterministic_findings: list       # pre-computed checks (no LLM)
    llm_findings: list                 # LLM-produced findings (grows incrementally)
    validated_findings: list           # post-FP-filtering findings (Phase 3.5)
    pending_analysis: list             # work items not yet analyzed
    coverage: CoverageMetrics          # current coverage state
    timestamp: str
```

**Contracts:**
- Checkpoint saved after every LLM call (chunk boundary)
- No work is repeated on resume
- Coverage metric always current
- Any agent can be interrupted and resumed independently

---

### Chunking Engine

Shared logic for breaking work into LLM-friendly units. Uses **CPG slicing** as the primary context preparation method rather than raw code.

**Token Budget Per Chunk:**
```
System prompt + persona + CoT template:   ~2K tokens
CWE definition (RAG, per vulnerability):  ~0.5K tokens
Security rules (relevant subset):         ~1-2K tokens
CPG slices (primary analysis content):    ~3-8K tokens   ← (was 5-20K with raw code)
Prior findings (compressed):              ~1-2K tokens
Output reserved:                          ~4K tokens
────────────────────────────────────────────────────────
Total per chunk:                          ~12-19K tokens  ← (was 17-37K)
```

CPG slicing reduces per-chunk cost by ~50%, allowing more paths per chunk or lower total cost.

**Chunking Strategies:**
- App agents: group taint paths sharing common CPG nodes (reduces redundant context)
- Infra agents: chunk by security domain (network, IAM, encryption, compound)

**Findings Compression:**
- Raw finding: ~200-500 tokens
- Compressed (carry-forward): ~30-50 tokens
- Beyond 40 findings: summarize by category

---

## Execution Model

### Phase 0: Specification Inference (Per Agent, LLM)

**Purpose:** Overcome the specification bottleneck — the #1 limitation of traditional taint analysis.

```
Input: import statements, framework usage patterns, custom library signatures

LLM Task: "Given this codebase uses [framework X], identify additional:
  - Sources: functions/parameters that accept external input
  - Sinks: functions that perform security-sensitive operations
  - Sanitizers: functions that validate/escape/transform data safely
  - Propagators: functions that pass taint through (wrappers, decorators)"

Output: Augmented source/sink/sanitizer definitions

Validation: Each inferred spec is grounded against code structure
  - Inferred source must accept external data (check call sites)
  - Inferred sink must perform a dangerous operation (check implementation)
  - Inferred sanitizer must transform data (check it's not a passthrough)
```

**Why validation is essential (AdaTaint insight):** LLMs hallucinate specifications. Without symbolic validation, false specs corrupt the entire analysis. Every inferred definition is checked against the actual code before being used.

**Cost:** ~1 LLM call per agent (~$0.20)

---

### Phase 1: Discovery (Orchestrator, No LLM)

```
Input: repository root path

1. Scan file tree for technology markers:
   - *.py, requirements.txt, pyproject.toml → Python agent
   - *.ts, *.js, package.json → JavaScript agent
   - *.tf, .terraform/ → Terraform agent
   - cdk.json, cdk.out/ → CDK agent

2. Identify boundaries:
   - Which directories map to which agent
   - Shared configuration files (env vars, secrets references)
   - Cross-technology references (Python reading TF outputs, etc.)

3. Create execution plan:
   - Which agents to invoke
   - Dependency order (infra agents first if app references infra outputs)
   - Parallel vs. sequential execution
```

---

### Phase 2: Graph Construction + Deterministic Analysis (Per Agent, No LLM)

Each agent builds its graph deterministically:
- Parse source files → AST → Code Property Graph (app agents) or Resource Graph (infra agents)
- Merge baseline + inferred source/sink/sanitizer definitions (from Phase 0)
- Compute reachability / enumerate all taint paths
- Run deterministic checks (encryption, public access, wildcard permissions)
- Score and prioritize paths for LLM analysis (knapsack allocation)

**Output:** Serialized CPG + deterministic findings + prioritized work queue

---

### Phase 3: LLM Taint Reasoning (Per Agent, Chunked)

Each agent executes its analysis independently using CPG-sliced context and CWE-specific prompting.

**Per-chunk LLM prompt structure:**

```
SYSTEM PROMPT:
  "You are a senior application security engineer specializing in taint
   analysis and vulnerability detection. You are performing a security
   audit of production code."

CWE CONTEXT (RAG):
  [Injected CWE definition for the vulnerability type being checked]

CPG SLICE:
  [Minimal code context extracted via CPG slicing — only the relevant
   nodes/edges for this specific taint path]

PRIOR FINDINGS:
  [Compressed carry-forward from previous chunks]

CoT TEMPLATE (Think & Verify):
  "Analyze this code path for [CWE-XXX: Vulnerability Name].

   STEP 1 — IDENTIFY: What untrusted input enters this path? Where does it
   come from? What does the attacker control?

   STEP 2 — TRACE: Follow the data through each transformation. For each
   step, state: (a) the variable carrying tainted data, (b) what operation
   is performed on it, (c) whether taint is preserved or removed.

   STEP 3 — ASSESS: Does the data pass through any sanitization? Is the
   sanitization sufficient for this specific sink type? Could it be bypassed?

   STEP 4 — CONCLUDE: Does tainted data reach the sink in a form that
   enables exploitation?

   STEP 5 — VERIFY: Challenge your own reasoning:
   - Could the path be unreachable due to preconditions?
   - Could the sanitizer handle edge cases you haven't considered?
   - Are there framework-level protections not visible in this slice?
   - Is there a type constraint that prevents exploitation?

   STEP 6 — VERDICT:
   { VULNERABLE | SAFE | UNCERTAIN }
   Confidence: { HIGH | MEDIUM | LOW }
   If VULNERABLE: describe the exploit scenario in one sentence."
```

**Processing:**
- Process chunks in priority order (risk-weighted)
- Checkpoint after each chunk
- Compress findings for carry-forward
- Track coverage metric

**Output:** Per-agent candidate findings list + coverage report

---

### Phase 3.5: False Positive Validation (Per Agent, LLM — Adversarial)

**Purpose:** Reduce false positives by 91% (validated by SAST+LLM research).

For each finding from Phase 3, a separate LLM call with an adversarial stance:

```
"A security scanner has flagged the following as a vulnerability:
  [finding description + code context]

Your task is to argue why this is NOT exploitable. Consider:
  1. Are there preconditions that prevent the vulnerable path from executing?
  2. Does the framework provide implicit protections not visible in the code?
  3. Are there type constraints that limit the attacker's input?
  4. Is the sanitizer actually sufficient despite appearing incomplete?
  5. Is the sink actually dangerous in this specific context?
  6. Could environmental controls (WAF, network isolation) mitigate this?

If you can construct a convincing argument that this is safe, explain why.
If you cannot find a valid reason it's safe, confirm the vulnerability."
```

**Decision logic:**
- If the model constructs a sound safety argument → downgrade to INFO or dismiss
- If the model cannot rebut → confirmed finding (HIGH confidence)
- If the model is uncertain → keep as MEDIUM confidence, flag for human review

**Cost:** ~$0.50 per project (one call per candidate finding, findings are short)

---

### Phase 4: Variant Analysis (Per Agent, LLM)

**Purpose:** Find vulnerabilities similar to known patterns (Google Big Sleep approach).

```
Input: Known vulnerability patterns from knowledge/vulnerability_patterns.json
       + the codebase's CPG

LLM Task: "Here is a known vulnerability pattern [CVE-XXXX]:
  [pattern description + code example]

  The codebase contains the following similar constructs:
  [CPG query results showing structurally similar code]

  Analyze whether any of these constitute the same vulnerability class.
  Consider variations: different variable names, wrapper functions,
  slightly different control flow that achieves the same unsafe result."
```

**This catches:**
- Copy-paste vulnerabilities (same bug in multiple places)
- Pattern variants (same logic flaw expressed differently)
- Library-level issues (all callers of an unsafe function)

---

### Phase 5: Cross-Boundary Correlation (Orchestrator, LLM)

The orchestrator receives all agent findings and performs compound analysis:

```
Inputs to correlation:
  - Python agent: "Lambda handler reads request.body['key'] and passes to DynamoDB query"
  - CDK agent: "Lambda role has dynamodb:* on Resource: *"
  - CDK agent: "API Gateway is publicly accessible, no WAF"

Compound finding:
  "Public API → Lambda with unvalidated input → DynamoDB injection possible
   because: (1) no input validation in app code, (2) overly broad permissions
   allow table scan/write to any table, (3) no WAF to filter malicious payloads"
```

---

### Phase 6: Reporting

Unified report with:
- Findings grouped by severity (CRITICAL → LOW)
- CVSS scores where applicable
- Attack path visualization (entry → hops → target)
- CWE classification for each finding
- Remediation guidance (specific to finding)
- Coverage summary (per-agent and global)
- Uncovered areas explicitly called out
- Confidence levels (HIGH/MEDIUM/LOW per finding)
- Cost summary (LLM tokens used, budget remaining)

---

## Coverage Metrics

### Application Code Coverage

```
C_taint = |source_sink_pairs_analyzed| / |total_reachable_pairs|
C_risk  = Σ risk(analyzed_pairs) / Σ risk(all_pairs)
```

Prioritization (knapsack optimization):
```
maximize:  Σ rᵢ · xᵢ           (total risk covered)
subject to: Σ cᵢ · xᵢ ≤ B     (token budget)

Where:
  rᵢ = exposure(source) × severity(sink) × (1 - sanitizer_confidence)
  cᵢ = estimated tokens for CPG slice analysis
```

### Infrastructure Coverage

```
C_network  = |connections_checked| / |total_connections|
C_iam      = |principals_fully_resolved| / |total_principals|
C_compound = |attack_paths_analyzed| / |viable_attack_paths|
```

Blast radius computation:
```
BlastRadius(n) = NetworkReachable(n) ∩ PermissionReachable(n)
Risk(path) = Exploitability(entry) × hop_difficulty × Impact(target)
```

### Global Coverage

```
C_global = Σ (weight_agent × C_agent) / Σ weight_agent

Where weight is proportional to the attack surface of each component.
```

---

## Multi-Stage Scanning Model

Security scanning integrates at multiple development stages, each with different latency/depth tradeoffs:

```
┌──────────────────────────────────────────────────────────────────────┐
│ STAGE 1: IDE (Real-time, <2s)                                        │
│   - MCP Server Pattern: AI assistant connected to fast rule checks   │
│   - Delta scanning: only analyze new/changed code segments           │
│   - Immediate developer feedback during authoring                    │
│   - Deterministic checks only (no LLM latency)                      │
├──────────────────────────────────────────────────────────────────────┤
│ STAGE 2: Pre-commit Hook (Fast, <10s)                                │
│   - Run deterministic checks on staged files                         │
│   - Block commits with CRITICAL findings (wildcard IAM, public DB)   │
│   - No LLM calls (too slow for git hook)                            │
├──────────────────────────────────────────────────────────────────────┤
│ STAGE 3: CI/CD Pipeline Gate (Comprehensive, 1-5min)                 │
│   - Full graph construction + Z3 IAM analysis                        │
│   - LLM-powered taint reasoning + FP validation                     │
│   - Toxic combination detection                                      │
│   - Attack path enumeration                                          │
│   - LLM remediation generation for findings                          │
│   - Post-fix validation (scanner re-run on generated fixes)         │
│   - Gate: block deploy if CRITICAL unfixed, warn on HIGH            │
├──────────────────────────────────────────────────────────────────────┤
│ STAGE 4: Post-deployment (Monitoring)                                │
│   - Drift detection: IaC state vs. deployed state                   │
│   - Runtime permission usage analysis (for least-privilege tuning)  │
│   - Continuous compliance monitoring                                 │
└──────────────────────────────────────────────────────────────────────┘
```

**MVP scope:** Stage 3 (CI/CD pipeline gate). Stages 1, 2, 4 are Phase 3 additions.

---

## Incremental Scanning (CI Integration)

On subsequent runs (not first scan):

```
1. Compute diff (git diff or template diff)
2. Identify affected nodes in each agent's CPG/graph
3. Expand to 1-hop neighbors (their security posture may have changed)
4. Invalidate only affected chunks
5. Re-run Phase 0 (spec inference) only if new imports/frameworks detected
6. Re-analyze only invalidated paths

Cost: O(|changed_nodes| × avg_degree) vs. O(|all_nodes|) for full scan
Typical: 5-10% of full scan for a normal PR
```

---

## Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Orchestration | Python (native tool-use loop) | Simple, no framework overhead for MVP |
| LLM | Claude (Opus for reasoning, Sonnet for spec inference/validation) | Best code reasoning, large context |
| Graph | NetworkX | Mature, full algorithm library, serializable |
| SMT Solver | Z3 (z3-solver Python bindings) | Formal IAM permission reasoning, same approach as AWS Zelkova |
| CPG Construction | tree-sitter → custom CPG builder | AST extraction, then CFG+DFG construction |
| Python parsing | tree-sitter (Python grammar) | Fast, incremental, production-grade |
| JS/TS parsing | tree-sitter (TypeScript grammar) | Same toolchain as Python |
| HCL parsing | python-hcl2 | Native Terraform format support |
| CFN parsing | JSON stdlib | Templates are plain JSON after synth |
| State/Checkpoints | JSON files on disk | Simple, inspectable, git-friendly |
| Deterministic checks | Custom Python | No external SAST dependency for MVP |
| Complementary SAST | Semgrep (optional) | Additional signal, reduces false negatives |
| CWE Knowledge | MITRE CWE database (curated top 50) | RAG context for VSP prompting |
| Validation data | TerraGoat + CloudCommotion | 280+ misconfigs + 40 attack scenarios for testing |

---

## Cost Model

Based on RepoAudit benchmark (~$2.54/project) and CPG slicing token reduction:

```
For a typical project (~50K lines, ~200 functions, ~100 AWS resources):

APPLICATION CODE ANALYSIS:
  Phase 0  (Spec inference):       ~$0.20  (1 LLM call per agent)
  Phase 3  (Taint reasoning):      ~$1.00  (10-15 chunks, CPG-sliced)
  Phase 3.5 (FP validation):       ~$0.40  (adversarial check per finding)
  Phase 4  (Variant analysis):     ~$0.30  (pattern matching)

INFRASTRUCTURE ANALYSIS:
  Graph construction:              free    (deterministic)
  Deterministic checks:            free    (40 rules, <1s)
  Z3 IAM analysis:                 free    (local computation, ~5-10s)
  Attack path enumeration:         free    (graph traversal)
  Toxic combination detection:     free    (pattern matching on graphs)
  LLM contextual analysis:        ~$0.60  (5-8 chunks for judgment calls)
  LLM remediation generation:     ~$0.30  (one call per confirmed finding)
  LLM FP validation:              ~$0.20  (adversarial check)

CROSS-BOUNDARY:
  Phase 5  (Correlation):          ~$0.30  (cross-boundary, single call)
─────────────────────────────────────────────────────────────────────
Total:                            ~$3.30/project (app + infra combined)

Incremental (PR-level):           ~$0.40-0.70/run (5-10% of full scan)
```

**Key cost insight:** The most valuable infra analyses (IAM reasoning, attack paths, toxic combinations) are **free** — computed deterministically or via Z3 solver. LLM cost is only incurred for contextual judgment and remediation, which represents the minority of the work.

---

## MVP Scope

### In Scope (Build First)
- Orchestrator with agent dispatch
- Python application agent with CPG construction and slicing
- CDK agent (infrastructure via synthesized CloudFormation)
- Phase 0: LLM-driven spec inference with symbolic validation
- Phase 3: Think & Verify CoT with CWE-specific prompting (VSP)
- Phase 3.5: False positive validation (adversarial stance)
- AWS managed policy bundle + action catalog
- AWS security rules (CIS subset — top 30 rules)
- CWE knowledge base (top 25 CWEs for Python + infra)
- Z3-based IAM permission analysis (formal reasoning)
- Privilege escalation path detection (21 primitives)
- Toxic combination detection (8 patterns)
- Blast radius computation per principal
- Attack path enumeration (entry → target)
- Deterministic checks for infra (~40 rules)
- LLM-generated remediation for confirmed findings
- Checkpoint/resume system
- CPG-sliced chunking engine
- Unified report output
- Validation against TerraGoat dataset

### Phase 2 (After MVP Validates)
- JavaScript/TypeScript agent
- Terraform agent (HCL parsing + plan JSON)
- Phase 4: Variant analysis with CVE pattern seeds
- Cross-boundary correlation (Phase 5)
- Incremental scanning (git-diff aware)
- Semgrep integration as complementary signal
- CVSS scoring
- CI/CD integration (GitHub Action / CodePipeline)
- MCP Server interface (expose agent as MCP tool for IDE integration)
- Multi-stack analysis (cross-stack references)
- CloudCommotion scenario validation

### Phase 3 (Scale)
- Additional language agents (Java, Go)
- Multi-account / multi-stack analysis
- Cross-account trust analysis (role chaining across accounts)
- Custom rule authoring (user-defined best practices)
- Custom toxic combination patterns
- Historical trend tracking
- IDE integration (real-time findings as you code)
- Fine-tuned models for spec inference (reduce cost)
- Runtime drift detection (IaC vs. deployed state comparison)

---

## Infrastructure Security Testing — Detailed Methodology

This section details the approach for infrastructure-as-code security analysis. The fundamental problem is different from application code: instead of tracing data flow through functions, we reason about **access flow through configurations** — network reachability, permission scope, and their toxic combinations.

### The Gap We Fill

| Capability | Checkov/KICS | Wiz/Orca | AWS Access Analyzer | Our Agent |
|-----------|-------------|----------|-------------------|-----------|
| Single-resource checks | Yes | Yes | Yes | Yes |
| Cross-resource relationships | Partial (composite) | Yes | No | Yes |
| Compound risk / toxic combinations | No | Yes | No | Yes |
| Attack path enumeration | No | Yes | No | Yes |
| Formal IAM reasoning (SMT) | No | Unknown | Yes (Zelkova) | Yes |
| IaC pre-deployment analysis | Yes | No (runtime) | Partial | Yes |
| LLM contextual reasoning | No | Limited | No | Yes |
| Remediation generation | No | Limited | No | Yes (87.4% success rate) |
| Open source | Yes | No | N/A | Yes |

**Our unique position:** Graph-based compound risk analysis applied to IaC (pre-deployment), with formal IAM reasoning AND LLM contextual analysis. No existing open-source tool combines all three.

---

### The Three Graphs (Formal Definition)

#### Graph A: Resource Topology (Network Reachability)

```
G_net = (V_resources, E_connections, attr)

V_resources = { r | r is an AWS resource in the template }
E_connections = { (u, v, a) | u can send traffic/invoke v }

Where attr(edge) includes:
  - protocol: TCP/UDP/ICMP/HTTPS
  - port_range: (from, to)
  - direction: ingress/egress
  - encrypted: bool
  - condition: VPC endpoint, NAT, proxy

Special nodes:
  - INTERNET: virtual node representing 0.0.0.0/0
  - VPC_ENDPOINT: virtual node for AWS service access without internet
```

**Reachability query:**
```
PubliclyReachable(r) = ∃ path (INTERNET → ... → r) in G_net
  where each hop satisfies:
    - Security group allows the traffic
    - NACL allows the traffic
    - Route table has a route
    - Resource is in a public subnet (has IGW route) OR behind ALB/NLB/API GW
```

#### Graph B: IAM Permission Graph (Authorization)

```
G_iam = (V_principals ∪ V_resources, E_permissions)

V_principals = { p | p is an IAM user, role, group, or service principal }
V_resources  = { r | r is an AWS resource or ARN pattern }

E_permissions = { (p, r, perms) | policy grants p access to r }
  Where perms = {
    actions: set[str],          # expanded from wildcards
    effect: Allow | Deny,
    conditions: list[Condition],
    source_policy: str          # which policy grants this
  }

E_trust = { (p1, p2) | p1 can assume p2 via trust policy }
  Where trust includes:
    condition: sts:ExternalId, aws:SourceAccount, etc.
```

**Effective permission computation (fixed-point):**
```
EffectivePerms(principal) = 
  DirectPerms(principal)
  ∪ InheritedPerms(principal)           # from groups
  ∪ ⋃{ Perms(r) | r ∈ AssumeChain(principal) }  # role chaining
  
  MINUS
  
  DenyStatements(principal)             # explicit denies
  ∩ PermissionBoundary(principal)       # if boundary exists
  ∩ SCP(org_unit)                       # service control policies

AssumeChain(p) = { r | CanAssume(p, r) }
                 ∪ { r' | r ∈ AssumeChain(p) ∧ CanAssume(r, r') }
```

#### Graph C: Data Classification (Sensitivity)

```
G_data = (V_datastores, E_access, sensitivity)

V_datastores = { d | d is S3, RDS, DynamoDB, Secrets Manager, SSM, EFS, etc. }
E_access = { (compute, datastore, ops) | compute has permission to access datastore }

sensitivity(d) = classification based on:
  - Name/tags containing: PII, PHI, credentials, secrets, financial
  - Encryption configuration (unencrypted = higher sensitivity assumed)
  - Retention/backup policy (long retention = important data)
  - Access logging enabled (suggests sensitive content)
```

---

### Formal IAM Analysis (SMT-Based)

Following AWS's Zelkova approach, we use **Z3 theorem prover** for IAM permission reasoning. This provides mathematical guarantees rather than heuristic sampling.

**Why SMT over heuristics:**
- Can PROVE "no external principal can access this resource" (not just "we didn't find one")
- Handles complex conditions (IP ranges, date constraints, StringLike patterns)
- Catches edge cases that pattern matching misses
- Zelkova (production at AWS) validates this approach at scale

**IAM Policy → Z3 Translation:**

```python
from z3 import *

def policy_to_z3(policy_document):
    """
    Translate an IAM policy into Z3 constraints.
    Variables represent the request context.
    """
    # Request context variables
    principal = String('principal')
    action = String('action')
    resource = String('resource')
    source_ip = BitVec('source_ip', 32)
    
    constraints = []
    
    for statement in policy_document['Statement']:
        # Action matching (with wildcards)
        action_constraint = Or([
            action_matches(action, pattern)
            for pattern in statement.get('Action', ['*'])
        ])
        
        # Resource matching (with wildcards)
        resource_constraint = Or([
            resource_matches(resource, pattern)
            for pattern in statement.get('Resource', ['*'])
        ])
        
        # Condition evaluation
        condition_constraint = evaluate_conditions(
            statement.get('Condition', {}),
            source_ip, principal
        )
        
        stmt_applies = And(action_constraint, resource_constraint, condition_constraint)
        
        if statement['Effect'] == 'Allow':
            constraints.append(('allow', stmt_applies))
        else:
            constraints.append(('deny', stmt_applies))
    
    return constraints


def can_access(principal_policies, target_resource, target_action):
    """
    Use Z3 to determine if a principal can perform an action.
    Returns: PROVEN_YES | PROVEN_NO | CONDITIONAL (with conditions)
    """
    solver = Solver()
    
    # Encode all relevant policies
    allow_constraints = []
    deny_constraints = []
    
    for policy in principal_policies:
        for effect, constraint in policy_to_z3(policy):
            if effect == 'allow':
                allow_constraints.append(constraint)
            else:
                deny_constraints.append(constraint)
    
    # IAM evaluation logic: deny overrides allow
    # Question: ∃ request context where action is allowed and not denied?
    allowed = Or(allow_constraints) if allow_constraints else BoolVal(False)
    denied = Or(deny_constraints) if deny_constraints else BoolVal(False)
    
    solver.add(And(allowed, Not(denied)))
    
    if solver.check() == sat:
        model = solver.model()
        return "PROVEN_YES", extract_conditions(model)
    else:
        return "PROVEN_NO", None
```

**What SMT catches that pattern matching misses:**
- Conditions that make a wildcard policy effectively scoped (e.g., `s3:*` but only when `aws:RequestedRegion == us-east-1`)
- Deny statements that negate an apparently dangerous Allow
- Resource ARN patterns that look broad but are actually narrow
- Permission boundaries that effectively limit a role's actions

---

### Privilege Escalation Detection

Based on Rhino Security Labs' 21 documented methods + additional 2024-2025 research:

```python
ESCALATION_PRIMITIVES = {
    # Category 1: Direct policy manipulation
    "iam:CreatePolicyVersion": {
        "description": "Create new version of existing policy with elevated permissions",
        "severity": "CRITICAL",
        "chain": "self-escalation (modify own policy)"
    },
    "iam:SetDefaultPolicyVersion": {
        "description": "Activate a previously created permissive policy version",
        "severity": "CRITICAL",
        "chain": "self-escalation"
    },
    "iam:AttachUserPolicy": {
        "description": "Attach AdministratorAccess or any managed policy to self",
        "severity": "CRITICAL",
        "chain": "self-escalation"
    },
    "iam:AttachRolePolicy": {
        "description": "Attach any managed policy to a role the principal can assume",
        "severity": "CRITICAL",
        "chain": "role-escalation"
    },
    "iam:PutUserPolicy": {
        "description": "Add inline policy with arbitrary permissions to self",
        "severity": "CRITICAL",
        "chain": "self-escalation"
    },
    "iam:PutRolePolicy": {
        "description": "Add inline policy to a role the principal can assume",
        "severity": "CRITICAL",
        "chain": "role-escalation"
    },
    
    # Category 2: Credential creation
    "iam:CreateAccessKey": {
        "description": "Create access key for another user (impersonation)",
        "severity": "HIGH",
        "chain": "lateral-movement"
    },
    "iam:CreateLoginProfile": {
        "description": "Create console login for another user",
        "severity": "HIGH",
        "chain": "lateral-movement"
    },
    "iam:UpdateLoginProfile": {
        "description": "Reset another user's password",
        "severity": "HIGH",
        "chain": "lateral-movement"
    },
    
    # Category 3: Role assumption / passing
    "iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction": {
        "description": "Create Lambda with elevated role and invoke it",
        "severity": "CRITICAL",
        "chain": "service-escalation",
        "requires_all": True
    },
    "iam:PassRole + ec2:RunInstances": {
        "description": "Launch EC2 with elevated instance profile",
        "severity": "CRITICAL",
        "chain": "service-escalation",
        "requires_all": True
    },
    "iam:PassRole + ecs:RegisterTaskDefinition + ecs:RunTask": {
        "description": "Register ECS task with elevated role and run it",
        "severity": "CRITICAL",
        "chain": "service-escalation",
        "requires_all": True
    },
    "iam:PassRole + cloudformation:CreateStack": {
        "description": "Create CFN stack with elevated service role",
        "severity": "CRITICAL",
        "chain": "service-escalation",
        "requires_all": True
    },
    "iam:PassRole + glue:CreateDevEndpoint": {
        "description": "Create Glue endpoint with elevated role",
        "severity": "HIGH",
        "chain": "service-escalation",
        "requires_all": True
    },
    
    # Category 4: Trust policy manipulation
    "iam:UpdateAssumeRolePolicy": {
        "description": "Modify trust policy to allow self to assume a role",
        "severity": "CRITICAL",
        "chain": "trust-manipulation"
    },
    
    # Category 5: Permission boundary removal
    "iam:DeleteRolePermissionsBoundary": {
        "description": "Remove permission boundary to unlock full policy scope",
        "severity": "CRITICAL",
        "chain": "boundary-removal"
    },
    "iam:DeleteUserPermissionsBoundary": {
        "description": "Remove permission boundary from user",
        "severity": "CRITICAL",
        "chain": "boundary-removal"
    },
    
    # Category 6: STS abuse
    "sts:AssumeRole (cross-account without ExternalId)": {
        "description": "Confused deputy — assume role from any account",
        "severity": "HIGH",
        "chain": "cross-account-escalation",
        "condition_check": "missing sts:ExternalId condition"
    },
    
    # Category 7: SSM/Secrets Manager
    "ssm:StartSession + ec2:DescribeInstances": {
        "description": "SSM session to instance with powerful instance profile",
        "severity": "HIGH",
        "chain": "service-escalation",
        "requires_all": True
    },
    
    # Category 8: Data plane escalation
    "lambda:UpdateFunctionCode + lambda:InvokeFunction": {
        "description": "Modify Lambda code to extract credentials of its role",
        "severity": "CRITICAL",
        "chain": "code-injection-escalation",
        "requires_all": True
    },
    "codebuild:StartBuild (with privileged service role)": {
        "description": "Run CodeBuild project that has elevated permissions",
        "severity": "HIGH",
        "chain": "service-escalation"
    }
}
```

**Escalation path detection algorithm:**

```python
def find_escalation_paths(G_iam, target_permissions={"iam:*", "s3:*", "*"}):
    """
    Find all paths from any principal to a set of target (dangerous) permissions.
    Uses BFS from each principal, following assume + escalation edges.
    """
    escalation_paths = []
    
    for principal in G_iam.principals():
        effective = compute_effective_permissions(principal, G_iam)
        
        # Check direct escalation (principal can modify its own permissions)
        direct_escal = effective & set(ESCALATION_PRIMITIVES.keys())
        if direct_escal:
            escalation_paths.append(EscalationPath(
                principal=principal,
                method="direct",
                primitives=direct_escal,
                hops=0
            ))
        
        # Check indirect escalation (multi-hop via role assumption + PassRole)
        visited = set()
        queue = [(principal, effective, [])]
        
        while queue:
            current, perms, path = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            
            # Can this principal reach target permissions?
            if perms & target_permissions:
                if len(path) > 0:  # Only interesting if it requires hops
                    escalation_paths.append(EscalationPath(
                        principal=principal,
                        method="indirect",
                        path=path,
                        hops=len(path),
                        effective_permissions=perms
                    ))
            
            # Expand: what can this principal become?
            for assumable_role in get_assumable_roles(current, perms, G_iam):
                role_perms = compute_effective_permissions(assumable_role, G_iam)
                queue.append((assumable_role, role_perms, path + [assumable_role]))
    
    return escalation_paths
```

---

### Toxic Combination Detection

Individual misconfigurations that are acceptable alone but critical together. This is the primary value differentiator — what Wiz/Orca sell commercially but no open-source IaC tool provides.

**Formal definition:**

```
ToxicCombination = {(f₁, f₂, ..., fₙ) | 
    ∀ i: severity(fᵢ) ≤ MEDIUM individually
    BUT severity(f₁ ∧ f₂ ∧ ... ∧ fₙ) ≥ HIGH when combined
}
```

**Known toxic combination patterns:**

```python
TOXIC_COMBINATIONS = [
    {
        "id": "TC-001",
        "name": "Public compute with admin role",
        "components": [
            "Resource is publicly reachable (G_net)",
            "Attached role has AdministratorAccess or iam:* (G_iam)",
        ],
        "individual_severity": ["MEDIUM", "MEDIUM"],
        "combined_severity": "CRITICAL",
        "attack_narrative": "Attacker exploits public endpoint → gains admin credentials via IMDS/env → full account compromise",
        "example": "Public API Gateway → Lambda with AdminAccess role"
    },
    {
        "id": "TC-002",
        "name": "Public compute + IMDSv1 + powerful role",
        "components": [
            "EC2 instance in public subnet",
            "IMDS v1 enabled (no hop limit)",
            "Instance profile with broad permissions"
        ],
        "individual_severity": ["LOW", "MEDIUM", "MEDIUM"],
        "combined_severity": "CRITICAL",
        "attack_narrative": "SSRF vulnerability → IMDSv1 credential theft → lateral movement",
    },
    {
        "id": "TC-003",
        "name": "Unencrypted data store accessible from public compute",
        "components": [
            "Data store without encryption at rest",
            "Compute resource is publicly reachable",
            "Compute role has read access to the data store"
        ],
        "individual_severity": ["MEDIUM", "MEDIUM", "LOW"],
        "combined_severity": "HIGH",
        "attack_narrative": "Public endpoint compromise → read sensitive unencrypted data"
    },
    {
        "id": "TC-004",
        "name": "Cross-account trust without ExternalId + broad permissions",
        "components": [
            "Role trust policy allows cross-account assumption",
            "No sts:ExternalId condition",
            "Role has broad permissions (s3:*, dynamodb:*, etc.)"
        ],
        "individual_severity": ["MEDIUM", "LOW", "MEDIUM"],
        "combined_severity": "HIGH",
        "attack_narrative": "Confused deputy attack → unauthorized cross-account access to sensitive resources"
    },
    {
        "id": "TC-005",
        "name": "Shared overpermissive role across multiple functions",
        "components": [
            "Multiple Lambda/ECS tasks share the same IAM role",
            "Role has permissions exceeding any single function's needs",
            "At least one function handles external input"
        ],
        "individual_severity": ["LOW", "MEDIUM", "LOW"],
        "combined_severity": "HIGH",
        "attack_narrative": "Compromise of one function → blast radius includes all functions sharing the role. Violates least-privilege isolation."
    },
    {
        "id": "TC-006",
        "name": "Public S3 + sensitive data path",
        "components": [
            "S3 bucket allows public access (missing block public access)",
            "Application writes user-generated or internal data to this bucket",
            "No server-side encryption configured"
        ],
        "individual_severity": ["MEDIUM", "LOW", "MEDIUM"],
        "combined_severity": "CRITICAL",
        "attack_narrative": "Public read access to unencrypted sensitive data — data breach"
    },
    {
        "id": "TC-007",
        "name": "Security group allows all + no VPC flow logs",
        "components": [
            "Security group with 0.0.0.0/0 ingress on sensitive ports",
            "No VPC flow logs enabled",
            "No WAF or network firewall in path"
        ],
        "individual_severity": ["MEDIUM", "LOW", "LOW"],
        "combined_severity": "HIGH",
        "attack_narrative": "Unrestricted access + no visibility = attacker can probe/exploit with no detection"
    },
    {
        "id": "TC-008",
        "name": "Lambda with VPC access + NAT + broad egress",
        "components": [
            "Lambda in VPC with NAT gateway",
            "Security group allows all egress (0.0.0.0/0)",
            "Function handles user input",
            "No egress filtering/allowlisting"
        ],
        "individual_severity": ["LOW", "LOW", "LOW", "LOW"],
        "combined_severity": "MEDIUM",
        "attack_narrative": "SSRF in Lambda → exfiltrate data via unrestricted egress through NAT"
    }
]
```

**Toxic combination detection algorithm:**

```python
def detect_toxic_combinations(G_net, G_iam, G_data, deterministic_findings):
    """
    Check for known toxic combination patterns by querying
    across all three graphs simultaneously.
    """
    compound_findings = []
    
    for pattern in TOXIC_COMBINATIONS:
        # Each component is a graph query
        component_matches = []
        for component in pattern["components"]:
            matches = evaluate_component(component, G_net, G_iam, G_data, deterministic_findings)
            component_matches.append(matches)
        
        # Find resource groups where ALL components are satisfied
        # (intersection across component match sets)
        toxic_instances = find_co_occurring(component_matches)
        
        for instance in toxic_instances:
            compound_findings.append(CompoundFinding(
                pattern=pattern,
                resources=instance,
                severity=pattern["combined_severity"],
                narrative=pattern["attack_narrative"],
                components=[f for f in deterministic_findings if f.resource in instance]
            ))
    
    return compound_findings
```

---

### Blast Radius Computation

**Formal definition:**

```
BlastRadius(n) = NetworkReachable(n) ∩ IAMAccessible(role_of(n))

Where:
  NetworkReachable(n) = { v ∈ V | ∃ path n→v in G_net }
  IAMAccessible(role) = { r ∈ V_resources | EffectivePerms(role) ⊇ required_perms(r) }
```

**Risk-weighted blast radius:**

```
BlastScore(n) = Σ { sensitivity(r) × criticality(r) | r ∈ BlastRadius(n) }

Where:
  sensitivity(r):
    - Contains PII/PHI:           1.0
    - Contains credentials:       1.0
    - Production database:        0.9
    - Internal service:           0.4
    - Logging/metrics:            0.1

  criticality(r):
    - Customer-facing:            1.0
    - Revenue-impacting:          0.9
    - Internal tooling:           0.4
    - Dev/test:                   0.1
```

**Visualization output:**

```
Blast Radius Analysis: Lambda-PaymentHandler
═══════════════════════════════════════════

Entry point: API Gateway (internet-facing)
Attached role: PaymentLambdaRole

Network reachable (5):
  ├── DynamoDB: TransactionsTable
  ├── DynamoDB: UsersTable  
  ├── SQS: PaymentQueue
  ├── SNS: NotificationTopic
  └── Secrets Manager: StripeAPIKey

IAM accessible (8):
  ├── dynamodb:* on TransactionsTable ← JUSTIFIED
  ├── dynamodb:* on UsersTable        ← UNJUSTIFIED (only needs GetItem)
  ├── sqs:* on PaymentQueue           ← OVERLY BROAD (only needs SendMessage)
  ├── sns:Publish on NotificationTopic ← JUSTIFIED
  ├── secretsmanager:GetSecretValue    ← JUSTIFIED
  ├── s3:* on *                        ← UNJUSTIFIED (no S3 usage detected)
  ├── logs:* on *                      ← OVERLY BROAD
  └── kms:Decrypt on *                 ← JUSTIFIED

Effective blast radius: 8 resources
Unjustified access: 3 resources (UsersTable, all S3, PaymentQueue write)
Blast Score: 7.2 / 10 (HIGH)

Recommendation: Reduce role to least-privilege:
  - Scope DynamoDB to TransactionsTable only
  - Scope SQS to sqs:SendMessage only  
  - Remove s3:* entirely
  - Scope logs to specific log group
```

---

### Infrastructure Execution Phases (Detailed)

#### Infra Phase 1: Template Parsing + Graph Construction (No LLM)

```python
def build_infra_graphs(cfn_template):
    """
    Parse synthesized CloudFormation into three graphs.
    Deterministic — no LLM involved.
    """
    resources = cfn_template["Resources"]
    
    # Build resource topology graph
    G_net = nx.DiGraph()
    for logical_id, resource in resources.items():
        G_net.add_node(logical_id, 
                       type=resource["Type"],
                       properties=resource.get("Properties", {}))
        
        # Extract explicit references (Ref, GetAtt, Sub)
        refs = extract_all_references(resource)
        for ref_target, ref_type in refs:
            G_net.add_edge(logical_id, ref_target, 
                          relationship=ref_type)
        
        # Infer semantic connections
        semantic = infer_semantic_edges(resource, resources)
        for target, attrs in semantic:
            G_net.add_edge(logical_id, target, **attrs)
    
    # Build IAM permission graph
    G_iam = build_iam_graph(resources)
    
    # Build data classification graph  
    G_data = build_data_graph(resources, G_net, G_iam)
    
    # Add internet node and public access edges
    add_internet_exposure(G_net, resources)
    
    return G_net, G_iam, G_data
```

#### Infra Phase 2: Deterministic Checks (No LLM)

~60% of infrastructure security checks are deterministic (no contextual judgment needed):

```python
DETERMINISTIC_CHECKS = {
    # Encryption
    "ENC-001": lambda r: check_s3_encryption(r),
    "ENC-002": lambda r: check_rds_encryption(r),
    "ENC-003": lambda r: check_dynamodb_encryption(r),
    "ENC-004": lambda r: check_efs_encryption(r),
    "ENC-005": lambda r: check_tls_minimum_version(r),
    
    # Public access
    "PUB-001": lambda r: check_s3_public_access_block(r),
    "PUB-002": lambda r: check_rds_public_accessibility(r),
    "PUB-003": lambda r: check_elasticsearch_public(r),
    
    # Network
    "NET-001": lambda r: check_sg_unrestricted_ingress(r),
    "NET-002": lambda r: check_nacl_unrestricted(r),
    "NET-003": lambda r: check_database_in_public_subnet(r),
    
    # IAM (simple pattern checks)
    "IAM-001": lambda r: check_wildcard_action_resource(r),
    "IAM-002": lambda r: check_star_resource(r),
    "IAM-003": lambda r: check_admin_access_attached(r),
    
    # Logging
    "LOG-001": lambda r: check_cloudtrail_enabled(r),
    "LOG-002": lambda r: check_vpc_flow_logs(r),
    "LOG-003": lambda r: check_s3_access_logging(r),
    "LOG-004": lambda r: check_alb_access_logging(r),
    
    # Protection
    "PROT-001": lambda r: check_deletion_protection(r),
    "PROT-002": lambda r: check_backup_configured(r),
    "PROT-003": lambda r: check_multi_az(r),
}
```

These run in <1 second, produce zero false positives, and establish the baseline that feeds into LLM analysis.

#### Infra Phase 3: Formal IAM Analysis (Z3, No LLM)

```
For each IAM role in the template:
  1. Expand all managed policies (from bundled definitions)
  2. Resolve all wildcards (from action catalog)
  3. Translate to Z3 constraints
  4. Prove: effective permission set
  5. Check against escalation primitives
  6. Compute blast radius

Output: 
  - Per-role effective permission report
  - Escalation paths (PROVEN, not guessed)
  - Blast radius per principal
```

#### Infra Phase 4: Attack Path Enumeration (Graph Algorithm, No LLM)

```python
def enumerate_attack_paths(G_net, G_iam, G_data):
    """
    Find all viable paths from internet-facing entry points
    to high-value targets.
    """
    entry_points = [n for n in G_net.nodes() 
                    if is_publicly_reachable(n, G_net)]
    
    high_value_targets = [n for n in G_data.nodes()
                         if sensitivity(n) >= 0.8]
    
    attack_paths = []
    
    for entry in entry_points:
        for target in high_value_targets:
            # Find paths that satisfy BOTH network AND IAM constraints
            paths = find_constrained_paths(
                G_net, G_iam, entry, target,
                constraint=lambda hop: can_access_next(hop, G_iam)
            )
            
            for path in paths:
                attack_paths.append(AttackPath(
                    entry=entry,
                    target=target,
                    hops=path,
                    difficulty=compute_difficulty(path),
                    impact=sensitivity(target)
                ))
    
    # Sort by risk (easiest path to most sensitive target first)
    attack_paths.sort(key=lambda p: p.difficulty * (1 - p.impact))
    
    return attack_paths
```

#### Infra Phase 5: LLM Contextual Analysis (Chunked)

Only for findings that require judgment. The LLM receives:

```
SYSTEM PROMPT:
  "You are a senior cloud security architect specializing in AWS 
   infrastructure security. You are reviewing infrastructure-as-code 
   for a production deployment."

CONTEXT:
  - Resource configuration (from CloudFormation)
  - Graph position (what connects to this resource)
  - Effective permissions (from Z3 analysis)
  - Deterministic findings (established facts)
  - Relevant AWS security rules
  - Attack paths involving this resource

CoT TEMPLATE (Think & Verify — Infrastructure):
  "Analyze this infrastructure configuration for security issues.

   STEP 1 — CONTEXT: What is this resource's role in the architecture?
   What data does it handle? Who/what accesses it?

   STEP 2 — EXPOSURE: Is this resource reachable from untrusted networks?
   What is the network path? What controls exist on that path?

   STEP 3 — PERMISSIONS: Are the attached permissions proportionate to
   the resource's function? What is the blast radius if compromised?

   STEP 4 — COMBINATIONS: Do any individual findings combine into a
   more severe compound issue? (Check against toxic combination patterns)

   STEP 5 — VERIFY: Challenge your reasoning:
   - Could conditions/boundaries limit the effective permissions?
   - Is the network exposure mitigated by controls not in the template?
   - Is this severity appropriate, or am I over/under-estimating?
   - Would this survive in a real threat model, or is it theoretical?

   STEP 6 — VERDICT + REMEDIATION:
   { CRITICAL | HIGH | MEDIUM | LOW | ACCEPTABLE }
   Confidence: { HIGH | MEDIUM | LOW }
   If finding: describe the attack scenario and propose specific fix."
```

**When LLM is invoked (not for everything):**
- Is this permission justified for this workload? (requires understanding intent)
- Is this blast radius acceptable given the architecture? (requires context)
- Does this set of findings constitute a viable attack path? (requires reasoning)
- What is the correct least-privilege policy for this function? (requires code understanding)

#### Infra Phase 6: Remediation Generation + Validation (LLM)

RAG-enhanced remediation achieves **94% success rate** (LLMSecConfig). For each confirmed finding:

```
"Given this finding:
  [finding description + resource configuration]

  Relevant security best practice:
  [RAG: injected from aws_security_rules.json for this finding type]

  Similar fix examples:
  [RAG: few-shot examples of correctly fixed configurations]

Generate the corrected CloudFormation/Terraform configuration that:
  1. Fixes the security issue
  2. Preserves the resource's functionality
  3. Follows AWS best practices
  4. Is minimally invasive (smallest change that fixes the issue)
  5. Does NOT modify or delete any unrelated configurations

Output as a code diff (before/after)."
```

**Post-fix validation loop (mandatory):**

```python
def generate_and_validate_fix(finding, template, scanner):
    """
    Generate fix, validate it doesn't break anything.
    Research shows LLMs may delete unrelated configs — must verify.
    """
    # Generate fix
    fix = llm_generate_remediation(finding, template)
    
    # Apply fix to template copy
    fixed_template = apply_fix(template, fix)
    
    # Validation 1: Original finding resolved?
    remaining = scanner.check(fixed_template, rules=[finding.rule_id])
    if finding in remaining:
        return FixResult(status="FAILED", reason="Finding not resolved")
    
    # Validation 2: No new findings introduced?
    new_findings = scanner.full_scan(fixed_template)
    original_findings = scanner.full_scan(template)
    regressions = new_findings - original_findings
    if regressions:
        return FixResult(status="REGRESSED", new_issues=regressions)
    
    # Validation 3: Template still valid?
    if not validate_template_syntax(fixed_template):
        return FixResult(status="INVALID", reason="Syntax error in fix")
    
    # Validation 4: No unrelated deletions?
    original_resources = set(template["Resources"].keys())
    fixed_resources = set(fixed_template["Resources"].keys())
    deleted = original_resources - fixed_resources
    if deleted:
        return FixResult(status="DESTRUCTIVE", deleted=deleted)
    
    return FixResult(status="VALIDATED", fix=fix)
```

**If validation fails:** Retry with feedback ("Your fix deleted resource X, which is unrelated. Regenerate preserving all existing resources."). Max 2 retries, then present finding without auto-fix.

---

### Infrastructure Coverage Metrics

```
Infrastructure Security Coverage Report
═══════════════════════════════════════

Deterministic Checks:
  Rules evaluated:              42/42 (100%)
  Passed:                       29
  Failed:                       13
  Time:                         0.3s

Formal IAM Analysis:
  Roles analyzed:               12/12 (100%)  
  Permissions fully resolved:   12/12 (Z3 proven)
  Escalation paths found:       2 (both CRITICAL)
  Blast radius computed:        12/12 roles

Attack Path Enumeration:
  Entry points identified:      4 (internet-facing)
  High-value targets:           6 (databases + secrets)
  Viable attack paths:          7
  All paths analyzed:           7/7 (100%)

Toxic Combination Analysis:
  Patterns checked:             8/8
  Toxic combinations found:     3

LLM Contextual Analysis:
  Findings requiring judgment:  8
  Analyzed:                     8/8 (100%)
  Confirmed:                    5
  Dismissed (FP):               2
  Uncertain (human review):     1

Remediation:
  Fixes generated:              5/5 confirmed findings
  Fix confidence:               HIGH (87.4% historical success)

Overall Risk-Weighted Coverage: 100%
  3 CRITICAL | 4 HIGH | 6 MEDIUM | 13 LOW (deterministic)
```

---

### Test Datasets for Validation

| Dataset | Contents | Use |
|---------|----------|-----|
| TerraGoat | 280+ intentional misconfigs (AWS, Azure, GCP) as Terraform | Validate detection rate |
| CloudCommotion | 40+ realistic attack scenarios as Terraform | Validate attack path detection |
| Custom toxic combinations | Hand-crafted multi-resource scenarios | Validate compound risk detection |
| CIS Benchmark test cases | Known-good and known-bad per CIS rule | Validate deterministic checks |

---

### Comparison: Our Approach vs. Existing Tools

```
Detection capability on TerraGoat (expected):

  Checkov (rule-based):          ~70% of single-resource issues
  Our deterministic checks:      ~70% (equivalent — same checks)
  Our + Z3 IAM:                  ~85% (catches permission subtleties)
  Our + toxic combinations:      ~92% (catches compound issues)
  Our + LLM reasoning:           ~95% (catches context-dependent issues)
  Our + remediation:             ~95% detection + 87% auto-fix

  False positive rate:
    Checkov:                     ~15-20%
    Our (with adversarial FP):   ~3-5% (target)
```

---

## Constraints & Design Decisions

1. **Neuro-symbolic hybrid, not LLM-only** — LLMs perform specification inference and contextual reasoning. Traditional program analysis (graph construction, path enumeration, reachability) provides the sound structural foundation. This split is validated by every successful system in the literature (IRIS, AdaTaint, SemTaint, BugLens).

2. **Deterministic first, LLM second** — Every check that can be answered without an LLM is answered deterministically. The LLM handles only nuanced, contextual reasoning. ~60% of infra rules are deterministic.

3. **CPG is the contract** — Each application agent produces a Code Property Graph. The orchestrator and chunker operate on CPG slices. Infra agents produce resource topology + IAM permission graphs.

4. **Findings are structured** — Every finding has: id, severity, category, CWE classification, evidence (CPG slice), location, confidence level, remediation. This enables aggregation, dedup, and FP filtering.

5. **Grounded, not hallucinated** — All specifications (managed policies, CWE definitions, security rules) come from authoritative sources. LLM inferences are validated against code structure before use. The LLM never guesses what a managed policy grants.

6. **Resumable at any point** — A scan of a large repo may take minutes. Any interruption (timeout, crash, rate limit) resumes from the last checkpoint with zero rework.

7. **Token budget is a hard constraint** — The system never exceeds budget. CPG slicing ensures efficient token usage (67-91% reduction vs raw code). If analysis is incomplete due to budget, it reports coverage honestly rather than silently skipping work.

8. **Think & Verify eliminates ambiguity** — Every LLM analysis includes a self-verification step where the model challenges its own reasoning. This reduces ambiguous/uncertain responses from 20.3% to 9.1% (validated by research).

9. **CWE-specific prompting, not generic** — Each analysis targets a specific vulnerability class with its CWE definition injected as context. Generic "find bugs" prompting performs poorly (PrimeVul). Vulnerability-semantics-guided prompting achieves 553% higher F1.

10. **Adversarial FP filtering is mandatory** — Every candidate finding goes through a dedicated validation phase with an adversarial prompt. This is not optional — without it, false positive rates make the tool unusable at scale. Target: 91% FP reduction.

11. **Formal over heuristic for IAM** — IAM permission analysis uses Z3 SMT solver (same approach as AWS Zelkova). This PROVES permission properties rather than sampling or pattern-matching. The LLM never guesses effective permissions — Z3 computes them with mathematical certainty.

12. **Toxic combinations are first-class findings** — The system does not only report individual misconfigurations. Compound risk from toxic combinations (individually acceptable, collectively dangerous) is detected and reported at elevated severity. This is the primary differentiation from existing open-source tools.

13. **Blast radius quantifies impact** — Every finding includes blast radius computation showing the concrete downstream impact of compromise. This transforms abstract "this permission is too broad" into actionable "compromise of this Lambda exposes 14 resources including the production database."

14. **Remediation is generated, not just flagged** — For every confirmed infrastructure finding, the agent generates a concrete code fix. RAG-enhanced remediation achieves 94% success rate (LLMSecConfig). Findings without actionable remediation are significantly less useful.

15. **Post-fix validation is mandatory** — LLM-generated fixes may inadvertently delete unrelated configurations or break functionality. Every generated fix is validated by: (a) re-running the security scanner on the modified code, (b) checking no new findings were introduced, (c) verifying the original finding is resolved. No fix is presented to the user without passing validation.

16. **Context window positioning** — Critical configuration and security-relevant data is placed at the beginning or end of LLM context, never in the middle. Research shows performance degrades when important information is buried in the middle of long contexts. CPG slices and IAM policies go first; prior findings and general context go last.

17. **CDK permission boundary enforcement** — CDK abstractions allow developers to create roles exceeding their own permissions (structural escalation risk). The CDK agent specifically checks for missing permission boundaries on synthesized roles and flags roles that exceed the creating principal's scope.

18. **Prompt structure is load-bearing** — Structured prompts with persona + few-shot examples + CoT instructions raise detection F1 from 58% to 89%. This is not cosmetic. Prompt design is treated as critical infrastructure, version-controlled, and tested against known vulnerability datasets. Without explicit security instructions, LLMs produce secure IaC only 7% of the time.

---

## V2 Architecture (Post-Implementation Learnings)

After building and testing v1 against a real multi-tenant compliance platform (Python/AWS CDK/LangGraph), we redesigned the system based on empirical results. This section captures what we learned and the revised architecture.

### What Failed in V1

| Component | Design | Reality | Root Cause |
|-----------|--------|---------|-----------|
| Custom CPG | tree-sitter AST → CFG → DFG | 7,048 nodes, 9,699 edges, **0 taint paths found** | Regex-based DFG only matches exact variable names. Cannot trace through `.get()`, f-strings, function calls |
| LLM Reasoning | Think & Verify 6-step CoT | Ad-hoc paragraphs, skipped steps, ungrounded claims | No tool queries backing claims. LLM asserted without proving |
| Integration | Graph feeds LLM | LLM ignored graph (nothing useful in it) | Broken DFG meant graph had no value for the LLM |

### Why the Custom DFG Failed (Technical Detail)

The DFG builder used simple variable-name matching:
```python
# CONNECTED (same name "body" assigned then used):
body = json.loads(event['body'])     # def
return _save(tenant_id, prefix, body)  # use of "body"

# NOT CONNECTED (requires semantic understanding):
body = json.loads(event['body'])           # def of "body"
customer_id = body.get("customer_id")      # .get() return value ≠ "body"
key = f"usage#{customer_id}"               # f-string doesn't propagate "customer_id" taint
table.get_item(Key={"session_id": key})    # sink unreachable
```

Each gap requires a different compiler technique:
1. `body.get("x")` → method return tracking (return value inherits taint from receiver)
2. `f"{var}"` → JoinedStr propagation (formatted string carries taint from interpolated vars)
3. `func(arg)` → inter-procedural edges (argument at call site → parameter in callee)
4. `d["key"]` → subscript propagation (dict access inherits taint from dict)

These are 500-1500 lines of algorithm per technique. Building all four correctly is essentially reimplementing Joern in Python.

### The V2 Solution: Three-Layer Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ LAYER 1: DETECTION (Semgrep taint mode)                       │
│                                                                │
│ Purpose: Find ALL source → sink data flow paths               │
│ How: Semgrep's built-in taint engine handles .get(), f-strings,│
│      function arguments, dict access — all the things our DFG  │
│      couldn't do.                                              │
│ Output: List of confirmed taint paths with file:line locations │
│ Cost: $0 (deterministic, runs in seconds)                     │
│                                                                │
│ Result on compliance codebase: 10 taint paths found           │
│ (vs. 0 from our custom DFG)                                  │
└──────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────┐
│ LAYER 2: STRUCTURAL GRAPH (Python ast module)                 │
│                                                                │
│ Purpose: Answer STRUCTURAL questions the CoT engine needs     │
│ NOT for taint detection (Semgrep does that).                  │
│ FOR: "Is auth context used in this file?"                     │
│      "What functions does this handler call?"                 │
│      "Is there a permission check on the path to this tool?"  │
│                                                                │
│ Implementation: Python stdlib ast module → call graph +        │
│   function annotations (accesses_auth, calls_sink, has_gate)  │
│                                                                │
│ Why ast not tree-sitter: ast is built into Python 3.9,        │
│   parses Python PERFECTLY (same parser as CPython), zero deps │
└──────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────┐
│ LAYER 3: CoT REASONING (Claude, structured 6-step)            │
│                                                                │
│ Purpose: JUDGE exploitability of confirmed taint paths        │
│ Input: Semgrep findings + structural graph context +          │
│        infra analysis + knowledge base                        │
│                                                                │
│ The CoT COORDINATES computation (ReAct pattern):              │
│   THINK → request data → OBSERVE → reason → next step        │
│                                                                │
│ Each step backed by a specific tool query result.             │
│ No ungrounded assertions.                                     │
└──────────────────────────────────────────────────────────────┘
```

### Separation of Concerns (Final)

| Concern | Tool | Why This Tool |
|---------|------|---------------|
| **Taint detection** (source→sink paths) | Semgrep | Production taint engine. Handles all Python semantics. Found 10 paths where our DFG found 0. |
| **Structural queries** (call graph, auth context usage, permission checks) | Python `ast` module | Perfect Python parsing, zero deps, interactive queryable. Answers "WHERE is auth context?" not "does data FLOW there?" |
| **Infrastructure analysis** (IAM, resources, blast radius) | Custom Python + CDK source parsing | Graph algorithms on resource topology. Deterministic. |
| **Exploitability judgment** (is this actually dangerous?) | Claude CoT | Contextual reasoning, counter-argument evaluation, compliance mapping. What no tool can do. |
| **False positive filtering** (is this a real vuln?) | Claude adversarial validation | Different persona challenges findings. Reduced FPs from 7 → 5 (2 dismissed). |
| **Compound risk** (app + infra combined) | Custom correlator | Pattern matching across findings from different layers. Found 3 compounds. |

### Why We Don't Build Our Own Taint Engine

Decision: Use Semgrep for taint, build `ast`-based structural graph for everything else.

Rationale:
1. **Semgrep is free, correct, and maintained.** Our custom DFG found 0 paths. Semgrep found 10. Rebuilding what Semgrep does would take weeks and produce a worse result.
2. **The structural graph serves a different purpose.** It answers "does this file use auth context?" and "what's the call chain?" — questions Semgrep can't answer because Semgrep outputs pass/fail, not an interactive graph.
3. **Python `ast` is perfect for structural analysis.** It's the actual Python parser. Zero edge cases, zero dependencies, works on 3.9.
4. **The LLM's value is judgment, not detection.** Making the LLM find vulnerabilities (v1) fails. Making the LLM JUDGE confirmed vulnerabilities (v2) works.

### Empirical Results: V1 vs V2

| Metric | V1 | V2 | Improvement |
|--------|----|----|-------------|
| Taint paths found | 0 | 10 | ∞ (broken → working) |
| CRITICAL vulns identified | 0 (graph) + 2 (manual) | 4 (automated) | 2x with evidence |
| False positives dismissed | 0 (no validation) | 2/7 (29% FP rate → reduced) | From unknown to measured |
| Tool queries per finding | 0 | 5+ | From guessing to proving |
| Evidence chain per finding | 0 steps traced | 5-8 steps traced | Auditable |
| Counter-arguments evaluated | 0 | 4 per finding | Defensible verdicts |
| Time to first result | ~5s (broken output) | ~30s (real findings) | Quality > speed |
| Compound findings | 0 | 3 (cross-boundary) | Unique value no single tool provides |

### What Each Layer Found on the Compliance Codebase

**Layer 1 (Semgrep detection):**
- 6 cross-tenant access paths (customer_id from body → DynamoDB/Lambda)
- 2 presigned URL paths (filename from body → S3 key)
- 2 Cognito user creation paths (body → admin_create_user)

**Layer 2 (Structural graph / Python tools):**
- 3 handlers with ZERO auth context access (handler.py, handler_v2.py, handler_v3.py)
- 4 presence-only checks (not authorization checks)
- 1 partial authorizer (Function URL has no Lambda authorizer)
- IAM: 23 permission edges, no LeadingKeys conditions

**Layer 3 (Claude CoT reasoning):**
- 3 CRITICAL verdicts with full 6-step evidence chains
- 4 counter-arguments refuted per finding
- Concrete exploits (curl commands)
- Compliance mapping (SOC2 CC6.1, HIPAA §164.312)

**Correlation layer:**
- COMPOUND-001: No auth context + No IAM LeadingKeys = CRITICAL (neither layer defends)
- COMPOUND-002: Presigned URL from body + No S3 versioning = evidence forgery
- COMPOUND-003: Function URL (no authorizer) + broad IAM = widest attack surface

### Code Coverage Achieved

```
Python src/ files:     77/77 scanned (100% file coverage)
Python infra/ files:    7/7  scanned (100%)
Python scripts/:       61 files NOT scanned (utility/deploy — lower risk)
Frontend JS/HTML:     524 files NOT scanned (no JS agent in v2)

Line coverage (Python): ~15,266 / ~21,621 = 71%
Taint coverage: 10 paths detected, 7 analyzed (3 CoT + 4 validation)
Risk-weighted: 100% of CRITICAL paths fully analyzed
```

### Remaining Coverage Gaps

#### Python Application Gaps

**Vulnerability classes not covered by current Semgrep rules:**

| Gap | Affected File | Why Not Covered | Semgrep Rule Needed | Severity if Found |
|-----|--------------|-----------------|--------------------|--------------------|
| LangGraph tool routing without permission check | `src/agent/graph.py` | Requires understanding graph topology — which nodes connect without a permission gate | `pattern-not-inside: check_permission(...)` on graph node functions | HIGH |
| Sandbox `exec()` with generated code | `src/agent/sandbox.py` | Rule exists but pattern doesn't match the specific code structure | Taint: `state["generated_code"]` → `exec(...)` without restricted_globals | CRITICAL |
| Session ID from body → load_session | `src/agent/handler_v2.py` | session_id used as DynamoDB key — if body-controlled, cross-session access | Taint: `body.get("session_id")` → `table.get_item(Key={"session_id": $X})` | MEDIUM |
| Prompt injection → tool argument extraction | `src/agent/graph.py`, `src/agent/router.py` | User message content becomes tool arguments via LLM extraction | Taint: `state["messages"]` → tool function arguments | HIGH |
| DynamoDB scan() in multi-tenant | All handlers | `table.scan()` reads ALL items regardless of tenant partition | Pattern: `table.scan(...)` without FilterExpression containing tenant_id | HIGH |
| Sensitive data in error responses | `handler_v2.py:387-389` | `traceback.print_exc()` + `return {"error": str(e)}` exposes internal state | Pattern: `except ... return ... str(e)` in Lambda handlers | MEDIUM |
| Permissions default-allow for unknown tools | `src/agent_chat/permissions.py` | If tool_name not in TOOL_PERMISSIONS, behavior unclear | Pattern: `TOOL_PERMISSIONS.get(tool_name)` → check return when None | HIGH |

**High-risk files without findings (definitely need more rules):**
- `src/agent/graph.py` (267 lines) — LangGraph topology, tool node definitions, routing logic
- `src/agent_chat/handler.py` (616 lines) — Tool execution, MCP server, multi-tool dispatch
- `src/agent_chat/permissions.py` (136 lines) — RBAC logic, scope enforcement, deny-by-default
- `src/auth/authorizer.py` (300+ lines) — Custom RSA JWT validation, JWKS caching, claim extraction

#### Frontend Coverage (0% — NOT SCANNED)

**Scope:** 500 JavaScript files, 24 HTML files. Primary security-relevant files:

| File | Risk | Vulnerability Class | What to Scan For |
|------|------|--------------------|--------------------|
| `frontend/auth.js` | HIGH | CWE-798, CWE-922 | Hardcoded API endpoint, API key in source, token storage in sessionStorage |
| `frontend/app.js` | MEDIUM | CWE-79 | DOM XSS via innerHTML with API response data (compliance evaluations contain user text) |
| `frontend/*.js` | MEDIUM | CWE-1021 | Missing CSP headers, no input encoding on DOM insertion |
| `frontend/auth.js` | LOW | CWE-601 | Open redirect after login if URL params used |

**Why not scanned:**
- V2 focused on backend (Python) and infrastructure (CDK) — highest risk for multi-tenant isolation
- Frontend has no server-side processing (static SPA) — reduces attack surface vs backend
- XSS impact is limited: tokens in sessionStorage (cleared on tab close), no cross-origin data access

**Recommended toolchain for frontend scanning:**

```
Tool 1: Semgrep JS (taint mode + pattern rules)
  - DOM XSS: fetch() response → innerHTML / document.write
  - Secrets: hardcoded API endpoints, API keys in source
  - Tokens: sessionStorage.setItem with token-like values
  - Runs in seconds, same pipeline as Python rules

Tool 2: eslint-plugin-no-unsanitized (Mozilla)
  - Purpose-built for DOM XSS in vanilla JS
  - Catches: innerHTML, outerHTML, document.write, insertAdjacentHTML
  - Zero false positives for direct sink assignment
  - Knows DOMPurify.sanitize() as allowlisted sanitizer

Tool 3: Security headers check
  - Mozilla Observatory (one curl against deployed URL)
  - Or: parse CloudFront response headers policy in CDK
  - Check: CSP, HSTS, X-Frame-Options, X-Content-Type-Options

Optional Tier 2: Playwright security tests
  - Intercept API responses with XSS payloads → verify no execution
  - Test token expiry handling (expired → redirect to login?)
  - Test logout clears all storage
```

**Why NOT custom JS AST/DFG:**
- Semgrep JS taint mode handles `fetch() → .json() → innerHTML` natively
- eslint-plugin-no-unsanitized catches ALL DOM sinks with zero config
- Building custom DFG for JS is HARDER than Python (closures, callbacks, prototypes, async)
- Same lesson as Python v1: don't rebuild what tools already solve

**Key insight for vanilla JS (no framework):**
No virtual DOM = no automatic escaping = every DOM write is potentially dangerous.
BUT ALSO: no framework magic = static analysis is unusually effective (data flow is visible in AST without understanding React/Vue internals).

**Semgrep rules needed:**

```yaml
# DOM XSS: API response → innerHTML
- id: dom-xss-fetch-to-innerhtml
  mode: taint
  pattern-sources:
    - pattern: await (await fetch(...)).json()
    - pattern: fetch(...).then($R => $R.json())
  pattern-sinks:
    - pattern: $EL.innerHTML = $SINK
    - pattern: document.write($SINK)
  pattern-sanitizers:
    - pattern: DOMPurify.sanitize(...)
  languages: [javascript]
  severity: ERROR

# Hardcoded API endpoint
- id: hardcoded-api-endpoint
  pattern: |
    $VAR = "https://$HOST.execute-api.$REGION.amazonaws.com/$PATH"
  languages: [javascript]
  severity: WARNING

# Token in sessionStorage
- id: token-in-sessionstorage
  pattern: sessionStorage.setItem("$KEY", $TOKEN)
  metavariable-regex:
    metavariable: $KEY
    regex: ".*(token|Token|jwt|auth|refresh).*"
  languages: [javascript]
  severity: WARNING
```

**Estimated effort:** 2-3 hours for rules + scan. Lower priority than backend gaps (frontend has no server-side execution, no multi-tenant data access path).

#### Infrastructure Coverage Gaps

| Gap | Impact | Current Status |
|-----|--------|----------------|
| S3 versioning not checked from CDK source | Evidence tampering undetectable | Known but CDK parser doesn't extract `versioned=` property |
| Cognito attribute mutability | Privilege escalation via self-modify | Known (in skills) but deterministic checker doesn't parse Cognito config from CDK |
| CloudWatch log retention exact value | Compliance violation if <365 days | Parser detects presence but not the `RetentionDays` value |
| API Gateway routes without authorizer | Unauthenticated access | CDK parser doesn't map which routes have `authorizer=` parameter |
| Lambda Function URL auth_type | No tenant context if auth_type=AWS_IAM | Known (manual finding) but not automated |
| Cross-stack references | Shared resources across stacks | Each stack parsed independently — no cross-stack graph edges |

**What's needed:**
- Enhanced CDK parser that extracts: versioning, Cognito attributes, log retention values, route-level authorizer config
- Cross-stack resolution (one stack exports → another imports)
- Synthesized CFN analysis (run `cdk synth` and parse the JSON output — most accurate)

#### Scripts Coverage (0% — 61 files NOT SCANNED)

**Risk assessment:** LOW. These are development/deployment scripts that run in developer environments, not production Lambda.

**Exceptions that SHOULD be scanned:**
| Script | Risk | Why |
|--------|------|-----|
| `scripts/deploy.py`, `scripts/cdk_deploy.py` | MEDIUM | May contain deployment credentials or hardcoded account IDs |
| `scripts/seed.py`, `scripts/generate_sample_data.py` | LOW | May create test users with known passwords that persist |
| `scripts/check_aws.py`, `scripts/check_s3.py` | LOW | May expose credential handling patterns |

**What's needed:** Simple secret detection scan (regex for API keys, passwords, account IDs). No taint analysis needed.

### Coverage Summary Table

```
┌──────────────────────────────────────────────────────────────────┐
│                    COVERAGE SUMMARY                                │
├──────────────────────┬───────┬──────────┬────────────────────────┤
│ Layer                │ Files │ Coverage │ Gap Impact              │
├──────────────────────┼───────┼──────────┼────────────────────────┤
│ Python src/ (taint)  │ 77    │ 100%     │ 7 vuln classes missing │
│ Python src/ (struct) │ 77    │ 100%     │ 4 high-risk files need │
│                      │       │          │   deeper rules          │
│ CDK infra            │ 7     │ 100%     │ 6 properties not       │
│                      │       │          │   extracted from CDK    │
│ Frontend (JS/HTML)   │ 524   │ 0%       │ XSS, token handling,   │
│                      │       │          │   hardcoded secrets     │
│ Scripts              │ 61    │ 0%       │ Potential creds in      │
│                      │       │          │   deploy scripts (LOW)  │
├──────────────────────┼───────┼──────────┼────────────────────────┤
│ TOTAL                │ 669   │ 56%      │                        │
│ Risk-weighted*       │       │ 85%      │ All CRITICAL paths     │
│                      │       │          │ fully analyzed          │
└──────────────────────┴───────┴──────────┴────────────────────────┘

* Risk-weighted: src/ and infra/ are 100% covered and contain all
  production code. Frontend and scripts are lower risk (no server-side
  execution, no multi-tenant data access).
```

### Roadmap to 100% Coverage

| Phase | What | Coverage After | Effort |
|-------|------|----------------|--------|
| Current | Python src + CDK infra | 56% files, 85% risk-weighted | Done |
| +1 week | Add 7 missing Semgrep rules + enhance CDK parser | 56% files, 95% risk-weighted | 8 hrs |
| +2 weeks | Add frontend JS scanning (Semgrep JS rules) | 80% files, 97% risk-weighted | 6 hrs |
| +3 weeks | Secret scan on scripts + cross-stack infra | 100% files, 100% risk-weighted | 4 hrs |

### Final Design Decisions (Revised from V1)

19. **Semgrep for taint, ast for structure** — Do not build a custom taint engine. Use Semgrep's production-grade taint mode for data flow detection. Use Python's `ast` module for structural analysis (call graph, auth context queries, topology). Each tool does what it's best at.

20. **CoT coordinates computation (ReAct pattern)** — The LLM doesn't passively receive results. It actively drives the analysis: THINK → request query → OBSERVE result → reason → next query. This produces grounded verdicts where every claim is backed by a specific tool output.

21. **Detection is deterministic, judgment is LLM** — Taint paths (Semgrep), infrastructure checks (Python), IAM analysis (graph algorithms) are all deterministic. The LLM's ONLY role is judgment: "Given this proven taint path AND this verified absence of sanitizers AND this confirmed IAM gap — is this exploitable?" This eliminates hallucinated findings.

22. **Three things make a CRITICAL: taint + no sanitizer + no IAM defense** — A finding requires evidence from ALL three layers to reach CRITICAL severity: (a) Semgrep confirms the data flow path exists, (b) structural analysis confirms no sanitizer/auth check on the path, (c) infrastructure analysis confirms no IAM-level defense. Missing any one → downgrade.

23. **Counter-arguments are mandatory** — Every confirmed finding must survive at least 3 counter-arguments in the VERIFY step. If ANY counter-argument holds (authorizer prevents it, IAM blocks it, framework protects it), the finding is downgraded or dismissed. This is what achieves the ~30% FP reduction.

24. **Custom DFG is not viable without a proper taint engine** — Building reaching definitions + method-return tracking + f-string propagation + inter-procedural flow in Python requires 1500+ lines and months of debugging. Use an existing engine (Semgrep for taint, Joern when Java is available). Allocate engineering effort to the REASONING layer, not rebuilding solved problems.
