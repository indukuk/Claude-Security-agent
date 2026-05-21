# Security Agent V3 — Agent Harness Architecture

## Design Basis

Based on Microsoft MDASH (88.45% CyberGym — beat Anthropic Mythos 83.1% and GPT-5.5 81.8%) and the agent harness framework research paper. The key finding: **the harness architecture itself — not just the model — is the decisive factor in performance.**

MDASH uses 100+ specialized agents in a 3-stage pipeline. We adapt this pattern for security code analysis using Claude as the underlying model.

---

## The Three-Stage Pipeline

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    V3: GENERATOR → VERIFIER → PROVER                     │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │ STAGE 1: GENERATOR (Detection Agents)                                │ │
│  │                                                                       │ │
│  │ Multiple specialized agents scan for potential vulnerabilities.       │ │
│  │ High recall, accepts false positives. Each agent is optimized for    │ │
│  │ ONE vulnerability class.                                              │ │
│  │                                                                       │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │ │
│  │  │Cross-    │ │IAM       │ │DOM XSS   │ │Prompt    │ │LangGraph │ │ │
│  │  │Tenant    │ │Escalation│ │Scanner   │ │Injection │ │Topology  │ │ │
│  │  │Scanner   │ │Scanner   │ │          │ │Scanner   │ │Scanner   │ │ │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ │ │
│  │       │             │             │             │             │       │ │
│  │       └─────────────┼─────────────┼─────────────┼─────────────┘       │ │
│  │                     ▼             ▼             ▼                      │ │
│  │              ┌──────────────────────────────────────┐                 │ │
│  │              │  Candidate Findings (high recall)     │                 │ │
│  │              └──────────────────────┬───────────────┘                 │ │
│  └─────────────────────────────────────┼─────────────────────────────────┘ │
│                                        ▼                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │ STAGE 2: VERIFIER (Debate Agents)                                    │ │
│  │                                                                       │ │
│  │ For each candidate finding, TWO agents DEBATE:                       │ │
│  │ - Prosecutor: argues why it IS exploitable                           │ │
│  │ - Defender: argues why it is NOT exploitable                         │ │
│  │ - Judge: evaluates both arguments, renders verdict                   │ │
│  │                                                                       │ │
│  │ Uses extended thinking for deep deliberation.                        │ │
│  │                                                                       │ │
│  │  ┌───────────────────────────────────────────────────────┐          │ │
│  │  │ For each candidate:                                    │          │ │
│  │  │                                                        │          │ │
│  │  │  Prosecutor    vs    Defender                          │          │ │
│  │  │  "This IS          "This is NOT                       │          │ │
│  │  │   exploitable       exploitable                       │          │ │
│  │  │   because..."       because..."                       │          │ │
│  │  │       │                  │                             │          │ │
│  │  │       └────────┬─────────┘                             │          │ │
│  │  │                ▼                                       │          │ │
│  │  │           ┌─────────┐                                  │          │ │
│  │  │           │  JUDGE  │ → CONFIRMED | DISMISSED          │          │ │
│  │  │           └─────────┘                                  │          │ │
│  │  └───────────────────────────────────────────────────────┘          │ │
│  │                                                                       │ │
│  │  Output: Verified findings (high precision)                          │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                        ▼                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │ STAGE 3: PROVER (Exploit Agents)                                     │ │
│  │                                                                       │ │
│  │ For each verified finding, generate a PROOF:                         │ │
│  │ - Construct exploit code (curl command, script, test case)           │ │
│  │ - Validate exploit actually works (if sandbox available)             │ │
│  │ - Generate remediation + verify fix resolves the issue               │ │
│  │                                                                       │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐          │ │
│  │  │ Exploit      │  │ Remediation  │  │ Fix Validator    │          │ │
│  │  │ Generator    │  │ Generator    │  │ (re-runs scan)   │          │ │
│  │  └──────────────┘  └──────────────┘  └──────────────────┘          │ │
│  │                                                                       │ │
│  │  Output: Proven findings with exploits + fixes                       │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
│                                                                           │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Architecture Principles (From Research)

### 1. Durable Execution

Every agent step is persisted. If the system crashes mid-scan, it resumes from the last successful step — not from the beginning.

```python
@dataclass
class AgentStep:
    agent_id: str
    step_name: str
    input: dict
    output: dict | None
    status: str  # pending | running | completed | failed
    started_at: str
    completed_at: str | None
    retry_count: int = 0

class DurableExecution:
    """External state persistence — NOT in the prompt."""
    
    def execute_step(self, agent_id: str, step_name: str, fn, input_data):
        # Check if step already completed (idempotent resume)
        existing = self.state_store.get(agent_id, step_name)
        if existing and existing.status == "completed":
            return existing.output  # Already done, don't redo
        
        # Execute
        step = AgentStep(agent_id=agent_id, step_name=step_name, input=input_data, status="running")
        self.state_store.save(step)
        
        try:
            result = fn(input_data)
            step.output = result
            step.status = "completed"
        except Exception as e:
            step.status = "failed"
            step.retry_count += 1
            if step.retry_count < 3:
                return self.execute_step(agent_id, step_name, fn, input_data)  # Retry
            raise
        finally:
            self.state_store.save(step)
        
        return result
```

### 2. Explicit Contracts (JSON Schema)

Every agent declares its inputs and outputs as schemas. This enables model-swapping without rewriting.

```python
@dataclass
class AgentContract:
    """Explicit interface between agents."""
    agent_name: str
    input_schema: dict   # JSON Schema
    output_schema: dict  # JSON Schema
    tools_allowed: list[str]
    deliberation_budget: int  # tokens for extended thinking
    
# Example: Cross-Tenant Scanner
CROSS_TENANT_SCANNER_CONTRACT = AgentContract(
    agent_name="cross_tenant_scanner",
    input_schema={
        "type": "object",
        "properties": {
            "file_path": {"type": "string"},
            "source_code": {"type": "string"},
            "semgrep_findings": {"type": "array"},
            "auth_context_usage": {"type": "array"},
        },
        "required": ["file_path", "source_code"]
    },
    output_schema={
        "type": "object",
        "properties": {
            "candidates": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                        "evidence": {"type": "string"},
                        "source_line": {"type": "integer"},
                        "sink_line": {"type": "integer"},
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    }
                }
            }
        }
    },
    tools_allowed=["read_file", "grep_pattern", "query_semgrep_results", "check_auth_usage"],
    deliberation_budget=8000,  # Extended thinking tokens
)
```

### 3. DAG-Based Parallel Execution

Stage 1 agents are independent — they can all run in parallel. Stage 2 debates are per-finding (parallelizable). Only Stage 3 is sequential (exploit depends on verified finding).

```
Stage 1 (parallel):
  ┌─────────────────┐
  │ Cross-Tenant    │──┐
  │ Scanner         │  │
  └─────────────────┘  │
  ┌─────────────────┐  │
  │ IAM Escalation  │──┼──→ Candidate Pool
  │ Scanner         │  │
  └─────────────────┘  │
  ┌─────────────────┐  │
  │ DOM XSS         │──┤
  │ Scanner         │  │
  └─────────────────┘  │
  ┌─────────────────┐  │
  │ LangGraph       │──┘
  │ Scanner         │
  └─────────────────┘

Stage 2 (parallel per finding):
  Finding 1 → [Prosecutor ⟷ Defender → Judge] → Verdict
  Finding 2 → [Prosecutor ⟷ Defender → Judge] → Verdict
  Finding 3 → [Prosecutor ⟷ Defender → Judge] → Verdict
  (all run concurrently)

Stage 3 (sequential per finding):
  Verified Finding 1 → Exploit → Remediation → Validate Fix
  Verified Finding 2 → Exploit → Remediation → Validate Fix
```

### 4. Debate Mechanism (Key Innovation from MDASH)

The debate stage is what reduces false positives while maintaining high recall. Unlike v2's single adversarial pass, v3 has a structured DEBATE:

```python
class DebateAgent:
    """Two agents argue, a third judges."""
    
    async def debate(self, finding: CandidateFinding) -> Verdict:
        # Round 1: Opening arguments
        prosecution = await self.prosecutor.argue(
            finding=finding,
            instruction="Argue why this finding IS a genuine, exploitable vulnerability. "
                       "Cite specific evidence from the code and context."
        )
        
        defense = await self.defender.argue(
            finding=finding,
            instruction="Argue why this finding is NOT exploitable or is a false positive. "
                       "Consider framework protections, environmental controls, and mitigating factors."
        )
        
        # Round 2: Rebuttals
        prosecution_rebuttal = await self.prosecutor.rebut(
            finding=finding,
            opponent_argument=defense,
            instruction="Counter the defense's arguments. Why do their mitigations fail?"
        )
        
        defense_rebuttal = await self.defender.rebut(
            finding=finding,
            opponent_argument=prosecution,
            instruction="Counter the prosecution's claims. What did they get wrong?"
        )
        
        # Round 3: Judge's verdict (extended thinking)
        verdict = await self.judge.decide(
            finding=finding,
            prosecution_case=[prosecution, prosecution_rebuttal],
            defense_case=[defense, defense_rebuttal],
            instruction="Evaluate both sides. Render verdict: CONFIRMED or DISMISSED. "
                       "Explain which arguments were strongest and why.",
            deliberation_budget=16000,  # Deep thinking for judgment
        )
        
        return verdict
```

### 5. Extended Thinking for Deliberation

Claude's extended thinking allows configurable "reasoning budget" per agent. Detection agents get a small budget (fast, pattern-matching). Debate judges get large budgets (deep reasoning).

```python
DELIBERATION_BUDGETS = {
    "scanner_agent": 4000,       # Fast detection, pattern recognition
    "prosecutor_agent": 8000,    # Build exploitation argument
    "defender_agent": 8000,      # Find mitigating factors
    "judge_agent": 16000,        # Deep evaluation of both sides
    "exploit_agent": 12000,      # Construct working exploit
    "remediation_agent": 8000,   # Generate fix code
}
```

---

## V3 Agent Inventory

### Stage 1: Generator Agents (Detection)

| Agent | Specialization | Input | Output | Tool Access |
|-------|---------------|-------|--------|-------------|
| `cross_tenant_scanner` | CWE-639: tenant_id from body | Source code + Semgrep results | Candidate cross-tenant findings | read_file, grep, semgrep_query |
| `iam_escalation_scanner` | CWE-269: privilege escalation | CDK source + IAM graph | Candidate IAM findings | read_cdk, iam_graph_query |
| `dom_xss_scanner` | CWE-79: innerHTML with user data | JS source + Semgrep results | Candidate XSS findings | read_file, grep, check_data_source |
| `prompt_injection_scanner` | CWE-77: user msg → tool execution | LangGraph source + agent config | Candidate PI findings | read_file, trace_state_flow |
| `graph_topology_scanner` | CWE-285: missing permission checks | LangGraph graph.py | Missing RBAC gates | read_file, parse_graph_edges |
| `session_scanner` | CWE-639: session_id enumeration | Handler source | Session isolation gaps | read_file, grep |
| `infra_scanner` | Multiple: encryption, logging, blast radius | CDK stacks | Infra misconfigs | read_cdk, iam_graph |
| `compound_scanner` | Cross-boundary toxic combinations | All Stage 1 outputs | Compound risk findings | query_all_findings |

### Stage 2: Verifier Agents (Debate)

| Agent | Role | Deliberation Budget |
|-------|------|---------------------|
| `prosecutor` | Argues finding IS exploitable | 8,000 tokens |
| `defender` | Argues finding is NOT exploitable | 8,000 tokens |
| `judge` | Evaluates both sides, renders verdict | 16,000 tokens |

### Stage 3: Prover Agents (Exploit + Fix)

| Agent | Role | Output |
|-------|------|--------|
| `exploit_generator` | Constructs PoC exploit (curl, script, test) | Working exploit code |
| `remediation_generator` | Generates fix code (minimal diff) | Code patch |
| `fix_validator` | Runs Semgrep on fixed code to verify | PASS/FAIL |

---

## V2 → V3 Improvement Matrix

| Aspect | V2 | V3 | Why Better |
|--------|----|----|-----------|
| Detection | Semgrep rules (static) | Semgrep + specialized scanner agents (dynamic) | Agents can reason about patterns Semgrep can't match |
| Validation | Single adversarial pass | Structured DEBATE (prosecution vs defense + judge) | Reduces both FP and FN via multi-perspective reasoning |
| Exploit | Manual curl in report | Agent-generated PoC code | Proves exploitability definitively |
| Remediation | Suggested fix | Generated fix + validated by re-scan | Proven to resolve the issue |
| Parallelism | Sequential pipeline | DAG-based parallel execution | 3-5x faster for multi-finding scans |
| Resumability | Checkpoints per phase | Durable execution per step | No work lost on any failure |
| Observability | Log files | OpenTelemetry traces | Cost tracking, performance profiling, debugging |
| Extensibility | Hardcoded agents | BaseAgent interface + contracts | Add new scanner types without changing harness |

---

## Implementation Plan

### Phase 1: Foundation (Harness Infrastructure)

```
v3/
├── harness/
│   ├── execution.py          # Durable execution engine
│   ├── state_store.py        # External state persistence (JSON files → DynamoDB later)
│   ├── contracts.py          # Agent contract definitions (JSON Schema)
│   ├── dag.py                # DAG-based parallel executor
│   └── observability.py      # OpenTelemetry integration
├── agents/
│   ├── base.py               # BaseAgent interface
│   ├── generators/           # Stage 1: Scanner agents
│   │   ├── cross_tenant.py
│   │   ├── iam_escalation.py
│   │   ├── dom_xss.py
│   │   ├── prompt_injection.py
│   │   ├── graph_topology.py
│   │   ├── session.py
│   │   ├── infra.py
│   │   └── compound.py
│   ├── verifiers/            # Stage 2: Debate agents
│   │   ├── prosecutor.py
│   │   ├── defender.py
│   │   └── judge.py
│   └── provers/              # Stage 3: Exploit + Fix agents
│       ├── exploit_gen.py
│       ├── remediation_gen.py
│       └── fix_validator.py
├── tools/                    # Tools available to agents
│   ├── file_tools.py        # read_file, grep, list_files
│   ├── semgrep_tools.py     # run_semgrep, query_results
│   ├── graph_tools.py       # iam_graph, call_graph, ast_query
│   └── sandbox_tools.py     # execute_exploit (isolated)
├── orchestrator.py           # Main pipeline coordinator
└── run_v3.py                 # Entry point
```

### Phase 2: Implement Agents (Using Claude SDK or In-Session)

Two options:
- **Option A:** Use Anthropic SDK / Claude Agent SDK for automated execution
- **Option B:** Run in Claude Code session (current approach, zero cost)

For Option B (what we can do now), each agent is a structured prompt + tool call sequence that Claude executes in-session.

### Phase 3: Wire DAG + Debate

Implement the parallel execution DAG and the structured debate mechanism.

---

## Key Differences from V2 → V3

### V2 Debate (simple):
```
Finding → "Why might this NOT be exploitable?" → Single answer → Verdict
```

### V3 Debate (MDASH-style):
```
Finding → Prosecutor builds case → Defender counters → 
          Prosecutor rebuts → Defender rebuts →
          Judge evaluates ALL arguments → Verdict with reasoning
```

The multi-round debate catches things the single-pass misses:
- Prosecutor might identify an exploitation angle the defender didn't consider
- Defender's rebuttal might reveal a mitigation the prosecutor overlooked
- Judge sees the FULL picture before deciding

### V2 Exploit (manual):
```
Finding confirmed → Human writes curl command in report
```

### V3 Exploit (agent-generated):
```
Finding confirmed → Exploit agent generates PoC code →
                    Sandbox validates it works (if available) →
                    Report includes proven exploit
```

---

## Running V3 From Claude Code Session

Since we're running from this session, the execution model is:

1. **Semgrep** runs (Python script) → produces candidate findings
2. **Claude** acts as all agents sequentially:
   - Wears "scanner" hat → identifies additional candidates
   - Wears "prosecutor" hat → argues each is exploitable
   - Wears "defender" hat → argues each is NOT exploitable
   - Wears "judge" hat → renders verdicts
   - Wears "exploit" hat → generates PoC for confirmed findings
   - Wears "remediation" hat → generates fixes

Each "hat change" is a distinct prompt with different persona, tools, and deliberation budget.

The key insight: **even in a single-session execution, the STRUCTURE of the debate produces better results than a single-pass analysis** (which is what V2 did).

---

## Success Criteria

| Metric | V2 (baseline) | V3 Target | How |
|--------|---------------|-----------|-----|
| False positive rate | 29% (2/7) | <10% | Debate mechanism |
| Findings with exploits | 0 | 100% of CRITICAL | Prover stage |
| Findings with validated fixes | 0 | 100% of CRITICAL | Fix validator |
| Vulnerability class coverage | 100% | 100% | Maintain with more scanner types |
| Reasoning depth | 6-step CoT | Multi-round debate (deeper) | Prosecution + defense + rebuttal |
| Parallelism | Sequential | 3-5x via DAG | Independent scanners/debates concurrent |
| Resumability | Per-phase | Per-step | Durable execution |

---

## References

1. Microsoft MDASH: 88.45% CyberGym (100+ agents, generator-verifier-prover)
2. Anthropic Mythos: 83.1% CyberGym (single model with scaffolding)
3. Claude Extended Thinking: configurable deliberation budgets
4. Claude Agent SDK: durable sessions, tool use, OpenTelemetry
5. Microsoft Agent Framework: BaseAgent interface, multi-agent orchestration
6. Durable Execution: external state, incremental execution, fault tolerance
7. VMAO: DAG-based parallel execution with verification-driven replanning
8. Semantic Kernel: Sequential, Concurrent, GroupChat, Handoff orchestration
