# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

A graph-based security vulnerability scanner with LLM reasoning. It analyzes Python applications and AWS CDK infrastructure for vulnerabilities including cross-tenant access, IAM escalation, DOM XSS, prompt injection, and toxic combinations across app+infra boundaries.

Four versions exist, each an evolution of the last:

- **V1** (`src/`): Original agent architecture with CPG builder, deterministic checks, and LLM-assisted validation
- **V2** (`v2/`): Semgrep taint detection + Chain-of-Thought reasoning pipeline with correlator
- **V3** (`v3/`): MDASH-inspired Generator → Verifier → Prover pipeline with durable execution and debate mechanism
- **V4** (`v4/`): Deep analysis — evidence walks, differential path analysis, absence detection, attack chain synthesis. Optimizes for analyst-actionable depth over speed.
- **V5** (`v5/`): Expert code reviewer — V4 deterministic foundation + zero trust analysis + LLM investigation agents. 6-layer pipeline. See `v5/DESIGN.md`.

## Running the Scanner

```bash
# V1 — CLI entry point (requires Bedrock credentials for LLM calls)
python -m src.main /path/to/repo --budget 5.0 --output report.json

# V1 — Deterministic-only mode (no LLM, outputs findings for Claude session reasoning)
python3 run_scan.py /path/to/repo

# V2 — Full pipeline (Semgrep + CoT + infra + correlation)
./v2/run_v2.sh /path/to/repo

# V3 — Three-stage pipeline
python3 v3/run_v3.py /path/to/repo

# V4 — Deep analysis (evidence walks, differential, chains)
PATH="$HOME/Library/Python/3.9/bin:$PATH" python3 v4/run_v4.py /path/to/repo

# V5 — Expert code reviewer (Layer 0 deterministic + Layer 1 LLM agents)
PATH="$HOME/Library/Python/3.9/bin:$PATH" python3 v5/run_v5.py /path/to/repo           # In-session mode
PATH="$HOME/Library/Python/3.9/bin:$PATH" python3 v5/run_v5.py /path/to/repo --api     # Bedrock API mode
PATH="$HOME/Library/Python/3.9/bin:$PATH" python3 v5/run_v5.py /path/to/repo --layer 0 # Layer 0 only
```

Default target repo is `/Users/indukuk/compliance`. Outputs go to `<target>/.security-agent/v{3,4}-state/`.

## Dependencies and Setup

```bash
pip install -e .                    # Core: networkx, boto3
pip install -e ".[tree-sitter]"     # Optional: tree-sitter for deeper AST parsing
pip install -e ".[z3]"              # Optional: z3-solver for formal IAM verification
pip install -e ".[terraform]"       # Optional: python-hcl2 for Terraform parsing
pip install -e ".[dev]"             # Dev: pytest, pytest-cov
```

Semgrep must be installed separately: `pip install semgrep` or `brew install semgrep`.

AWS credentials (Bedrock access) required for LLM-powered modes. Deterministic modes (`run_scan.py`, V3 without API calls) work offline.

## Architecture

### V3 Three-Stage Pipeline (current focus)

1. **Stage 1 — Generator**: Parallel scanner agents via DAG executor detect candidate vulnerabilities. Optimizes for high recall. Scanners: semgrep python, semgrep gaps, semgrep frontend, infra checks, business logic (IDOR/auth), spec inference, community rules (Lambda + AI security), rule generator, compound scanner.
2. **Stage 2 — Verifier**: AEGIS-style grounded debate (Prosecutor vs Defender → Judge) anchored to CPG evidence bundle. Only CRITICAL/HIGH findings are debated; lower severity passes through. Arguments must cite numbered evidence items — uncited claims are discarded.
3. **Stage 3 — Prover**: Generates exploit PoCs, validates in sandbox (`ExploitSandbox` uses AST analysis not actual execution), generates fix code, verifies fix eliminates the finding via re-scan.

**Neuro-symbolic split**: Rules with `context_needed=false` in `v3/symbolic/rules/*.yaml` produce final findings (zero FP, no LLM). Rules with `context_needed=true` produce candidates routed to Layer 2 (LLM debate).

Key V3 infrastructure:
- `v3/harness/execution.py` — Durable executor: idempotent resume, retry with backoff, circuit breaker (3 consecutive failures)
- `v3/harness/state_store.py` — JSON-file persistence (designed to swap to DynamoDB)
- `v3/harness/dag.py` — DAG-based parallel execution (ThreadPoolExecutor, max 4 workers)
- `v3/harness/contracts.py` — Agent contracts: inputs, outputs, allowed tools, deliberation budget tokens, persona
- `v3/agents/base.py` — `BaseAgent` → `ClaudeAgent` (LLM) / `DeterministicAgent` (no LLM)
- `v3/symbolic/property_engine.py` — Evaluates declarative YAML rules against InfraGraph
- `v3/agents/verifiers/grounded_debate.py` — Builds EvidenceBundle from CPG slices, generates prosecution/defense prompts
- `v3/agents/provers/fix_verifier.py` — Re-runs Semgrep after applying fix to confirm elimination
- `v3/knowledge/community_rules/` — Semgrep-compatible Python rules for Lambda, AI/LLM, and general Python security

### V1 Core Components (`src/`)

- `common/graph.py` — `CodePropertyGraph` (AST+CFG+DFG, networkx DiGraph) and `InfraGraph` (resource + IAM graph). These are the shared data structures used across all versions.
- `agents/python/cpg_builder.py` — Builds CPG from Python files using regex patterns (or tree-sitter if installed). Identifies sources, sinks, sanitizers, gates.
- `agents/infrastructure/z3_iam_analyzer.py` — Z3 SMT-based formal IAM verification (Zelkova approach). Encodes policies as constraints, proves missing tenant isolation conditions.
- `agents/infrastructure/toxic_combos.py` — Detects when individually-acceptable findings combine into critical risks
- `common/llm_client.py` — Bedrock Claude client with per-call cost tracking and budget enforcement
- `skills/` — Specialized analysis skills invoked by the orchestrator (taint, CPG queries, infra, compliance mapping, secrets detection)

### V4 Deep Analysis Pipeline (`v4/`)

Run: `PATH="$HOME/Library/Python/3.9/bin:$PATH" python3 v4/run_v4.py /path/to/repo`

Six-stage pipeline: CPG → Semgrep + Evidence Walks → Absence Detection → Differential Analysis → Chain Synthesis → Report

- `v4/cpg/enhanced_builder.py` — Inter-procedural CPG with call graph, param binding, framework-aware patterns (Lambda/DynamoDB/APIGW), handler detection with auth context
- `v4/analysis/evidence_walker.py` — BFS source→sink traces (5-9 steps) with semantic annotations and missing-control detection
- `v4/analysis/absence_detector.py` — Must-guard specs + deviant behavior mining. Detects missing audit logging, ownership checks, role verification, rate limiting
- `v4/analysis/differential_analyzer.py` — Sink-equivalence clustering + guard-set differencing. Finds bypass paths where one handler has fewer guards than another
- `v4/analysis/chain_synthesizer.py` — Precondition/postcondition capability graph. Composes findings into multi-step attack chains with composite severity escalation
- `v4/report/generator.py` — Structured Markdown + JSON reports with evidence walks, verified/unverified annotations, and contextual fix suggestions
- `v4/rules/crypto_auth.yaml` — JWT unsigned decode, custom crypto detection
- `v4/rules/frontend_secrets.yaml` — Hardcoded API keys in JS

### V2 Components (`v2/`)

- `cot_engine.py` — 6-step Chain-of-Thought analysis with context gathering
- `correlator.py` — Cross-boundary compound risk detection (app vuln + infra misconfiguration)
- `semgrep_rules*.yaml` — Custom taint rules. V3 and V4 reuse these rule files from the `v2/` directory.

## Key Design Decisions

- LLM calls use **Claude Sonnet** via Bedrock (`us.anthropic.claude-sonnet-4-6-20250514-v1:0`)
- Budget tracking is per-scan with configurable USD limit (default $5)
- Deterministic checks run without LLM; LLM reasoning is layered on top
- Exit codes: 0=clean, 1=HIGH findings, 2=CRITICAL findings
- Checkpoint/resume: completed steps are skipped on re-run (idempotent via state store)
- The scanner analyzes a separate target repo, not itself
- V3 deduplicates findings before debate and before proof to avoid redundant LLM work
- CPG is built between Stage 1 and Stage 2 so debate prompts can cite specific taint path nodes

## Testing

No test suite exists yet. To verify changes:

```bash
# Quick smoke test: run deterministic scan against the target repo
python3 run_scan.py /Users/indukuk/compliance

# Full V3 pipeline (takes longer, produces state in target/.security-agent/v3-state/)
python3 v3/run_v3.py /Users/indukuk/compliance

# Test individual components in isolation
python3 -c "from src.agents.python.cpg_builder import PythonCPGBuilder; print('OK')"
python3 -c "from v3.symbolic.property_engine import PropertyEngine; print('OK')"
python3 -c "from src.agents.infrastructure.z3_iam_analyzer import Z3IAMAnalyzer; print('OK')"  # requires z3-solver
```

When pytest infrastructure is added, use: `pytest -k "test_name"` for single tests, `pytest --cov=src` for coverage.
