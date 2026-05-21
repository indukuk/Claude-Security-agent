# Security Agent — System Design

## Agent Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SYSTEM BOUNDARY                                  │
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                        AGENT 1: ORCHESTRATOR                             │ │
│  │                                                                           │ │
│  │  ┌──────────┐  ┌──────────────┐  ┌────────────┐  ┌──────────────────┐  │ │
│  │  │  Repo    │  │  Execution   │  │  State     │  │  Report          │  │ │
│  │  │  Scanner │  │  Planner     │  │  Manager   │  │  Generator       │  │ │
│  │  └──────────┘  └──────────────┘  └────────────┘  └──────────────────┘  │ │
│  │                        │                                                  │ │
│  │                        │ dispatch                                         │ │
│  └────────────────────────┼──────────────────────────────────────────────────┘ │
│                           │                                                    │
│         ┌─────────────────┼─────────────────────┐                             │
│         │                 │                     │                             │
│         ▼                 ▼                     ▼                             │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────┐                     │
│  │  AGENT 2:   │  │  AGENT 3:   │  │    AGENT 4:      │                     │
│  │  Python App │  │  JS/TS App  │  │  Infrastructure  │                     │
│  └──────┬──────┘  └──────┬──────┘  └────────┬─────────┘                     │
│         │                 │                   │                               │
│         └─────────────────┼───────────────────┘                               │
│                           │ candidate findings                                │
│                           ▼                                                    │
│                  ┌──────────────────┐                                         │
│                  │    AGENT 5:      │                                         │
│                  │   Validation     │                                         │
│                  └──────────────────┘                                         │
│                                                                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Shared Interfaces

All agents communicate through well-defined data contracts. No agent directly imports another's internals.

### Finding Schema

Every agent produces findings in this format:

```python
@dataclass
class Finding:
    id: str                          # Unique identifier (agent_type + sequential)
    agent: str                       # "python" | "javascript" | "infrastructure"
    category: str                    # "sql_injection" | "iam_escalation" | "toxic_combination" etc.
    cwe: str | None                  # CWE-89, CWE-78, etc. (None for infra-only findings)
    severity: Severity               # CRITICAL | HIGH | MEDIUM | LOW
    confidence: Confidence           # HIGH | MEDIUM | LOW
    title: str                       # One-line description
    description: str                 # Detailed explanation including exploit scenario
    evidence: Evidence               # Code/config snippet proving the finding
    location: Location               # File, line, resource identifier
    attack_path: list[str] | None    # For compound findings: step-by-step path
    blast_radius: list[str] | None   # Resources affected if exploited
    remediation: Remediation | None  # Generated fix (after validation)
    related_findings: list[str]      # IDs of findings that combine with this one


@dataclass
class Evidence:
    snippet: str                     # Relevant code/config
    graph_context: str               # CPG slice or subgraph (serialized)
    reasoning: str                   # LLM's CoT reasoning trace


@dataclass
class Location:
    file_path: str
    start_line: int
    end_line: int
    resource_id: str | None          # For infra: logical resource ID


@dataclass
class Remediation:
    fix_diff: str                    # Before/after code diff
    explanation: str                 # Why this fix resolves the issue
    validated: bool                  # Has the fix passed post-fix validation?
    validation_result: str | None    # "PASS" | "REGRESSED" | "INVALID"


class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1


class Confidence(Enum):
    HIGH = 3
    MEDIUM = 2
    LOW = 1
```

### Agent State Schema

```python
@dataclass
class AgentState:
    agent_id: str
    agent_type: str
    status: AgentStatus              # IDLE | RUNNING | CHECKPOINTED | COMPLETE | FAILED
    phase: int
    chunk_index: int
    graph: dict | None               # Serialized graph (NetworkX adjacency)
    inferred_specs: dict | None      # Phase 0 output (sources/sinks/sanitizers)
    deterministic_findings: list[Finding]
    candidate_findings: list[Finding]    # Pre-validation
    validated_findings: list[Finding]    # Post-validation
    coverage: CoverageMetrics
    cost_incurred: float             # USD spent on LLM calls
    cost_budget: float               # USD budget allocated
    started_at: str
    last_checkpoint: str
    error: str | None


class AgentStatus(Enum):
    IDLE = "idle"
    RUNNING = "running"
    CHECKPOINTED = "checkpointed"
    COMPLETE = "complete"
    FAILED = "failed"
```

### Message Protocol Between Agents

```python
@dataclass
class AgentMessage:
    from_agent: str
    to_agent: str
    message_type: MessageType
    payload: dict
    timestamp: str


class MessageType(Enum):
    # Orchestrator → Agents
    START_SCAN = "start_scan"           # Begin analysis with config
    RESUME_SCAN = "resume_scan"         # Resume from checkpoint
    ABORT = "abort"                     # Stop work
    
    # Agents → Orchestrator
    PHASE_COMPLETE = "phase_complete"   # Phase finished, here are results
    CHECKPOINT = "checkpoint"           # Intermediate state save
    ERROR = "error"                     # Unrecoverable error
    FINDINGS_READY = "findings_ready"   # Candidate findings for validation
    
    # Orchestrator → Validation Agent
    VALIDATE_FINDINGS = "validate_findings"  # Batch of findings to validate
    
    # Validation Agent → Orchestrator
    VALIDATION_COMPLETE = "validation_complete"  # Findings with verdicts
```

---

## Agent 1: Orchestrator

### Purpose

Coordinates the entire security scan. Does no security analysis itself (except cross-boundary correlation). Manages state, dispatches agents, collects results, produces the final report.

### Internal Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                         ORCHESTRATOR                                 │
│                                                                      │
│  ┌──────────────────┐                                               │
│  │   Repo Scanner   │  Scans filesystem → identifies technologies   │
│  │                  │  Output: TechnologyManifest                    │
│  └────────┬─────────┘                                               │
│           │                                                          │
│           ▼                                                          │
│  ┌──────────────────┐                                               │
│  │ Execution Planner│  Decides: which agents, what order, parallel? │
│  │                  │  Output: ExecutionPlan                         │
│  └────────┬─────────┘                                               │
│           │                                                          │
│           ▼                                                          │
│  ┌──────────────────┐                                               │
│  │  Agent Dispatcher│  Starts agents, manages lifecycle              │
│  │                  │  Handles: parallel execution, retries, budget  │
│  └────────┬─────────┘                                               │
│           │                                                          │
│           ▼                                                          │
│  ┌──────────────────┐                                               │
│  │  State Manager   │  Global checkpoint, agent state aggregation   │
│  │                  │  Handles: resume, cost tracking, coverage      │
│  └────────┬─────────┘                                               │
│           │                                                          │
│           ▼                                                          │
│  ┌──────────────────┐                                               │
│  │ Cross-Boundary   │  Correlates findings across agents            │
│  │ Correlator       │  ONLY component that calls LLM                │
│  └────────┬─────────┘                                               │
│           │                                                          │
│           ▼                                                          │
│  ┌──────────────────┐                                               │
│  │ Report Generator │  Aggregates, deduplicates, formats output     │
│  └──────────────────┘                                               │
│                                                                      │
└────────────────────────────────────────────────────────────────────┘
```

### Repo Scanner

```python
class RepoScanner:
    """
    Identify technologies present in the repository.
    Purely filesystem-based — no LLM, no parsing.
    """
    
    TECHNOLOGY_MARKERS = {
        "python": {
            "files": ["*.py"],
            "indicators": ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"],
            "frameworks": {
                "flask": ["from flask import", "Flask(__name__)"],
                "django": ["django.conf", "INSTALLED_APPS"],
                "fastapi": ["from fastapi import", "FastAPI()"],
                "lambda": ["def handler(event", "def lambda_handler"],
            }
        },
        "javascript": {
            "files": ["*.js", "*.ts", "*.tsx"],
            "indicators": ["package.json", "tsconfig.json"],
            "frameworks": {
                "express": ["require('express')", "from 'express'"],
                "react": ["from 'react'", "import React"],
                "nextjs": ["next.config"],
                "lambda": ["exports.handler"],
            }
        },
        "terraform": {
            "files": ["*.tf"],
            "indicators": [".terraform/", "terraform.tfstate", ".terraform.lock.hcl"],
        },
        "cdk": {
            "files": ["cdk.json"],
            "indicators": ["cdk.out/", "aws-cdk-lib"],
        }
    }
    
    def scan(self, repo_path: str) -> TechnologyManifest:
        """
        Returns which technologies are present, which directories they occupy,
        and which frameworks are detected.
        """
        manifest = TechnologyManifest()
        
        for tech, markers in self.TECHNOLOGY_MARKERS.items():
            directories = self._find_directories(repo_path, markers)
            if directories:
                manifest.add(tech, directories, 
                           frameworks=self._detect_frameworks(directories, markers))
        
        # Identify cross-references
        manifest.cross_references = self._find_cross_references(manifest)
        
        return manifest


@dataclass
class TechnologyManifest:
    technologies: dict[str, TechEntry]   # tech_name → entry
    cross_references: list[CrossRef]      # shared env vars, output references
    
@dataclass
class TechEntry:
    directories: list[str]
    file_count: int
    line_count: int                       # Rough estimate for budget allocation
    frameworks: list[str]
    entry_points: list[str]              # Lambda handlers, Flask routes, API endpoints

@dataclass  
class CrossRef:
    source_tech: str                      # e.g., "terraform"
    target_tech: str                      # e.g., "python"
    reference_type: str                   # "env_var" | "output" | "ssm_parameter"
    details: str                          # What's shared
```

### Execution Planner

```python
class ExecutionPlanner:
    """
    Determine agent execution order, parallelism, and budget allocation.
    """
    
    def plan(self, manifest: TechnologyManifest, config: ScanConfig) -> ExecutionPlan:
        agents_needed = []
        
        for tech, entry in manifest.technologies.items():
            if tech == "python" and config.enable_python:
                agents_needed.append(AgentSpec(
                    type="python",
                    directories=entry.directories,
                    budget=self._allocate_budget(entry, config)
                ))
            elif tech == "javascript" and config.enable_javascript:
                agents_needed.append(AgentSpec(
                    type="javascript",
                    directories=entry.directories,
                    budget=self._allocate_budget(entry, config)
                ))
            elif tech in ("terraform", "cdk") and config.enable_infrastructure:
                agents_needed.append(AgentSpec(
                    type="infrastructure",
                    parser="cfn" if tech == "cdk" else "hcl",
                    directories=entry.directories,
                    budget=self._allocate_budget(entry, config)
                ))
        
        # Always include validation agent
        agents_needed.append(AgentSpec(type="validation", budget=config.validation_budget))
        
        # Determine execution order
        # Infra agents go first if app agents reference infra outputs
        order = self._topological_sort(agents_needed, manifest.cross_references)
        
        # Identify parallelizable groups
        parallel_groups = self._find_parallel_groups(order, manifest.cross_references)
        
        return ExecutionPlan(
            agents=agents_needed,
            execution_order=order,
            parallel_groups=parallel_groups,
            total_budget=config.total_budget
        )
    
    def _allocate_budget(self, entry: TechEntry, config: ScanConfig) -> float:
        """
        Budget proportional to code size, weighted by technology risk.
        Infra gets higher per-line budget (IAM analysis is expensive reasoning).
        """
        WEIGHT = {"python": 1.0, "javascript": 1.0, "infrastructure": 1.5}
        total_weighted = sum(
            e.line_count * WEIGHT.get(t, 1.0) 
            for t, e in config.manifest.technologies.items()
        )
        share = (entry.line_count * WEIGHT.get(entry.tech, 1.0)) / total_weighted
        return config.total_budget * share
```

### Cross-Boundary Correlator

The only orchestrator component that calls the LLM.

```python
class CrossBoundaryCorrelator:
    """
    Find compound vulnerabilities that span agent boundaries.
    E.g., Python code + CDK infrastructure together create a risk
    that neither agent would find alone.
    """
    
    CORRELATION_PATTERNS = [
        {
            "name": "public_endpoint_with_unsafe_code",
            "app_signal": "unsanitized_input_to_sink",
            "infra_signal": "publicly_reachable_compute",
            "compound_severity": "CRITICAL"
        },
        {
            "name": "overpermissive_role_with_data_handling",
            "app_signal": "handles_user_data",
            "infra_signal": "role_exceeds_least_privilege",
            "compound_severity": "HIGH"
        },
        {
            "name": "env_var_injection_path",
            "app_signal": "reads_env_var_unsafely",
            "infra_signal": "env_var_from_untrusted_source",
            "compound_severity": "HIGH"
        }
    ]
    
    SYSTEM_PROMPT = """You are a senior security architect performing cross-boundary 
threat analysis. You are correlating findings from application code analysis and 
infrastructure analysis to identify compound vulnerabilities that only emerge when 
both layers are considered together.

Focus on attack paths that chain an application-level weakness with an 
infrastructure-level weakness to achieve impact greater than either alone."""

    COT_TEMPLATE = """Given the following findings from separate security analyses:

APPLICATION FINDINGS:
{app_findings}

INFRASTRUCTURE FINDINGS:
{infra_findings}

CROSS-REFERENCES (shared configuration):
{cross_refs}

STEP 1 — IDENTIFY CONNECTIONS: Which application findings relate to which 
infrastructure findings? (e.g., a Lambda that has both a code vulnerability 
AND an overpermissive role)

STEP 2 — TRACE ATTACK PATHS: For each connection, construct the full attack 
narrative. What does the attacker exploit first? How do they pivot? What do 
they ultimately access?

STEP 3 — ASSESS COMBINED SEVERITY: Is the compound risk greater than either 
individual finding? Why?

STEP 4 — VERIFY: Could environmental controls prevent this chain? Is the 
attack path actually viable end-to-end?

STEP 5 — OUTPUT: For each compound finding, provide:
  - Attack path: [step1 → step2 → ... → impact]
  - Combined severity: CRITICAL | HIGH | MEDIUM
  - Explanation: Why this combination is dangerous
  - Remediation: Which single fix breaks the chain most effectively"""

    def correlate(self, app_findings: list[Finding], 
                  infra_findings: list[Finding],
                  cross_refs: list[CrossRef]) -> list[Finding]:
        
        # Pre-filter: only send findings that COULD be related
        relevant_app = self._filter_correlatable(app_findings)
        relevant_infra = self._filter_correlatable(infra_findings)
        
        if not relevant_app or not relevant_infra:
            return []
        
        # Compress findings for context efficiency
        app_summary = self._compress_findings(relevant_app)
        infra_summary = self._compress_findings(relevant_infra)
        cross_ref_summary = self._format_cross_refs(cross_refs)
        
        prompt = self.COT_TEMPLATE.format(
            app_findings=app_summary,
            infra_findings=infra_summary,
            cross_refs=cross_ref_summary
        )
        
        response = self.llm_client.analyze(
            system_prompt=self.SYSTEM_PROMPT,
            user_prompt=prompt,
            temperature=0.1
        )
        
        return self._parse_compound_findings(response)
```

### Report Generator

```python
class ReportGenerator:
    """
    Produces the final unified report.
    Deterministic — no LLM calls. Pure aggregation and formatting.
    """
    
    def generate(self, scan_result: ScanResult) -> SecurityReport:
        report = SecurityReport()
        
        # Aggregate all findings
        all_findings = (
            scan_result.app_findings +
            scan_result.infra_findings +
            scan_result.compound_findings
        )
        
        # Deduplicate (same location + same CWE = duplicate)
        deduped = self._deduplicate(all_findings)
        
        # Sort by severity (CRITICAL first), then confidence
        deduped.sort(key=lambda f: (f.severity.value, f.confidence.value), reverse=True)
        
        # Group by category
        report.findings_by_severity = self._group_by_severity(deduped)
        report.findings_by_category = self._group_by_category(deduped)
        
        # Coverage summary
        report.coverage = self._aggregate_coverage(scan_result.agent_states)
        
        # Cost summary
        report.cost = self._aggregate_cost(scan_result.agent_states)
        
        # Executive summary
        report.summary = self._generate_summary(deduped, report.coverage)
        
        return report
    
    def _generate_summary(self, findings, coverage) -> str:
        critical = len([f for f in findings if f.severity == Severity.CRITICAL])
        high = len([f for f in findings if f.severity == Severity.HIGH])
        
        return (
            f"Scanned {coverage.total_files} files across {coverage.technologies} technologies. "
            f"Found {len(findings)} security issues: {critical} CRITICAL, {high} HIGH. "
            f"Risk-weighted coverage: {coverage.risk_weighted:.0%}. "
            f"Analysis cost: ${coverage.total_cost:.2f}."
        )
```

---

## Agent 2: Python Application Security Agent

### Purpose

Detects taint-flow vulnerabilities in Python code via Code Property Graph construction and LLM-powered semantic reasoning.

### Internal Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                    PYTHON APPLICATION AGENT                              │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ PHASE 0: Specification Inference                                    │ │
│  │                                                                      │ │
│  │  ┌──────────────┐    ┌───────────────┐    ┌─────────────────────┐  │ │
│  │  │ Import/Usage │───▶│ LLM Inference │───▶│ Symbolic Validation │  │ │
│  │  │ Scanner      │    │ (sources/     │    │ (ground against     │  │ │
│  │  │              │    │  sinks/san.)  │    │  actual code)       │  │ │
│  │  └──────────────┘    └───────────────┘    └─────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                    │                                     │
│                                    ▼                                     │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ PHASE 2: Graph Construction (Deterministic)                         │ │
│  │                                                                      │ │
│  │  ┌─────────────┐  ┌───────────┐  ┌───────────┐  ┌──────────────┐  │ │
│  │  │ tree-sitter │─▶│ AST Graph │─▶│ CFG Build │─▶│ DFG Build    │  │ │
│  │  │ Parse       │  │           │  │           │  │ (def-use)    │  │ │
│  │  └─────────────┘  └───────────┘  └───────────┘  └──────────────┘  │ │
│  │                                                         │           │ │
│  │                                                         ▼           │ │
│  │  ┌──────────────────────────────────────────────────────────────┐  │ │
│  │  │            Unified Code Property Graph (CPG)                  │  │ │
│  │  └──────────────────────────────────────────────────────────────┘  │ │
│  │                          │                                          │ │
│  │                          ▼                                          │ │
│  │  ┌──────────────┐  ┌────────────────┐  ┌────────────────────┐     │ │
│  │  │ Source/Sink  │  │ Path           │  │ Prioritizer        │     │ │
│  │  │ Identifier   │  │ Enumerator     │  │ (risk score +      │     │ │
│  │  │              │  │ (BFS/DFS)      │  │  knapsack)         │     │ │
│  │  └──────────────┘  └────────────────┘  └────────────────────┘     │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                    │                                     │
│                                    ▼                                     │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ PHASE 3: LLM Taint Reasoning (Chunked)                             │ │
│  │                                                                      │ │
│  │  ┌────────────┐  ┌─────────────┐  ┌────────────┐  ┌────────────┐  │ │
│  │  │ CPG Slicer │─▶│ Context     │─▶│ LLM Call   │─▶│ Finding    │  │ │
│  │  │            │  │ Assembler   │  │ (Think &   │  │ Extractor  │  │ │
│  │  │            │  │ (positioning)│  │  Verify)   │  │            │  │ │
│  │  └────────────┘  └─────────────┘  └────────────┘  └────────────┘  │ │
│  │                                                                      │ │
│  │  Repeats per chunk. Checkpoint after each.                           │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
└────────────────────────────────────────────────────────────────────────┘
```

### Phase 0: Specification Inference

```python
class PythonSpecInference:
    """
    Infer project-specific sources, sinks, and sanitizers using LLM.
    Then validate each inference against actual code.
    """
    
    SYSTEM_PROMPT = """You are a security engineer analyzing a Python codebase 
to identify taint-flow entry points and sinks. You specialize in identifying 
framework-specific and custom sources/sinks that static tools would miss."""

    INFERENCE_PROMPT = """Analyze these imports and usage patterns from a Python project:

IMPORTS:
{imports}

FRAMEWORK PATTERNS:
{framework_usage}

CUSTOM FUNCTION SIGNATURES:
{custom_functions}

Identify additional sources, sinks, and sanitizers beyond the standard ones 
(Flask request.args, os.system, etc.). Focus on:
1. Custom wrappers around standard sources/sinks
2. Framework-specific entry points (e.g., Celery task arguments, gRPC handlers)
3. Project-specific validation functions that act as sanitizers
4. Decorator patterns that transform data

Output as JSON:
{{
  "sources": [{{"function": "...", "reason": "...", "confidence": "HIGH|MEDIUM"}}],
  "sinks": [{{"function": "...", "cwe": "CWE-XXX", "reason": "...", "confidence": "HIGH|MEDIUM"}}],
  "sanitizers": [{{"function": "...", "sanitizes_for": "CWE-XXX", "reason": "..."}}],
  "propagators": [{{"function": "...", "reason": "..."}}]
}}"""

    def infer(self, project_info: ProjectInfo) -> InferredSpecs:
        imports = self._extract_imports(project_info.files)
        framework_usage = self._detect_framework_patterns(project_info.files)
        custom_functions = self._extract_function_signatures(project_info.files)
        
        response = self.llm_client.analyze(
            system_prompt=self.SYSTEM_PROMPT,
            user_prompt=self.INFERENCE_PROMPT.format(
                imports=imports,
                framework_usage=framework_usage,
                custom_functions=custom_functions
            ),
            temperature=0.1
        )
        
        raw_specs = self._parse_response(response)
        validated_specs = self._validate(raw_specs, project_info)
        
        return validated_specs
    
    def _validate(self, specs: InferredSpecs, project: ProjectInfo) -> InferredSpecs:
        """
        Ground each inferred spec against actual code.
        Reject specs that don't match code reality.
        """
        validated = InferredSpecs()
        
        for source in specs.sources:
            # Check: does this function actually receive external data?
            func_def = project.find_function(source.function)
            if func_def and self._receives_external_data(func_def, project):
                validated.sources.append(source)
            # else: LLM hallucinated — discard
        
        for sink in specs.sinks:
            # Check: does this function perform a dangerous operation?
            func_def = project.find_function(sink.function)
            if func_def and self._performs_dangerous_op(func_def, sink.cwe):
                validated.sinks.append(sink)
        
        for sanitizer in specs.sanitizers:
            # Check: does this function actually transform data?
            func_def = project.find_function(sanitizer.function)
            if func_def and self._transforms_data(func_def):
                validated.sanitizers.append(sanitizer)
        
        return validated
```

### Phase 2: CPG Construction

```python
class PythonCPGBuilder:
    """
    Build Code Property Graph from Python source using tree-sitter.
    CPG = AST edges ∪ CFG edges ∪ DFG edges
    """
    
    def build(self, files: list[str], specs: MergedSpecs) -> CodePropertyGraph:
        cpg = CodePropertyGraph()
        
        for file_path in files:
            # Step 1: Parse to AST via tree-sitter
            tree = self.parser.parse(read_file(file_path))
            ast_graph = self._build_ast_graph(tree, file_path)
            
            # Step 2: Build CFG from AST
            cfg = self._build_cfg(ast_graph)
            
            # Step 3: Build DFG (def-use chains)
            dfg = self._build_dfg(ast_graph, cfg)
            
            # Step 4: Merge into CPG
            cpg.merge(ast_graph, cfg, dfg)
        
        # Step 5: Add inter-procedural edges (call graph)
        call_edges = self._build_call_graph(cpg)
        cpg.add_edges(call_edges, edge_type="CALL")
        
        # Step 6: Mark sources, sinks, sanitizers
        cpg.mark_nodes(specs.sources, role="SOURCE")
        cpg.mark_nodes(specs.sinks, role="SINK")
        cpg.mark_nodes(specs.sanitizers, role="SANITIZER")
        
        return cpg
    
    def _build_ast_graph(self, tree, file_path) -> nx.DiGraph:
        """Convert tree-sitter AST to NetworkX graph with node types."""
        G = nx.DiGraph()
        
        def visit(node, parent_id=None):
            node_id = f"{file_path}:{node.start_point[0]}:{node.start_point[1]}"
            G.add_node(node_id, 
                      type=node.type,
                      text=node.text.decode('utf-8') if node.text else "",
                      file=file_path,
                      line=node.start_point[0] + 1,
                      col=node.start_point[1])
            
            if parent_id:
                G.add_edge(parent_id, node_id, edge_type="AST")
            
            for child in node.children:
                visit(child, node_id)
        
        visit(tree.root_node)
        return G
    
    def _build_cfg(self, ast_graph) -> list[tuple]:
        """
        Build control flow edges.
        Handles: sequential statements, if/else branches, 
        for/while loops, try/except, return/raise.
        """
        cfg_edges = []
        
        for func_node in self._get_function_nodes(ast_graph):
            body_stmts = self._get_body_statements(func_node, ast_graph)
            
            for i, stmt in enumerate(body_stmts):
                # Sequential flow
                if i + 1 < len(body_stmts):
                    cfg_edges.append((stmt, body_stmts[i+1], {"edge_type": "CFG"}))
                
                # Branch flow (if/else)
                if self._is_branch(stmt, ast_graph):
                    true_branch, false_branch = self._get_branches(stmt, ast_graph)
                    cfg_edges.append((stmt, true_branch, {"edge_type": "CFG", "condition": "true"}))
                    if false_branch:
                        cfg_edges.append((stmt, false_branch, {"edge_type": "CFG", "condition": "false"}))
                
                # Loop flow
                if self._is_loop(stmt, ast_graph):
                    loop_body = self._get_loop_body(stmt, ast_graph)
                    cfg_edges.append((stmt, loop_body, {"edge_type": "CFG", "condition": "loop_enter"}))
                    cfg_edges.append((loop_body, stmt, {"edge_type": "CFG", "condition": "loop_back"}))
        
        return cfg_edges
    
    def _build_dfg(self, ast_graph, cfg) -> list[tuple]:
        """
        Build data flow edges (def-use chains).
        For each variable assignment (def), find all reads (use) reachable via CFG.
        """
        dfg_edges = []
        
        # Find all definitions (assignments, parameters, imports)
        definitions = self._find_definitions(ast_graph)
        
        for def_node, var_name in definitions:
            # Find all uses of this variable reachable from the def via CFG
            uses = self._find_reaching_uses(def_node, var_name, ast_graph, cfg)
            for use_node in uses:
                dfg_edges.append((def_node, use_node, {
                    "edge_type": "DFG",
                    "variable": var_name
                }))
        
        return dfg_edges


class CPGSlicer:
    """
    Extract minimal subgraph relevant to a specific taint path.
    Achieves 67-91% token reduction while preserving vulnerability context.
    """
    
    def slice(self, cpg: CodePropertyGraph, source: str, sink: str) -> CPGSlice:
        # 1. Find all DFG paths from source to sink
        dfg_paths = list(nx.all_simple_paths(
            cpg.graph, source, sink, 
            cutoff=15  # Max path length to prevent explosion
        ))
        
        # Filter to only paths using DFG edges
        dfg_paths = [p for p in dfg_paths if self._uses_dfg_edges(p, cpg)]
        
        # 2. Collect all nodes on these paths
        slice_nodes = set()
        for path in dfg_paths:
            slice_nodes.update(path)
        
        # 3. Add CFG branch conditions that gate the flow
        for node in list(slice_nodes):
            for pred in cpg.predecessors(node, edge_type="CFG"):
                if cpg.is_branch_condition(pred):
                    slice_nodes.add(pred)
        
        # 4. Add 1-hop AST context (function signatures, class names)
        for node in list(slice_nodes):
            parent = cpg.ast_parent(node)
            if parent and cpg.node_type(parent) in ("function_definition", "class_definition"):
                slice_nodes.add(parent)
        
        # 5. Extract subgraph
        subgraph = cpg.subgraph(slice_nodes)
        
        # 6. Render to LLM-friendly format
        return CPGSlice(
            graph=subgraph,
            source_code=self._render_code(subgraph, cpg),
            graph_description=self._render_graph_description(subgraph, cpg),
            token_estimate=self._estimate_tokens(subgraph)
        )
    
    def _render_code(self, subgraph, cpg) -> str:
        """
        Render the slice as readable code with annotations.
        Position critical code at beginning (context window optimization).
        """
        lines = []
        
        # Source node first (beginning of context)
        source_node = self._find_role(subgraph, "SOURCE")
        lines.append(f"# SOURCE (user input enters here):")
        lines.append(cpg.get_code_context(source_node, context_lines=2))
        lines.append("")
        
        # Intermediate nodes (middle)
        for node in self._topological_order(subgraph):
            if cpg.get_role(node) not in ("SOURCE", "SINK"):
                lines.append(f"# Data flows through:")
                lines.append(cpg.get_code_context(node, context_lines=1))
                lines.append("")
        
        # Sink node last (end of context — also strong position)
        sink_node = self._find_role(subgraph, "SINK")
        lines.append(f"# SINK (sensitive operation):")
        lines.append(cpg.get_code_context(sink_node, context_lines=2))
        
        return "\n".join(lines)
```

### Phase 3: LLM Taint Reasoning

```python
class PythonTaintAnalyzer:
    """
    Performs chunked LLM analysis using CPG slices and CWE-specific prompting.
    """
    
    SYSTEM_PROMPT = """You are a senior application security engineer specializing 
in Python taint analysis and vulnerability detection. You are performing a security 
audit of production code. You reason step-by-step about data flow, never jumping 
to conclusions without tracing the actual path."""

    THINK_AND_VERIFY_TEMPLATE = """Analyze this code path for {cwe_id}: {cwe_name}.

{cwe_definition}

CODE CONTEXT (CPG Slice — only the relevant path):
{cpg_slice_code}

DATA FLOW GRAPH:
{cpg_slice_graph}

KNOWN FACTS (from deterministic analysis):
{prior_facts}

---

STEP 1 — IDENTIFY: What untrusted input enters this path? Where does it come from? 
What does the attacker control? Be specific about the variable name and its origin.

STEP 2 — TRACE: Follow the data through each transformation step-by-step.
For each step state:
  (a) Variable name carrying tainted data
  (b) Operation performed on it
  (c) Whether taint is preserved, removed, or transformed

STEP 3 — ASSESS: Does the data pass through any sanitization?
  - Is the sanitization sufficient for THIS SPECIFIC sink type?
  - Could it be bypassed? (e.g., encoding bypass, type confusion, partial sanitization)
  - Is it applied on ALL paths or only some?

STEP 4 — CONCLUDE: Does tainted data reach the sink in a form that enables exploitation?
  - What specific exploit payload would succeed?
  - What is the concrete impact?

STEP 5 — VERIFY: Challenge your own reasoning:
  - Could the path be unreachable due to authentication/authorization checks?
  - Could the sanitizer handle edge cases you haven't considered?
  - Are there framework-level protections not visible in this slice?
  - Is there a type constraint that prevents exploitation?
  - Is the sink actually dangerous in this specific context?

STEP 6 — VERDICT:
  {{ VULNERABLE | SAFE | UNCERTAIN }}
  Confidence: {{ HIGH | MEDIUM | LOW }}
  If VULNERABLE: describe the exploit scenario in one sentence.
  If SAFE: explain what prevents exploitation.
  If UNCERTAIN: explain what additional context would resolve the ambiguity."""

    def analyze_chunk(self, chunk: AnalysisChunk, state: AgentState) -> list[Finding]:
        findings = []
        
        for taint_path in chunk.paths:
            # Get CPG slice for this path
            cpg_slice = self.slicer.slice(state.cpg, taint_path.source, taint_path.sink)
            
            # Determine which CWE to check based on sink type
            cwe = self._get_cwe_for_sink(taint_path.sink, state.specs)
            cwe_definition = self.knowledge.get_cwe(cwe)
            
            # Assemble context (positioning: critical at start/end)
            prompt = self.THINK_AND_VERIFY_TEMPLATE.format(
                cwe_id=cwe.id,
                cwe_name=cwe.name,
                cwe_definition=cwe_definition,        # Beginning: CWE context
                cpg_slice_code=cpg_slice.source_code,  # Middle: code
                cpg_slice_graph=cpg_slice.graph_description,
                prior_facts=self._compress_prior_findings(state.candidate_findings)  # End
            )
            
            response = self.llm_client.analyze(
                system_prompt=self.SYSTEM_PROMPT,
                user_prompt=prompt,
                temperature=0.1
            )
            
            finding = self._parse_verdict(response, taint_path, cpg_slice)
            if finding and finding.severity != Severity.LOW:
                findings.append(finding)
        
        return findings
    
    def create_chunks(self, priority_queue: list[TaintPath], 
                      cpg: CodePropertyGraph,
                      budget_per_chunk: int = 20000) -> list[AnalysisChunk]:
        """
        Group taint paths into chunks that fit within token budget.
        Optimize: group paths sharing CPG nodes to reduce redundant context.
        """
        chunks = []
        current_chunk = AnalysisChunk()
        current_tokens = 0
        
        for path in priority_queue:
            slice_cost = self.slicer.estimate_tokens(cpg, path.source, path.sink)
            
            # Check for node overlap with current chunk (sharing reduces cost)
            overlap = current_chunk.shared_nodes(path)
            effective_cost = slice_cost * (1 - 0.5 * overlap)  # 50% savings on shared nodes
            
            if current_tokens + effective_cost > budget_per_chunk:
                chunks.append(current_chunk)
                current_chunk = AnalysisChunk()
                current_tokens = 0
            
            current_chunk.add_path(path)
            current_tokens += effective_cost
        
        if current_chunk.paths:
            chunks.append(current_chunk)
        
        return chunks
```

---

## Agent 3: JavaScript/TypeScript Application Security Agent

### Purpose

Same architecture as Agent 2 but with JS/TS-specific parsing, vulnerability classes, and framework knowledge.

### Key Differences from Python Agent

```python
class JavaScriptCPGBuilder(BaseCPGBuilder):
    """
    JS/TS-specific CPG construction.
    Handles: async/await, Promises, closures, prototype chain, JSX.
    """
    
    # JS-specific: async data flow through Promise chains
    def _build_dfg(self, ast_graph, cfg):
        dfg_edges = super()._build_dfg(ast_graph, cfg)
        
        # Add edges through .then() chains
        dfg_edges += self._trace_promise_chains(ast_graph)
        
        # Add edges through async/await
        dfg_edges += self._trace_async_await(ast_graph)
        
        # Add edges through React props (parent → child component)
        dfg_edges += self._trace_react_props(ast_graph)
        
        # Add edges through event handlers
        dfg_edges += self._trace_event_handlers(ast_graph)
        
        return dfg_edges
    
    # JS-specific: prototype pollution tracking
    def _mark_prototype_sinks(self, cpg):
        """
        Mark Object.assign, spread with computed keys, 
        lodash.merge, etc. as prototype pollution sinks.
        """
        patterns = [
            "Object.assign({}, *)",
            "_.merge(*, *)",
            "_.defaultsDeep(*, *)",
            "Object.defineProperty(*, computed_key, *)",
        ]
        for pattern in patterns:
            matches = cpg.find_pattern(pattern)
            for match in matches:
                cpg.mark_node(match, role="SINK", cwe="CWE-1321")


class JavaScriptSpecInference(BaseSpecInference):
    """JS/TS-specific specification inference."""
    
    INFERENCE_PROMPT = """Analyze these imports and patterns from a JavaScript/TypeScript project:

IMPORTS (package.json dependencies):
{dependencies}

FRAMEWORK PATTERNS:
{framework_usage}

ROUTE DEFINITIONS:
{routes}

Identify sources, sinks, and sanitizers specific to this project.
Pay special attention to:
1. Custom middleware that processes user input
2. Template engines and their auto-escaping behavior
3. ORM usage patterns (parameterized vs. raw queries)
4. React component props that receive user-controlled data
5. WebSocket message handlers

Output as JSON: ..."""
```

### JS-Specific CoT Additions

```python
# Additional verification steps for JS/TS
JS_VERIFY_ADDITIONS = """
  - Does the template engine auto-escape? (EJS: no, Handlebars: yes by default)
  - Is this a client-side or server-side code path? (DOM XSS vs reflected XSS)
  - Does React's JSX auto-escape this output? (yes for text, no for dangerouslySetInnerHTML)
  - Could prototype pollution in a dependency affect this path?
  - Is the code using strict mode? (affects certain injection vectors)
"""
```

---

## Agent 4: Infrastructure Security Agent

### Purpose

Analyzes AWS infrastructure defined in CDK (CloudFormation) or Terraform for misconfigurations, privilege escalation, toxic combinations, and attack paths.

### Internal Architecture

```
┌───────────────────────────────────────────────────────────────────────────┐
│                      INFRASTRUCTURE AGENT                                   │
│                                                                             │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ INPUT PARSERS (Deterministic — select based on input type)             │ │
│  │                                                                         │ │
│  │  ┌──────────────────┐    ┌──────────────────┐                          │ │
│  │  │  CFN Parser      │    │  HCL Parser      │                          │ │
│  │  │  (CDK → synth →  │    │  (Terraform .tf  │                          │ │
│  │  │   JSON)          │    │   files)         │                          │ │
│  │  └────────┬─────────┘    └────────┬─────────┘                          │ │
│  │           │                        │                                    │ │
│  │           └────────────┬───────────┘                                    │ │
│  │                        ▼                                                │ │
│  │           ┌──────────────────────┐                                      │ │
│  │           │ Normalized Resource  │  ← Standard schema regardless        │ │
│  │           │ Model                │     of input format                   │ │
│  │           └──────────┬───────────┘                                      │ │
│  └──────────────────────┼────────────────────────────────────────────────┘ │
│                         │                                                   │
│                         ▼                                                   │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ GRAPH CONSTRUCTION (Deterministic)                                     │ │
│  │                                                                         │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐             │ │
│  │  │ G_net        │  │ G_iam        │  │ G_data           │             │ │
│  │  │ (Resource    │  │ (Permission  │  │ (Data store      │             │ │
│  │  │  topology)   │  │  graph)      │  │  classification) │             │ │
│  │  └──────────────┘  └──────────────┘  └──────────────────┘             │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                         │                                                   │
│                         ▼                                                   │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ ANALYSIS ENGINES (Deterministic — no LLM)                              │ │
│  │                                                                         │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌───────────┐ │ │
│  │  │ Deterministic│  │ Z3 IAM       │  │ Attack Path  │  │ Toxic     │ │ │
│  │  │ Rule Checker │  │ Analyzer     │  │ Enumerator   │  │ Combo     │ │ │
│  │  │ (40+ rules)  │  │ (formal)     │  │ (graph algo) │  │ Detector  │ │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  └───────────┘ │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                         │                                                   │
│                         ▼                                                   │
│  ┌───────────────────────────────────────────────────────────────────────┐ │
│  │ LLM REASONING (Only for contextual judgment + remediation)             │ │
│  │                                                                         │ │
│  │  ┌──────────────────────┐    ┌──────────────────────────┐             │ │
│  │  │ Contextual Analyzer  │    │ Remediation Generator    │             │ │
│  │  │ (is this justified?  │    │ (generate fix + validate │             │ │
│  │  │  what's the intent?) │    │  against scanner)        │             │ │
│  │  └──────────────────────┘    └──────────────────────────┘             │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
└───────────────────────────────────────────────────────────────────────────┘
```

### Normalized Resource Model

Both parsers (CFN and HCL) produce the same intermediate representation:

```python
@dataclass
class NormalizedResource:
    logical_id: str                    # Unique identifier within the template
    resource_type: str                 # AWS::Lambda::Function, aws_lambda_function
    provider: str                      # "aws" | "gcp" | "azure"
    properties: dict                   # All configuration properties
    references_to: list[str]           # Resources this one depends on
    referenced_by: list[str]           # Resources that depend on this one
    iam_role: str | None               # Attached IAM role (if compute resource)
    network_config: NetworkConfig | None  # VPC, subnet, security groups
    encryption_config: EncryptionConfig | None
    tags: dict[str, str]


@dataclass
class NormalizedTemplate:
    resources: dict[str, NormalizedResource]
    parameters: dict[str, Parameter]
    outputs: dict[str, Output]
    conditions: dict[str, Condition]
```

### CFN Parser

```python
class CloudFormationParser:
    """
    Parse synthesized CloudFormation JSON into normalized model.
    Handles: Ref, Fn::GetAtt, Fn::Sub, Fn::Select, Fn::If, Conditions.
    """
    
    def parse(self, template_path: str) -> NormalizedTemplate:
        with open(template_path) as f:
            cfn = json.load(f)
        
        normalized = NormalizedTemplate()
        
        for logical_id, resource in cfn.get("Resources", {}).items():
            norm_resource = NormalizedResource(
                logical_id=logical_id,
                resource_type=resource["Type"],
                provider="aws",
                properties=resource.get("Properties", {}),
                references_to=self._extract_references(resource),
                iam_role=self._find_attached_role(resource),
                network_config=self._extract_network_config(resource),
                encryption_config=self._extract_encryption_config(resource),
                tags=self._extract_tags(resource)
            )
            normalized.resources[logical_id] = norm_resource
        
        # Resolve back-references
        for res_id, res in normalized.resources.items():
            for ref_target in res.references_to:
                if ref_target in normalized.resources:
                    normalized.resources[ref_target].referenced_by.append(res_id)
        
        return normalized
    
    def _extract_references(self, resource: dict) -> list[str]:
        """Recursively find all Ref, Fn::GetAtt, Fn::Sub references."""
        refs = []
        self._walk_for_refs(resource, refs)
        return refs
    
    def _walk_for_refs(self, obj, refs):
        if isinstance(obj, dict):
            if "Ref" in obj:
                refs.append(obj["Ref"])
            elif "Fn::GetAtt" in obj:
                refs.append(obj["Fn::GetAtt"][0])
            elif "Fn::Sub" in obj:
                # Extract ${ResourceName} patterns from Sub strings
                import re
                sub_str = obj["Fn::Sub"] if isinstance(obj["Fn::Sub"], str) else obj["Fn::Sub"][0]
                refs.extend(re.findall(r'\$\{(\w+)', sub_str))
            for value in obj.values():
                self._walk_for_refs(value, refs)
        elif isinstance(obj, list):
            for item in obj:
                self._walk_for_refs(item, refs)
```

### HCL Parser (Terraform)

```python
class TerraformParser:
    """
    Parse Terraform HCL files into normalized model.
    Uses python-hcl2 for parsing.
    Handles: resource blocks, data sources, modules, variables, outputs.
    """
    
    def parse(self, tf_directory: str) -> NormalizedTemplate:
        import hcl2
        
        normalized = NormalizedTemplate()
        
        # Parse all .tf files in directory
        for tf_file in glob.glob(f"{tf_directory}/**/*.tf", recursive=True):
            with open(tf_file) as f:
                parsed = hcl2.load(f)
            
            for resource_block in parsed.get("resource", []):
                for resource_type, instances in resource_block.items():
                    for name, config in instances.items():
                        logical_id = f"{resource_type}.{name}"
                        norm_resource = NormalizedResource(
                            logical_id=logical_id,
                            resource_type=self._normalize_type(resource_type),
                            provider=self._infer_provider(resource_type),
                            properties=config,
                            references_to=self._extract_tf_references(config),
                            iam_role=self._find_iam_role(resource_type, config),
                            network_config=self._extract_network_config(resource_type, config),
                            encryption_config=self._extract_encryption(resource_type, config),
                            tags=config.get("tags", {})
                        )
                        normalized.resources[logical_id] = norm_resource
        
        # Parse terraform plan JSON if available (more accurate)
        plan_path = f"{tf_directory}/tfplan.json"
        if os.path.exists(plan_path):
            normalized = self._enrich_from_plan(normalized, plan_path)
        
        return normalized
    
    def _extract_tf_references(self, config: dict) -> list[str]:
        """
        Find references like: aws_iam_role.my_role.arn
        or var.xxx, data.xxx.yyy.zzz
        """
        refs = []
        self._walk_for_tf_refs(config, refs)
        return refs
    
    def _walk_for_tf_refs(self, obj, refs):
        if isinstance(obj, str):
            # Match patterns like: aws_iam_role.my_role.arn
            import re
            tf_refs = re.findall(r'((?:aws|data|var|local|module)\.\w+(?:\.\w+)*)', obj)
            refs.extend(tf_refs)
        elif isinstance(obj, dict):
            for value in obj.values():
                self._walk_for_tf_refs(value, refs)
        elif isinstance(obj, list):
            for item in obj:
                self._walk_for_tf_refs(item, refs)
```

### Graph Construction

```python
class InfraGraphBuilder:
    """
    Build three graphs from normalized template.
    All deterministic — no LLM calls.
    """
    
    # AWS resource types that represent compute (can be entry points)
    COMPUTE_TYPES = {
        "AWS::Lambda::Function", "AWS::ECS::TaskDefinition",
        "AWS::EC2::Instance", "AWS::EKS::Cluster",
        "AWS::AppRunner::Service", "AWS::Batch::JobDefinition"
    }
    
    # AWS resource types that represent data stores
    DATA_TYPES = {
        "AWS::DynamoDB::Table", "AWS::RDS::DBInstance", "AWS::RDS::DBCluster",
        "AWS::S3::Bucket", "AWS::ElastiCache::CacheCluster",
        "AWS::Elasticsearch::Domain", "AWS::SecretsManager::Secret",
        "AWS::SSM::Parameter", "AWS::EFS::FileSystem"
    }
    
    # AWS resource types that define network connectivity
    NETWORK_TYPES = {
        "AWS::EC2::VPC", "AWS::EC2::Subnet", "AWS::EC2::SecurityGroup",
        "AWS::EC2::NetworkAcl", "AWS::EC2::RouteTable",
        "AWS::EC2::InternetGateway", "AWS::EC2::NatGateway",
        "AWS::ElasticLoadBalancingV2::LoadBalancer",
        "AWS::ApiGateway::RestApi", "AWS::ApiGatewayV2::Api"
    }
    
    def build_all(self, template: NormalizedTemplate) -> InfraGraphs:
        G_net = self._build_resource_topology(template)
        G_iam = self._build_iam_graph(template)
        G_data = self._build_data_graph(template, G_net, G_iam)
        
        return InfraGraphs(network=G_net, iam=G_iam, data=G_data)
    
    def _build_resource_topology(self, template: NormalizedTemplate) -> nx.DiGraph:
        G = nx.DiGraph()
        
        # Add INTERNET virtual node
        G.add_node("INTERNET", type="virtual", exposure="public")
        
        for res_id, resource in template.resources.items():
            G.add_node(res_id, 
                      type=resource.resource_type,
                      properties=resource.properties,
                      is_compute=resource.resource_type in self.COMPUTE_TYPES,
                      is_data=resource.resource_type in self.DATA_TYPES)
            
            # Explicit reference edges
            for ref in resource.references_to:
                if ref in template.resources:
                    G.add_edge(res_id, ref, relationship="references")
            
            # Semantic edges: public exposure
            if self._is_publicly_accessible(resource, template):
                G.add_edge("INTERNET", res_id, 
                          relationship="public_access",
                          mechanism=self._get_exposure_mechanism(resource))
            
            # Semantic edges: security group associations
            if resource.network_config:
                for sg in resource.network_config.security_groups:
                    G.add_edge(res_id, sg, relationship="uses_security_group")
            
            # Semantic edges: event source mappings (Lambda triggers)
            if resource.resource_type == "AWS::Lambda::EventSourceMapping":
                source = resource.properties.get("EventSourceArn", "")
                target = resource.properties.get("FunctionName", "")
                G.add_edge(source, target, relationship="triggers")
        
        return G
    
    def _build_iam_graph(self, template: NormalizedTemplate) -> nx.DiGraph:
        G = nx.DiGraph()
        
        for res_id, resource in template.resources.items():
            if "IAM::Role" in resource.resource_type:
                G.add_node(res_id, node_type="principal", 
                          resource=resource)
                
                # Trust policy → who can assume this role
                trust = resource.properties.get("AssumeRolePolicyDocument", {})
                for stmt in trust.get("Statement", []):
                    principals = self._extract_trust_principals(stmt)
                    for principal in principals:
                        G.add_edge(principal, res_id,
                                  relationship="can_assume",
                                  condition=stmt.get("Condition"))
                
                # Inline policies → what this role can do
                for policy in resource.properties.get("Policies", []):
                    for stmt in policy.get("PolicyDocument", {}).get("Statement", []):
                        self._add_permission_edges(G, res_id, stmt)
                
                # Managed policy attachments
                for policy_arn in resource.properties.get("ManagedPolicyArns", []):
                    expanded = self.policy_bundle.expand(policy_arn)
                    if expanded:
                        for stmt in expanded["document"]["Statement"]:
                            self._add_permission_edges(G, res_id, stmt, 
                                                     source_policy=policy_arn)
            
            # Resource policies (S3 bucket policy, SQS policy, etc.)
            if self._has_resource_policy(resource):
                policy_doc = self._get_resource_policy(resource)
                for stmt in policy_doc.get("Statement", []):
                    principals = self._extract_principals(stmt)
                    for principal in principals:
                        self._add_permission_edges(G, principal, stmt, 
                                                 target_resource=res_id)
        
        return G
    
    def _add_permission_edges(self, G, principal_id, statement, 
                             source_policy=None, target_resource=None):
        """Add permission edges from a policy statement."""
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        
        resources = statement.get("Resource", ["*"])
        if isinstance(resources, str):
            resources = [resources]
        
        effect = statement.get("Effect", "Allow")
        condition = statement.get("Condition")
        
        # Expand wildcards using action catalog
        expanded_actions = set()
        for action in actions:
            expanded_actions.update(self.action_catalog.expand(action))
        
        for resource_arn in resources:
            target = target_resource or resource_arn
            G.add_edge(principal_id, target,
                      actions=list(expanded_actions),
                      effect=effect,
                      condition=condition,
                      source_policy=source_policy)
```

### Z3 IAM Analyzer

```python
class Z3IAMAnalyzer:
    """
    Formal IAM permission analysis using Z3 SMT solver.
    Proves properties about permissions rather than sampling.
    """
    
    def __init__(self, policy_bundle, action_catalog, escalation_primitives):
        self.policy_bundle = policy_bundle
        self.action_catalog = action_catalog
        self.escalation_primitives = escalation_primitives
    
    def analyze_role(self, role_id: str, G_iam: nx.DiGraph) -> RoleAnalysis:
        """Complete analysis of a single IAM role."""
        
        # 1. Compute effective permissions (transitive closure)
        effective_perms = self._compute_effective_permissions(role_id, G_iam)
        
        # 2. Classify permissions by danger category
        classification = self.action_catalog.classify(effective_perms.actions)
        
        # 3. Check for privilege escalation capability
        escalation = self._check_escalation(effective_perms, G_iam)
        
        # 4. Compute blast radius
        blast_radius = self._compute_blast_radius(role_id, effective_perms, G_iam)
        
        # 5. Formal verification: can this role access admin-level resources?
        admin_proof = self._prove_admin_access(role_id, G_iam)
        
        return RoleAnalysis(
            role_id=role_id,
            effective_permissions=effective_perms,
            classification=classification,
            escalation_paths=escalation,
            blast_radius=blast_radius,
            admin_access=admin_proof,
            risk_tier=self._compute_risk_tier(classification, escalation, blast_radius)
        )
    
    def _compute_effective_permissions(self, role_id, G_iam) -> EffectivePermissions:
        """
        Fixed-point computation of all permissions reachable through role chaining.
        """
        visited = set()
        all_actions = set()
        all_resources = set()
        assume_chain = []
        
        queue = [role_id]
        
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            
            # Direct permissions from this principal
            for _, target, data in G_iam.out_edges(current, data=True):
                if data.get("effect") == "Allow":
                    all_actions.update(data.get("actions", []))
                    all_resources.add(target)
            
            # Assumable roles
            for source, target, data in G_iam.in_edges(current, data=True):
                pass  # already handled above
            
            for _, target, data in G_iam.out_edges(current, data=True):
                if data.get("relationship") == "can_assume":
                    assume_chain.append((current, target))
                    queue.append(target)
        
        return EffectivePermissions(
            actions=all_actions,
            resources=all_resources,
            assume_chain=assume_chain,
            visited_roles=visited
        )
    
    def _check_escalation(self, perms: EffectivePermissions, G_iam) -> list[EscalationPath]:
        """
        Check if this role's permissions include any escalation primitives.
        """
        findings = []
        
        for primitive_name, primitive_def in self.escalation_primitives.items():
            if primitive_def.get("requires_all"):
                # All listed actions must be present
                required = set(primitive_name.split(" + "))
                if required.issubset(perms.actions):
                    findings.append(EscalationPath(
                        method=primitive_name,
                        severity=primitive_def["severity"],
                        description=primitive_def["description"],
                        chain_type=primitive_def["chain"]
                    ))
            else:
                # Single action check
                if primitive_name in perms.actions:
                    findings.append(EscalationPath(
                        method=primitive_name,
                        severity=primitive_def["severity"],
                        description=primitive_def["description"],
                        chain_type=primitive_def["chain"]
                    ))
        
        return findings
    
    def _prove_admin_access(self, role_id, G_iam) -> FormalProof:
        """
        Use Z3 to formally prove whether this role can achieve admin access.
        """
        from z3 import Solver, String, Or, And, Not, sat
        
        solver = Solver()
        
        # Collect all Allow statements for this role
        allow_stmts = self._get_all_allow_statements(role_id, G_iam)
        deny_stmts = self._get_all_deny_statements(role_id, G_iam)
        
        # Encode: can this role perform iam:* on *?
        action = String('action')
        resource = String('resource')
        
        # Action matches any IAM write action
        iam_admin_actions = self.action_catalog.get_dangerous("privilege_escalation")
        
        for target_action in iam_admin_actions:
            solver.push()
            
            # Is there an Allow that covers this action?
            allow_clauses = []
            for stmt in allow_stmts:
                allow_clauses.append(
                    self._action_matches_z3(action, stmt["actions"]) 
                )
            
            # Is there a Deny that blocks it?
            deny_clauses = []
            for stmt in deny_stmts:
                deny_clauses.append(
                    self._action_matches_z3(action, stmt["actions"])
                )
            
            solver.add(Or(allow_clauses))
            if deny_clauses:
                solver.add(Not(Or(deny_clauses)))
            
            if solver.check() == sat:
                return FormalProof(
                    result="PROVEN_POSSIBLE",
                    action=target_action,
                    explanation=f"Role can perform {target_action} — escalation possible"
                )
            
            solver.pop()
        
        return FormalProof(result="PROVEN_SAFE", explanation="No escalation actions reachable")
```

### Toxic Combination Detector

```python
class ToxicCombinationDetector:
    """
    Detect compound risk patterns that span multiple resources and graphs.
    """
    
    def detect(self, G_net: nx.DiGraph, G_iam: nx.DiGraph, 
               G_data: nx.DiGraph, deterministic_findings: list[Finding],
               role_analyses: dict[str, RoleAnalysis]) -> list[Finding]:
        
        compound_findings = []
        
        for pattern in self.toxic_patterns:
            instances = self._match_pattern(
                pattern, G_net, G_iam, G_data, 
                deterministic_findings, role_analyses
            )
            
            for instance in instances:
                compound_findings.append(Finding(
                    id=self._generate_id("toxic", pattern["id"]),
                    agent="infrastructure",
                    category="toxic_combination",
                    severity=Severity[pattern["combined_severity"]],
                    confidence=Confidence.HIGH,  # Deterministic detection
                    title=pattern["name"],
                    description=self._build_narrative(pattern, instance),
                    evidence=Evidence(
                        snippet=self._render_resources(instance.resources),
                        graph_context=self._render_subgraph(instance, G_net),
                        reasoning=pattern["attack_narrative"]
                    ),
                    location=Location(
                        file_path=instance.primary_resource.file,
                        start_line=0,
                        end_line=0,
                        resource_id=instance.primary_resource.logical_id
                    ),
                    attack_path=instance.attack_steps,
                    blast_radius=instance.affected_resources
                ))
        
        return compound_findings
    
    def _match_pattern(self, pattern, G_net, G_iam, G_data, findings, analyses):
        """
        Check if pattern components are satisfied by actual infrastructure.
        Each component is a predicate over the graphs.
        """
        PREDICATES = {
            "publicly_reachable_compute": lambda r: (
                G_net.has_edge("INTERNET", r) and 
                G_net.nodes[r].get("is_compute")
            ),
            "overpermissive_role": lambda r: (
                r in analyses and 
                analyses[r].risk_tier in ("CRITICAL", "HIGH")
            ),
            "imdsv1_enabled": lambda r: (
                G_net.nodes[r].get("type") == "AWS::EC2::Instance" and
                not self._has_imdsv2(G_net.nodes[r].get("properties", {}))
            ),
            "unencrypted_data_store": lambda r: (
                any(f.rule_id.startswith("ENC-") and f.location.resource_id == r 
                    for f in findings)
            ),
            "no_waf": lambda r: (
                not any(G_net.has_edge(waf, r) 
                       for waf in G_net.nodes() 
                       if "WAF" in G_net.nodes[waf].get("type", ""))
            ),
            "cross_account_trust_no_external_id": lambda r: (
                any(data.get("condition") is None 
                    for _, _, data in G_iam.in_edges(r, data=True)
                    if data.get("relationship") == "can_assume" 
                    and self._is_cross_account(data))
            ),
        }
        
        instances = []
        compute_nodes = [n for n in G_net.nodes() if G_net.nodes[n].get("is_compute")]
        
        for resource in compute_nodes:
            all_match = True
            matched_components = []
            
            for component_desc in pattern["component_predicates"]:
                predicate = PREDICATES.get(component_desc)
                if predicate and predicate(resource):
                    matched_components.append(component_desc)
                else:
                    all_match = False
                    break
            
            if all_match:
                instances.append(PatternInstance(
                    primary_resource=resource,
                    matched_components=matched_components,
                    resources=self._get_affected_resources(resource, G_net),
                    attack_steps=self._build_attack_steps(pattern, resource, G_net, G_iam)
                ))
        
        return instances
```

### Infrastructure LLM Reasoning

```python
class InfraContextualAnalyzer:
    """
    LLM reasoning for infrastructure findings that require judgment.
    Only invoked for findings that deterministic checks cannot resolve.
    """
    
    SYSTEM_PROMPT = """You are a senior cloud security architect specializing in AWS 
infrastructure security. You are reviewing infrastructure-as-code for a production 
deployment. You reason about security holistically — considering network topology, 
IAM permissions, data sensitivity, and their interactions."""

    INFRA_COT_TEMPLATE = """Analyze this infrastructure configuration for security issues.

RESOURCE UNDER ANALYSIS:
{resource_config}

GRAPH POSITION (what connects to this resource):
{graph_context}

EFFECTIVE PERMISSIONS (formally proven via SMT solver):
{effective_permissions}

DETERMINISTIC FINDINGS (established facts about this resource):
{deterministic_facts}

RELEVANT SECURITY RULES:
{applicable_rules}

ATTACK PATHS INVOLVING THIS RESOURCE:
{attack_paths}

---

STEP 1 — CONTEXT: What is this resource's role in the architecture? What data does 
it handle? Who/what accesses it? Is this a production workload?

STEP 2 — EXPOSURE: Is this resource reachable from untrusted networks? What is the 
full network path? What controls exist on that path (WAF, SG, NACL, VPC endpoint)?

STEP 3 — PERMISSIONS: Are the attached permissions proportionate to the resource's 
function? What specific permissions are excessive? What is the blast radius if this 
resource is compromised?

STEP 4 — COMBINATIONS: Do any individual findings combine into a more severe compound 
issue? Consider the full attack chain from entry to impact.

STEP 5 — VERIFY: Challenge your reasoning:
  - Could conditions or permission boundaries limit the effective scope?
  - Is the network exposure mitigated by controls not visible in the template?
  - Is this severity appropriate, or am I over/under-estimating?
  - Would this survive in a real threat model, or is it purely theoretical?
  - Are there organizational controls (SCPs, Config rules) that might mitigate?

STEP 6 — VERDICT + REMEDIATION:
  {{ CRITICAL | HIGH | MEDIUM | LOW | ACCEPTABLE }}
  Confidence: {{ HIGH | MEDIUM | LOW }}
  If finding: describe the attack scenario and propose a specific minimal fix.
  If acceptable: explain why the current configuration is appropriate."""

    def analyze(self, resource: NormalizedResource, 
                context: InfraAnalysisContext) -> Finding | None:
        """Analyze a resource that requires contextual judgment."""
        
        prompt = self.INFRA_COT_TEMPLATE.format(
            resource_config=self._render_resource(resource),
            graph_context=self._render_graph_position(resource, context.G_net),
            effective_permissions=self._render_permissions(resource, context.role_analyses),
            deterministic_facts=self._render_deterministic(resource, context.findings),
            applicable_rules=self._render_rules(resource, context.security_rules),
            attack_paths=self._render_attack_paths(resource, context.attack_paths)
        )
        
        response = self.llm_client.analyze(
            system_prompt=self.SYSTEM_PROMPT,
            user_prompt=prompt,
            temperature=0.1
        )
        
        return self._parse_infra_verdict(response, resource)
```

### Remediation Generator

```python
class InfraRemediationGenerator:
    """
    Generate and validate infrastructure fixes.
    Uses RAG with security best practices and few-shot examples.
    """
    
    REMEDIATION_PROMPT = """Fix the following infrastructure security issue.

FINDING:
{finding_description}

CURRENT CONFIGURATION:
{current_config}

SECURITY BEST PRACTICE (from AWS/CIS):
{best_practice}

SIMILAR FIX EXAMPLES:
{few_shot_examples}

Generate the corrected configuration that:
1. Fixes the security issue
2. Preserves the resource's operational functionality
3. Follows AWS best practices
4. Is minimally invasive (smallest change that fixes the issue)
5. Does NOT modify or delete any unrelated configurations
6. Includes comments explaining the security-relevant changes

Output ONLY the corrected configuration block (no explanation outside the code)."""

    def generate_fix(self, finding: Finding, template: NormalizedTemplate) -> Remediation:
        # Get relevant best practice from knowledge base
        best_practice = self.knowledge.get_rule(finding.category)
        
        # Get few-shot examples of similar fixes
        examples = self.knowledge.get_fix_examples(finding.category, n=2)
        
        prompt = self.REMEDIATION_PROMPT.format(
            finding_description=finding.description,
            current_config=self._render_current_config(finding, template),
            best_practice=best_practice,
            few_shot_examples=self._render_examples(examples)
        )
        
        response = self.llm_client.analyze(
            system_prompt="You are an AWS solutions architect generating secure infrastructure configurations.",
            user_prompt=prompt,
            temperature=0.1
        )
        
        fix_diff = self._parse_fix(response)
        
        # Validate the fix
        validation = self._validate_fix(fix_diff, finding, template)
        
        return Remediation(
            fix_diff=fix_diff,
            explanation=f"Fixes {finding.title} by {self._summarize_change(fix_diff)}",
            validated=validation.passed,
            validation_result=validation.status
        )
    
    def _validate_fix(self, fix_diff: str, finding: Finding, 
                      template: NormalizedTemplate) -> ValidationResult:
        """
        Validate that the fix actually resolves the issue without regressions.
        """
        # Apply fix to template copy
        fixed_template = self._apply_diff(template, fix_diff)
        
        # Check 1: Template still syntactically valid?
        if not self._is_valid_template(fixed_template):
            return ValidationResult(passed=False, status="INVALID_SYNTAX")
        
        # Check 2: No resources deleted?
        original_resources = set(template.resources.keys())
        fixed_resources = set(fixed_template.resources.keys())
        if original_resources - fixed_resources:
            return ValidationResult(passed=False, status="DESTRUCTIVE_DELETION",
                                   detail=f"Deleted: {original_resources - fixed_resources}")
        
        # Check 3: Original finding resolved?
        new_findings = self.deterministic_checker.check(fixed_template)
        if any(f.id == finding.id for f in new_findings):
            return ValidationResult(passed=False, status="NOT_RESOLVED")
        
        # Check 4: No new findings introduced?
        original_findings = self.deterministic_checker.check(template)
        regressions = set(new_findings) - set(original_findings)
        if regressions:
            return ValidationResult(passed=False, status="REGRESSION",
                                   detail=f"New issues: {regressions}")
        
        return ValidationResult(passed=True, status="VALIDATED")
```

---

## Agent 5: Validation Agent

### Purpose

Adversarial false positive elimination. Receives candidate findings from all other agents and challenges each one. Operates with a fundamentally different persona (skeptic, not detective).

### Internal Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                       VALIDATION AGENT                                   │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ BATCH PROCESSOR                                                     │ │
│  │                                                                      │ │
│  │  Input: list[Finding] from agents 2, 3, 4                           │ │
│  │                                                                      │ │
│  │  ┌────────────┐  ┌────────────────┐  ┌──────────────────────────┐  │ │
│  │  │ Severity   │  │ Context        │  │ Adversarial LLM          │  │ │
│  │  │ Filter     │  │ Enricher       │  │ Analysis                 │  │ │
│  │  │(skip LOW)  │  │(fetch extra    │  │(argue why NOT vulnerable)│  │ │
│  │  │            │  │ context)       │  │                          │  │ │
│  │  └─────┬──────┘  └───────┬────────┘  └─────────────┬────────────┘  │ │
│  │        │                  │                          │               │ │
│  │        └──────────────────┼──────────────────────────┘               │ │
│  │                           ▼                                          │ │
│  │              ┌──────────────────────────┐                            │ │
│  │              │ VERDICT ASSIGNMENT        │                            │ │
│  │              │                          │                            │ │
│  │              │ CONFIRMED → keep finding │                            │ │
│  │              │ DISMISSED  → remove      │                            │ │
│  │              │ UNCERTAIN → flag review  │                            │ │
│  │              └──────────────────────────┘                            │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│                                                                          │
└────────────────────────────────────────────────────────────────────────┘
```

### Design

```python
class ValidationAgent:
    """
    Adversarial false positive filter.
    
    Key design principle: This agent has a DIFFERENT PERSONA from detection agents.
    It is a skeptic. Its job is to argue AGAINST the finding.
    If it cannot construct a convincing counter-argument, the finding stands.
    
    This separation prevents the detection agent from self-confirming its own bias.
    """
    
    SYSTEM_PROMPT = """You are a senior security engineer acting as a skeptic and 
defense counsel. Your role is to critically evaluate security findings and determine 
whether they represent real, exploitable vulnerabilities or false positives.

You should approach each finding with skepticism — looking for reasons it might NOT 
be exploitable. You are protecting development teams from alert fatigue by ensuring 
only genuine vulnerabilities reach them.

However, you must be intellectually honest. If you cannot find a valid reason a 
finding is safe, you must confirm it. Do not dismiss findings without sound reasoning."""

    ADVERSARIAL_TEMPLATE = """A security scanner has flagged the following as a vulnerability:

FINDING:
  Category: {category}
  Severity: {severity}
  Title: {title}
  Description: {description}
  
EVIDENCE:
  {evidence}

ADDITIONAL CONTEXT (retrieved for your evaluation):
  {additional_context}

---

Your task is to argue why this finding is NOT exploitable. Systematically consider:

1. PRECONDITIONS: Are there authentication, authorization, or other checks that 
   prevent an attacker from reaching this code path?

2. FRAMEWORK PROTECTIONS: Does the framework provide implicit protections not visible 
   in the code? (e.g., Django's CSRF protection, React's JSX escaping, AWS SDK 
   parameterized queries)

3. TYPE CONSTRAINTS: Do type system guarantees or runtime checks limit what an 
   attacker can provide as input?

4. SANITIZER SUFFICIENCY: Is the identified sanitizer actually sufficient despite 
   appearing incomplete? (e.g., a custom validator that handles all edge cases)

5. CONTEXT LIMITATIONS: Is the sink actually dangerous in this specific context? 
   (e.g., exec() used with a hardcoded format string, not user input)

6. ENVIRONMENTAL CONTROLS: Would WAF, network isolation, permission boundaries, 
   or other infrastructure controls prevent exploitation in practice?

7. EXPLOITABILITY: Even if theoretically vulnerable, is exploitation actually 
   feasible given real-world constraints? (e.g., race condition with microsecond 
   window, requires physical access)

---

VERDICT (choose exactly one):

CONFIRMED — I cannot find a valid reason this is safe. The vulnerability is real 
and exploitable.

DISMISSED — I have found a convincing reason this is not exploitable: [explain].
The finding should be removed.

UNCERTAIN — There are factors that might prevent exploitation, but I cannot be sure 
without additional information: [what information is needed]. Flag for human review."""

    def validate_batch(self, findings: list[Finding]) -> list[ValidatedFinding]:
        """
        Validate a batch of findings. Skip LOW severity (not worth LLM cost).
        Process CRITICAL first (most important to confirm).
        """
        results = []
        
        # Sort: CRITICAL first, skip LOW
        to_validate = sorted(
            [f for f in findings if f.severity != Severity.LOW],
            key=lambda f: f.severity.value,
            reverse=True
        )
        
        for finding in to_validate:
            # Enrich with additional context beyond what the detection agent saw
            additional_context = self._fetch_additional_context(finding)
            
            prompt = self.ADVERSARIAL_TEMPLATE.format(
                category=finding.category,
                severity=finding.severity.name,
                title=finding.title,
                description=finding.description,
                evidence=finding.evidence.snippet,
                additional_context=additional_context
            )
            
            response = self.llm_client.analyze(
                system_prompt=self.SYSTEM_PROMPT,
                user_prompt=prompt,
                temperature=0.2  # Slightly higher for creative counter-arguments
            )
            
            verdict = self._parse_verdict(response)
            
            results.append(ValidatedFinding(
                original=finding,
                verdict=verdict.decision,  # CONFIRMED | DISMISSED | UNCERTAIN
                reasoning=verdict.explanation,
                validated_severity=self._adjust_severity(finding, verdict),
                validated_confidence=self._adjust_confidence(finding, verdict)
            ))
        
        # LOW severity findings pass through without validation
        for finding in findings:
            if finding.severity == Severity.LOW:
                results.append(ValidatedFinding(
                    original=finding,
                    verdict="CONFIRMED",
                    reasoning="Low severity — passed without adversarial validation",
                    validated_severity=Severity.LOW,
                    validated_confidence=finding.confidence
                ))
        
        return results
    
    def _fetch_additional_context(self, finding: Finding) -> str:
        """
        Fetch context that the detection agent might not have included.
        This gives the validation agent a broader view for its assessment.
        """
        context_parts = []
        
        # For app findings: check for authentication middleware, decorators
        if finding.agent in ("python", "javascript"):
            auth_context = self._check_auth_decorators(finding.location)
            if auth_context:
                context_parts.append(f"Authentication context: {auth_context}")
            
            framework_protections = self._check_framework_defaults(finding)
            if framework_protections:
                context_parts.append(f"Framework protections: {framework_protections}")
        
        # For infra findings: check for SCPs, Config rules, org-level controls
        if finding.agent == "infrastructure":
            org_controls = self._check_organizational_controls(finding)
            if org_controls:
                context_parts.append(f"Organizational controls: {org_controls}")
        
        return "\n".join(context_parts) if context_parts else "No additional context found."
    
    def _adjust_severity(self, finding: Finding, verdict) -> Severity:
        """
        Adjust severity based on validation result.
        DISMISSED → removed entirely (not just downgraded)
        UNCERTAIN → downgrade by one level
        CONFIRMED → keep original severity
        """
        if verdict.decision == "CONFIRMED":
            return finding.severity
        elif verdict.decision == "UNCERTAIN":
            # Downgrade one level
            if finding.severity == Severity.CRITICAL:
                return Severity.HIGH
            elif finding.severity == Severity.HIGH:
                return Severity.MEDIUM
            else:
                return finding.severity
        else:  # DISMISSED
            return None  # Will be filtered out
```

---

## Execution Lifecycle (Full Scan)

```python
class SecurityScanOrchestrator:
    """
    Main entry point. Coordinates the full scan lifecycle.
    """
    
    def scan(self, repo_path: str, config: ScanConfig) -> SecurityReport:
        # Phase 1: Discovery
        manifest = self.repo_scanner.scan(repo_path)
        plan = self.execution_planner.plan(manifest, config)
        
        # Initialize state
        global_state = GlobalState(plan=plan)
        self.state_manager.save_checkpoint(global_state)
        
        # Phase 2-4: Dispatch agents (parallel where possible)
        agent_results = {}
        
        for parallel_group in plan.parallel_groups:
            # Run agents in this group concurrently
            futures = {}
            for agent_spec in parallel_group:
                agent = self._create_agent(agent_spec)
                futures[agent_spec.type] = self._run_agent_async(agent, agent_spec)
            
            # Collect results
            for agent_type, future in futures.items():
                result = future.result()
                agent_results[agent_type] = result
                self.state_manager.save_checkpoint(global_state)
        
        # Collect all candidate findings
        all_candidates = []
        for result in agent_results.values():
            all_candidates.extend(result.candidate_findings)
        
        # Phase 3.5: Validation (adversarial)
        validated = self.validation_agent.validate_batch(all_candidates)
        
        # Filter: only CONFIRMED and UNCERTAIN
        confirmed_findings = [
            v.original for v in validated 
            if v.verdict in ("CONFIRMED", "UNCERTAIN")
        ]
        
        # Phase 5: Cross-boundary correlation
        app_findings = [f for f in confirmed_findings if f.agent in ("python", "javascript")]
        infra_findings = [f for f in confirmed_findings if f.agent == "infrastructure"]
        
        compound_findings = []
        if app_findings and infra_findings:
            compound_findings = self.correlator.correlate(
                app_findings, infra_findings, manifest.cross_references
            )
        
        # Phase 6: Report
        all_findings = confirmed_findings + compound_findings
        report = self.report_generator.generate(ScanResult(
            findings=all_findings,
            validated=validated,
            agent_states=agent_results,
            compound_findings=compound_findings,
            manifest=manifest
        ))
        
        return report
    
    def resume(self, checkpoint_path: str) -> SecurityReport:
        """Resume from last checkpoint after interruption."""
        global_state = self.state_manager.load_checkpoint(checkpoint_path)
        
        # Determine what's already done
        completed_agents = {k for k, v in global_state.agent_results.items() 
                          if v.status == AgentStatus.COMPLETE}
        
        # Resume incomplete agents from their own checkpoints
        for agent_spec in global_state.plan.agents:
            if agent_spec.type not in completed_agents:
                agent = self._create_agent(agent_spec)
                result = agent.resume(global_state.agent_checkpoints[agent_spec.type])
                global_state.agent_results[agent_spec.type] = result
        
        # Continue from Phase 3.5 onward
        # ... (same as above)
```

---

## Directory Structure

```
security-agent/
├── REQUIREMENTS.md
├── DESIGN.md
├── src/
│   ├── __init__.py
│   ├── main.py                        # CLI entry point
│   ├── config.py                      # ScanConfig, defaults
│   │
│   ├── orchestrator/                  # Agent 1
│   │   ├── __init__.py
│   │   ├── scanner.py                 # RepoScanner
│   │   ├── planner.py                 # ExecutionPlanner
│   │   ├── dispatcher.py             # Agent lifecycle management
│   │   ├── correlator.py             # CrossBoundaryCorrelator
│   │   ├── state.py                   # GlobalState, checkpoint management
│   │   └── report.py                 # ReportGenerator
│   │
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── base.py                    # BaseAgent (shared interface)
│   │   │
│   │   ├── python/                    # Agent 2
│   │   │   ├── __init__.py
│   │   │   ├── agent.py              # PythonSecurityAgent (orchestrates phases)
│   │   │   ├── spec_inference.py     # Phase 0: LLM spec inference
│   │   │   ├── cpg_builder.py        # Phase 2: tree-sitter → CPG
│   │   │   ├── cpg_slicer.py         # CPG slice extraction
│   │   │   ├── taint_analyzer.py     # Phase 3: LLM taint reasoning
│   │   │   └── knowledge.py          # Python-specific sources/sinks/CWEs
│   │   │
│   │   ├── javascript/                # Agent 3
│   │   │   ├── __init__.py
│   │   │   ├── agent.py              # JavaScriptSecurityAgent
│   │   │   ├── spec_inference.py     # Phase 0: JS-specific inference
│   │   │   ├── cpg_builder.py        # Phase 2: tree-sitter TS → CPG
│   │   │   ├── cpg_slicer.py         # CPG slice extraction
│   │   │   ├── taint_analyzer.py     # Phase 3: JS-specific taint reasoning
│   │   │   └── knowledge.py          # JS-specific sources/sinks/CWEs
│   │   │
│   │   ├── infrastructure/            # Agent 4
│   │   │   ├── __init__.py
│   │   │   ├── agent.py              # InfraSecurityAgent (orchestrates phases)
│   │   │   ├── parsers/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── cfn_parser.py     # CloudFormation JSON parser
│   │   │   │   ├── hcl_parser.py     # Terraform HCL parser
│   │   │   │   └── normalizer.py     # Both → NormalizedTemplate
│   │   │   ├── graphs/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── builder.py        # InfraGraphBuilder (all 3 graphs)
│   │   │   │   ├── network.py        # G_net construction helpers
│   │   │   │   ├── iam.py            # G_iam construction helpers
│   │   │   │   └── data.py           # G_data construction helpers
│   │   │   ├── analyzers/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── deterministic.py  # 40+ rule-based checks
│   │   │   │   ├── z3_iam.py         # Z3 formal IAM analysis
│   │   │   │   ├── attack_paths.py   # Attack path enumeration
│   │   │   │   ├── toxic_combos.py   # Toxic combination detection
│   │   │   │   └── blast_radius.py   # Blast radius computation
│   │   │   ├── contextual.py         # LLM contextual reasoning
│   │   │   └── remediation.py        # Fix generation + validation
│   │   │
│   │   └── validation/                # Agent 5
│   │       ├── __init__.py
│   │       ├── agent.py              # ValidationAgent
│   │       ├── context_enricher.py   # Fetch additional context for findings
│   │       └── verdict.py            # Verdict parsing and severity adjustment
│   │
│   ├── common/
│   │   ├── __init__.py
│   │   ├── llm_client.py            # Claude API wrapper (with retry, caching)
│   │   ├── graph.py                  # CodePropertyGraph class, NetworkX helpers
│   │   ├── checkpoint.py            # Checkpoint save/load/resume logic
│   │   ├── chunker.py               # Token budget management, chunk creation
│   │   ├── findings.py              # Finding, Evidence, Location dataclasses
│   │   ├── coverage.py              # CoverageMetrics computation
│   │   └── cost.py                  # Cost tracking, budget enforcement
│   │
│   └── knowledge/                    # Ground truth data (bundled)
│       ├── __init__.py
│       ├── loader.py                 # Load and query knowledge base
│       ├── aws_managed_policies.json
│       ├── aws_action_catalog.json
│       ├── aws_security_rules.json
│       ├── iam_escalation_paths.json
│       ├── toxic_combinations.json
│       ├── cwe_definitions.json
│       ├── vulnerability_patterns.json
│       ├── resource_connections.json
│       ├── python_sources_sinks.json
│       ├── javascript_sources_sinks.json
│       └── refresh_policies.py       # Script to update from AWS
│
├── tests/
│   ├── __init__.py
│   ├── test_orchestrator/
│   ├── test_python_agent/
│   ├── test_javascript_agent/
│   ├── test_infra_agent/
│   ├── test_validation_agent/
│   ├── fixtures/                     # Test IaC templates, Python code samples
│   │   ├── terragoat/               # Intentionally vulnerable Terraform
│   │   ├── vulnerable_python/       # Intentionally vulnerable Python apps
│   │   └── secure_baseline/         # Known-good configurations
│   └── integration/
│       └── test_full_scan.py         # End-to-end test
│
├── pyproject.toml
└── Makefile
```

---

## Configuration

```python
@dataclass
class ScanConfig:
    # Budget
    total_budget: float = 5.00           # USD max spend per scan
    validation_budget: float = 1.00       # USD allocated to validation agent
    
    # Agent enablement
    enable_python: bool = True
    enable_javascript: bool = True
    enable_infrastructure: bool = True
    
    # Severity threshold
    min_severity: Severity = Severity.LOW  # Report findings at this level and above
    fail_threshold: Severity = Severity.HIGH  # CI gate fails at this level
    
    # LLM configuration
    reasoning_model: str = "claude-opus-4-6-20250414"   # Complex reasoning
    fast_model: str = "claude-sonnet-4-6-20250414"      # Spec inference, validation
    temperature: float = 0.1
    max_retries: int = 2
    
    # Analysis depth
    max_taint_paths: int = 100           # Cap on paths to analyze (knapsack selects best)
    max_path_length: int = 15            # Max hops in a taint path
    cpg_slice_budget: int = 20000        # Tokens per chunk
    
    # Checkpoint
    checkpoint_dir: str = ".security-agent/checkpoints"
    resume_from: str | None = None       # Path to checkpoint to resume from
    
    # Output
    output_format: str = "json"          # "json" | "sarif" | "markdown"
    output_path: str = "security-report"
```

---

## LLM Client Design

```python
class LLMClient:
    """
    Shared LLM client with:
    - Model selection (Opus for reasoning, Sonnet for fast tasks)
    - Cost tracking and budget enforcement
    - Retry with backoff
    - Response caching (for deterministic prompts)
    - Context window positioning optimization
    """
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.cost_tracker = CostTracker(budget=config.total_budget)
        self.cache = ResponseCache()
    
    def analyze(self, system_prompt: str, user_prompt: str,
                model: str = None, temperature: float = None,
                task_type: str = "reasoning") -> str:
        """
        Send analysis request to Claude.
        Enforces budget, tracks cost, handles retries.
        """
        model = model or self._select_model(task_type)
        temperature = temperature or self.config.temperature
        
        # Check budget
        estimated_cost = self._estimate_cost(system_prompt, user_prompt, model)
        if not self.cost_tracker.can_afford(estimated_cost):
            raise BudgetExhausted(
                f"Estimated cost ${estimated_cost:.3f} exceeds remaining budget "
                f"${self.cost_tracker.remaining:.3f}"
            )
        
        # Check cache (for deterministic prompts)
        cache_key = self._cache_key(system_prompt, user_prompt, model)
        if cached := self.cache.get(cache_key):
            return cached
        
        # Make API call with retry
        response = self._call_with_retry(
            model=model,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
            temperature=temperature,
            max_tokens=4096
        )
        
        # Track cost
        actual_cost = self._compute_cost(response.usage, model)
        self.cost_tracker.record(actual_cost)
        
        # Cache response
        self.cache.set(cache_key, response.content)
        
        return response.content
    
    def _select_model(self, task_type: str) -> str:
        """
        Opus for complex reasoning (taint analysis, correlation).
        Sonnet for simpler tasks (spec inference, validation, remediation).
        """
        if task_type in ("reasoning", "correlation", "contextual"):
            return self.config.reasoning_model
        else:  # "inference", "validation", "remediation"
            return self.config.fast_model
    
    def _call_with_retry(self, **kwargs) -> APIResponse:
        """Retry with exponential backoff on rate limit or transient errors."""
        for attempt in range(self.config.max_retries + 1):
            try:
                return self.api.messages.create(**kwargs)
            except RateLimitError:
                if attempt < self.config.max_retries:
                    wait = 2 ** attempt
                    time.sleep(wait)
                else:
                    raise
            except TransientError:
                if attempt < self.config.max_retries:
                    time.sleep(1)
                else:
                    raise
```

---

## Checkpoint System Design

```python
class CheckpointManager:
    """
    Persistence layer for scan state.
    Guarantees: no work is lost, no work is repeated.
    """
    
    def save(self, state: AgentState, checkpoint_dir: str):
        """
        Atomic save: write to temp file, then rename.
        Prevents corruption from mid-write crashes.
        """
        checkpoint_path = os.path.join(
            checkpoint_dir, 
            f"{state.agent_id}_phase{state.phase}_chunk{state.chunk_index}.json"
        )
        
        temp_path = checkpoint_path + ".tmp"
        with open(temp_path, 'w') as f:
            json.dump(asdict(state), f, indent=2, default=str)
        
        os.rename(temp_path, checkpoint_path)  # Atomic on POSIX
        
        # Keep only latest 3 checkpoints per agent (disk space)
        self._prune_old_checkpoints(checkpoint_dir, state.agent_id, keep=3)
    
    def load_latest(self, agent_id: str, checkpoint_dir: str) -> AgentState | None:
        """Load the most recent checkpoint for an agent."""
        checkpoints = sorted(
            glob.glob(os.path.join(checkpoint_dir, f"{agent_id}_*.json")),
            key=os.path.getmtime,
            reverse=True
        )
        
        if not checkpoints:
            return None
        
        with open(checkpoints[0]) as f:
            data = json.load(f)
        
        return AgentState(**data)
    
    def can_resume(self, agent_id: str, checkpoint_dir: str) -> bool:
        """Check if a valid checkpoint exists for this agent."""
        state = self.load_latest(agent_id, checkpoint_dir)
        return state is not None and state.status != AgentStatus.COMPLETE
```

---

## Error Handling Strategy

```python
class AgentErrorHandler:
    """
    Handle errors at each level without losing progress.
    """
    
    def handle_llm_error(self, error, state: AgentState, chunk: AnalysisChunk):
        """
        LLM call failed (rate limit, timeout, budget exhausted).
        """
        if isinstance(error, BudgetExhausted):
            # Save progress, report partial coverage
            state.status = AgentStatus.CHECKPOINTED
            state.error = f"Budget exhausted after analyzing {state.chunk_index} chunks"
            return AgentAction.STOP_GRACEFULLY
        
        elif isinstance(error, RateLimitError):
            # Already retried in LLM client; if here, retries exhausted
            state.status = AgentStatus.CHECKPOINTED
            state.error = "Rate limit exhausted after retries"
            return AgentAction.STOP_GRACEFULLY
        
        elif isinstance(error, InvalidResponse):
            # LLM returned unparseable response
            # Skip this chunk, continue with next
            state.pending_analysis.remove(chunk)
            state.coverage.note_skipped(chunk, reason="unparseable_response")
            return AgentAction.CONTINUE_NEXT_CHUNK
    
    def handle_parse_error(self, error, file_path: str, state: AgentState):
        """
        File couldn't be parsed (syntax error, encoding issue).
        """
        # Skip file, note in coverage
        state.coverage.note_skipped_file(file_path, reason=str(error))
        return AgentAction.CONTINUE
    
    def handle_graph_error(self, error, state: AgentState):
        """
        Graph construction failed (unexpected structure).
        """
        state.status = AgentStatus.FAILED
        state.error = f"Graph construction failed: {error}"
        return AgentAction.ABORT
```
