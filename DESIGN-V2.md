# Security Agent v2 — Redesigned Architecture

## The Problem with v1

Our v1 had two disconnected worlds:
1. **Python code** — built a weak graph (regex DFG, no inter-procedural flow, 0 taint paths found)
2. **LLM reasoning** — read raw code and did ad-hoc analysis (no structured trace, skipped steps)

Neither used the other properly. The graph was too weak to find anything, and the LLM wasn't grounded in graph evidence.

## The v2 Insight

**Chain-of-Thought doesn't just reason — it COORDINATES computation.**

Each CoT step can:
- REQUEST data from the graph (Joern query)
- REQUEST code execution (Python analysis)
- REASON about results
- DECIDE next step

This is the **ReAct pattern** (Reason + Act) applied to security analysis:

```
THINK: "I need to know where customer_id originates"
ACT:   joern.query("cpg.identifier('customer_id').reachableByFlows(cpg.call('.*get.*')).l")
OBSERVE: [node at handler_v2.py:369, flows from body.get("customer_id")]
THINK: "It comes from request body. I need to check if it's validated against auth context"
ACT:   joern.query("cpg.call('.*get.*authorizer.*').inFile('handler_v2').l")
OBSERVE: [] (empty — no auth context access)
THINK: "No auth context is accessed. This is a cross-tenant vulnerability."
```

---

## Architecture: CoT-Orchestrated Graph Analysis

```
┌─────────────────────────────────────────────────────────────────┐
│                    CHAIN-OF-THOUGHT ENGINE                        │
│                                                                   │
│  The CoT is the ORCHESTRATOR. It doesn't just reason —           │
│  it drives the entire analysis by requesting computations.       │
│                                                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  STEP 1: IDENTIFY                                          │  │
│  │  Think: "What sources exist in this handler?"              │  │
│  │  Act:   query_sources(file="handler_v2.py")                │  │
│  │  Observe: [body.get("customer_id"):369, headers.get():369] │  │
│  │  Think: "customer_id from body and headers. Both tainted." │  │
│  ├───────────────────────────────────────────────────────────┤  │
│  │  STEP 2: TRACE                                             │  │
│  │  Think: "Where does customer_id flow to?"                  │  │
│  │  Act:   forward_taint("customer_id", file="handler_v2.py") │  │
│  │  Observe: [→ _handle_start:param, → _save_session:param,  │  │
│  │            → table.put_item:item.customer_id,              │  │
│  │            → lambda.invoke:payload.customer_id]            │  │
│  │  Think: "It reaches DynamoDB write AND Lambda invoke."     │  │
│  ├───────────────────────────────────────────────────────────┤  │
│  │  STEP 3: ASSESS                                            │  │
│  │  Think: "Is there any validation before the sink?"         │  │
│  │  Act:   find_sanitizers_between(source=369, sink=135)      │  │
│  │  Observe: [] (empty — no sanitizers)                       │  │
│  │  Act:   find_auth_context_usage(file="handler_v2.py")      │  │
│  │  Observe: [] (empty — authorizer context never accessed)   │  │
│  │  Think: "No sanitization. No auth context. Unprotected."   │  │
│  ├───────────────────────────────────────────────────────────┤  │
│  │  STEP 4: CONCLUDE                                          │  │
│  │  Think: "Tainted data reaches sink unsanitized."           │  │
│  │  Act:   check_iam_constraints("sessions_table")            │  │
│  │  Observe: "No LeadingKeys condition. Full table access."   │  │
│  │  Think: "No defense-in-depth either. VULNERABLE."          │  │
│  ├───────────────────────────────────────────────────────────┤  │
│  │  STEP 5: VERIFY                                            │  │
│  │  Think: "Could the API Gateway authorizer prevent this?"   │  │
│  │  Act:   check_authorizer_coverage("handler_v2")            │  │
│  │  Observe: "Authorizer present but injects to                │  │
│  │           requestContext.authorizer — handler ignores it"   │  │
│  │  Think: "Authorizer validates JWT but handler doesn't use  │  │
│  │          the injected tenant_id. Vuln confirmed."           │  │
│  ├───────────────────────────────────────────────────────────┤  │
│  │  STEP 6: VERDICT                                           │  │
│  │  VULNERABLE | Confidence: HIGH | Severity: CRITICAL        │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                   │
│         ↕ calls            ↕ calls            ↕ calls            │
│                                                                   │
│  ┌─────────────┐    ┌─────────────┐    ┌──────────────────┐     │
│  │   JOERN     │    │   PYTHON    │    │   KNOWLEDGE      │     │
│  │   CPG       │    │   TOOLS     │    │   BASE           │     │
│  │             │    │             │    │                  │     │
│  │ - taint     │    │ - IAM graph │    │ - CWE defs      │     │
│  │ - reachable │    │ - blast rad │    │ - Exploit pats  │     │
│  │ - slice     │    │ - toxic det │    │ - FP patterns   │     │
│  │ - callgraph │    │ - infra chk │    │ - Breach cases  │     │
│  └─────────────┘    └─────────────┘    └──────────────────┘     │
└─────────────────────────────────────────────────────────────────┘
```

---

## The Tool Interface

The CoT engine has access to these tools (callable from Python):

### Joern CPG Tools

```python
class JoernTools:
    """Interface to Joern's Code Property Graph."""

    def query(self, cpg_query: str) -> list[dict]:
        """Execute a Joern/CPGQL query and return results."""
        # Executes via joern-cli or joern-server REST API
        pass

    def forward_taint(self, variable: str, file: str, line: int) -> list[TaintStep]:
        """
        Trace where a variable's value flows to (forward from source).
        Uses Joern's built-in taint tracking.
        
        Returns ordered list of steps:
        [
            TaintStep(file="handler_v2.py", line=369, code="customer_id = body.get(...)", type="source"),
            TaintStep(file="handler_v2.py", line=376, code="_handle_start(body, customer_id, ...)", type="propagation"),
            TaintStep(file="handler_v2.py", line=135, code="_save_session(session_id, customer_id, ...)", type="propagation"),
            TaintStep(file="handler_v2.py", line=49, code='item["customer_id"] = customer_id', type="propagation"),
            TaintStep(file="handler_v2.py", line=60, code="table.put_item(Item=item)", type="sink"),
        ]
        """
        pass

    def backward_slice(self, variable: str, file: str, line: int) -> list[dict]:
        """
        Trace where a variable's value comes FROM (backward from sink).
        Answers: "what influences this value?"
        """
        pass

    def find_callers(self, function_name: str) -> list[dict]:
        """Find all call sites that invoke this function."""
        pass

    def find_callees(self, function_name: str) -> list[dict]:
        """Find all functions called by this function."""
        pass

    def get_cfg_paths(self, start_line: int, end_line: int, file: str) -> list[list[int]]:
        """
        Get all control flow paths between two lines.
        Used to determine: "can execution reach line Y from line X?"
        """
        pass

    def find_sanitizers_between(self, source_line: int, sink_line: int, file: str) -> list[dict]:
        """
        Find any validation/sanitization nodes on CFG paths between source and sink.
        Checks for: permission checks, comparisons, type assertions, return-on-failure patterns.
        """
        pass

    def get_dataflow_paths(self, source: str, sink: str) -> list[list[dict]]:
        """
        Get all data flow paths from a source expression to a sink expression.
        This is Joern's killer feature — full inter-procedural taint tracking.
        
        Example:
            get_dataflow_paths(
                source='body.get("customer_id")',
                sink='table.put_item'
            )
        Returns all paths through the program where body data reaches DynamoDB.
        """
        pass

    def get_function_cpg(self, function_name: str) -> dict:
        """Get the full CPG subgraph for a specific function (for LLM context)."""
        pass
```

### Python Analysis Tools

```python
class PythonAnalysisTools:
    """Deterministic analysis computed in Python."""

    def check_iam_permissions(self, resource: str) -> dict:
        """
        Check IAM permissions for a resource.
        Returns: actions granted, conditions present, principal roles.
        """
        pass

    def compute_blast_radius(self, resource: str) -> dict:
        """
        Compute blast radius if a resource is compromised.
        Returns: all reachable resources via network + IAM.
        """
        pass

    def check_infra_config(self, resource_type: str, property_name: str) -> dict:
        """
        Check infrastructure configuration.
        Example: check_infra_config("S3::Bucket", "Versioning")
        """
        pass

    def find_auth_context_usage(self, file: str) -> list[dict]:
        """
        Find where event['requestContext']['authorizer'] is accessed in a file.
        Critical for determining if authenticated tenant_id is used.
        """
        pass

    def check_authorizer_coverage(self, handler_name: str) -> dict:
        """
        Check if an API Gateway route has an authorizer attached.
        Returns: authorizer type, what it injects, which routes are protected.
        """
        pass

    def detect_toxic_combinations(self, findings: list) -> list[dict]:
        """
        Check if a set of individual findings combine into compound risk.
        """
        pass

    def read_code_context(self, file: str, start_line: int, end_line: int) -> str:
        """Read actual code from the file for LLM context."""
        pass
```

### Knowledge Base Tools

```python
class KnowledgeTools:
    """Query the vulnerability knowledge base."""

    def get_cwe(self, cwe_id: str) -> dict:
        """Get CWE definition with detection guidance for this codebase."""
        pass

    def get_exploit_payloads(self, vulnerability_type: str) -> list[str]:
        """Get concrete exploit payloads for a vulnerability type."""
        pass

    def get_similar_breaches(self, vulnerability_type: str) -> list[dict]:
        """Get real-world breach cases with similar root cause."""
        pass

    def check_known_false_positive(self, finding_pattern: str) -> dict | None:
        """Check if this matches a known false positive pattern."""
        pass

    def get_compliance_mapping(self, finding_category: str) -> dict:
        """Map a finding to SOC2/HIPAA controls."""
        pass
```

---

## The CoT Execution Engine

```python
class ChainOfThoughtEngine:
    """
    Orchestrates security analysis using structured reasoning + tool calls.
    
    The engine executes a 6-step analysis for each potential vulnerability,
    calling tools at each step to ground its reasoning in computed facts.
    """

    def __init__(self, joern: JoernTools, python_tools: PythonAnalysisTools, 
                 knowledge: KnowledgeTools):
        self.joern = joern
        self.python = python_tools
        self.knowledge = knowledge

    def analyze_taint_path(self, source: TaintSource, sink: TaintSink) -> Finding | None:
        """
        Execute full Think & Verify analysis on a source → sink pair.
        Each step calls tools and reasons about results.
        """
        context = AnalysisContext(source=source, sink=sink)

        # STEP 1: IDENTIFY
        context = self._step_identify(context)
        
        # STEP 2: TRACE
        context = self._step_trace(context)
        if context.verdict == "NO_PATH":
            return None  # No data flow exists — not a vulnerability
        
        # STEP 3: ASSESS
        context = self._step_assess(context)
        if context.verdict == "SANITIZED":
            return None  # Proper sanitization exists
        
        # STEP 4: CONCLUDE
        context = self._step_conclude(context)
        
        # STEP 5: VERIFY
        context = self._step_verify(context)
        if context.verdict == "SAFE":
            return None  # Counter-argument succeeded
        
        # STEP 6: VERDICT
        return self._step_verdict(context)

    def _step_identify(self, ctx: AnalysisContext) -> AnalysisContext:
        """
        STEP 1: What untrusted input enters? Where from?
        
        Tools used:
        - joern.backward_slice(sink_variable) → trace origin
        - python.read_code_context(source) → get actual code
        - knowledge.get_cwe(inferred_cwe) → get vulnerability definition
        """
        # Get CWE context for this type of vulnerability
        cwe = self.knowledge.get_cwe(ctx.sink.cwe)
        ctx.cwe_context = cwe

        # Backward slice from the source variable to understand its origin
        origins = self.joern.backward_slice(
            variable=ctx.source.variable,
            file=ctx.source.file,
            line=ctx.source.line
        )
        ctx.source_origins = origins

        # Classify: is this from body (tainted), auth context (safe), or env (low risk)?
        ctx.source_classification = self._classify_source(origins)

        # Get code context for LLM
        ctx.source_code = self.python.read_code_context(
            ctx.source.file, 
            max(ctx.source.line - 5, 1), 
            ctx.source.line + 5
        )

        ctx.step1_reasoning = (
            f"Source: {ctx.source.variable} at {ctx.source.file}:{ctx.source.line}\n"
            f"Origin: {ctx.source_classification}\n"
            f"Classification: {'TAINTED' if ctx.source_classification in ('body', 'header') else 'SAFE'}"
        )

        # Early exit: if source is from auth context, it's safe
        if ctx.source_classification == "auth_context":
            ctx.verdict = "SAFE"
        
        return ctx

    def _step_trace(self, ctx: AnalysisContext) -> AnalysisContext:
        """
        STEP 2: Trace data flow from source to sink.
        
        Tools used:
        - joern.forward_taint(source) → get taint propagation path
        - joern.get_dataflow_paths(source_expr, sink_expr) → all paths
        - joern.get_cfg_paths(source_line, sink_line) → control flow reachability
        """
        # Use Joern's taint tracking to find all paths
        taint_paths = self.joern.get_dataflow_paths(
            source=ctx.source.expression,
            sink=ctx.sink.expression
        )

        if not taint_paths:
            # Try forward taint from the source variable
            forward = self.joern.forward_taint(
                variable=ctx.source.variable,
                file=ctx.source.file,
                line=ctx.source.line
            )
            if not any(step.type == "sink" for step in forward):
                ctx.verdict = "NO_PATH"
                ctx.step2_reasoning = "No data flow path exists from source to sink."
                return ctx
            taint_paths = [forward]

        ctx.taint_paths = taint_paths

        # For each path, record the transformation at each step
        ctx.taint_trace = []
        for path in taint_paths[:3]:  # Analyze top 3 paths
            for step in path:
                ctx.taint_trace.append({
                    "file": step.file,
                    "line": step.line,
                    "code": step.code,
                    "type": step.type,
                    "taint_preserved": step.type != "sanitizer",
                })

        ctx.step2_reasoning = (
            f"Found {len(taint_paths)} data flow paths from source to sink.\n"
            f"Path length: {len(ctx.taint_trace)} steps.\n"
            f"Taint preserved through all steps: {all(s['taint_preserved'] for s in ctx.taint_trace)}"
        )

        return ctx

    def _step_assess(self, ctx: AnalysisContext) -> AnalysisContext:
        """
        STEP 3: Check for sanitization on the path.
        
        Tools used:
        - joern.find_sanitizers_between(source, sink) → sanitizer nodes
        - python.find_auth_context_usage(file) → is auth tenant used?
        - knowledge.check_known_false_positive(pattern) → known safe pattern?
        """
        # Find sanitizers between source and sink
        sanitizers = self.joern.find_sanitizers_between(
            source_line=ctx.source.line,
            sink_line=ctx.sink.line,
            file=ctx.source.file
        )
        ctx.sanitizers_found = sanitizers

        # Check if auth context is used anywhere in this file
        auth_usage = self.python.find_auth_context_usage(ctx.source.file)
        ctx.auth_context_usage = auth_usage

        # Check known false positive patterns
        fp_check = self.knowledge.check_known_false_positive(
            f"{ctx.source.variable} → {ctx.sink.expression}"
        )
        ctx.known_fp = fp_check

        if sanitizers:
            # Verify sanitizer is SUFFICIENT for this sink type
            ctx.sanitizer_sufficient = self._verify_sanitizer_sufficiency(
                sanitizers, ctx.sink.cwe
            )
            if ctx.sanitizer_sufficient:
                ctx.verdict = "SANITIZED"

        ctx.step3_reasoning = (
            f"Sanitizers on path: {len(sanitizers)}\n"
            f"Auth context used in file: {'YES' if auth_usage else 'NO'}\n"
            f"Known FP match: {fp_check is not None}\n"
            f"Verdict: {'SANITIZED' if ctx.verdict == 'SANITIZED' else 'NO SANITIZER'}"
        )

        return ctx

    def _step_conclude(self, ctx: AnalysisContext) -> AnalysisContext:
        """
        STEP 4: Determine exploitability and impact.
        
        Tools used:
        - python.check_iam_permissions(target_resource) → IAM constraints
        - python.compute_blast_radius(compromised_resource) → impact scope
        - knowledge.get_exploit_payloads(vuln_type) → concrete exploit
        """
        # Check IAM-level defenses
        iam_check = self.python.check_iam_permissions(ctx.sink.resource)
        ctx.iam_constraints = iam_check

        # Compute blast radius
        blast = self.python.compute_blast_radius(ctx.sink.resource)
        ctx.blast_radius = blast

        # Get exploit payloads for this vulnerability type
        payloads = self.knowledge.get_exploit_payloads(ctx.sink.cwe)
        ctx.exploit_payloads = payloads

        # Construct the exploit narrative
        ctx.exploit_narrative = self._construct_exploit(ctx)

        ctx.step4_reasoning = (
            f"IAM constraints: {iam_check.get('has_conditions', False)}\n"
            f"Blast radius: {len(blast.get('resources', []))} resources\n"
            f"Exploit feasible: {ctx.exploit_narrative is not None}"
        )

        return ctx

    def _step_verify(self, ctx: AnalysisContext) -> AnalysisContext:
        """
        STEP 5: Challenge own reasoning. Try to prove it's SAFE.
        
        Tools used:
        - python.check_authorizer_coverage(handler) → is route protected?
        - python.check_infra_config(resource, "Condition") → compensating controls
        - knowledge.get_similar_breaches(vuln_type) → has this been exploited before?
        """
        counter_arguments = []

        # Counter 1: Is there an authorizer?
        auth_coverage = self.python.check_authorizer_coverage(ctx.source.handler_name)
        if auth_coverage.get("authorizer_present"):
            counter_arguments.append(
                f"Authorizer present: {auth_coverage.get('type')}. "
                f"BUT: does the handler USE the injected context? "
                f"Auth context used: {'YES' if ctx.auth_context_usage else 'NO'}"
            )
            # If handler uses auth context for this specific variable → might be safe
            if ctx.auth_context_usage and ctx.source.variable in str(ctx.auth_context_usage):
                ctx.verdict = "SAFE"
                ctx.step5_reasoning = "Handler uses auth context for this variable."
                return ctx

        # Counter 2: IAM-level protection
        if ctx.iam_constraints.get("has_conditions"):
            counter_arguments.append(
                f"IAM has conditions: {ctx.iam_constraints.get('conditions')}. "
                f"This might prevent cross-tenant access at the IAM level."
            )
            if "LeadingKeys" in str(ctx.iam_constraints.get("conditions", "")):
                ctx.verdict = "SAFE"
                ctx.step5_reasoning = "IAM LeadingKeys condition prevents cross-tenant access."
                return ctx

        # Counter 3: Is this a known safe pattern?
        if ctx.known_fp:
            counter_arguments.append(f"Known FP: {ctx.known_fp.get('reason')}")

        # Counter 4: Is the sink actually dangerous?
        # (e.g., session_id as key makes cross-tenant reads hard)
        
        # Counter 5: Similar breaches confirm this IS dangerous
        breaches = self.knowledge.get_similar_breaches(ctx.sink.cwe)
        if breaches:
            counter_arguments.append(
                f"Similar breaches exist: {breaches[0].get('name')} ({breaches[0].get('date')}). "
                f"This pattern has been exploited in production."
            )

        ctx.counter_arguments = counter_arguments
        ctx.step5_reasoning = (
            f"Counter-arguments evaluated: {len(counter_arguments)}\n"
            + "\n".join(f"  - {ca}" for ca in counter_arguments)
            + f"\nVerdict holds: {'YES' if ctx.verdict != 'SAFE' else 'NO'}"
        )

        return ctx

    def _step_verdict(self, ctx: AnalysisContext) -> Finding:
        """
        STEP 6: Final verdict with full evidence chain.
        """
        severity = self._compute_severity(ctx)
        confidence = self._compute_confidence(ctx)
        compliance = self.knowledge.get_compliance_mapping(ctx.sink.cwe)

        return Finding(
            id=f"COT-{ctx.source.file}:{ctx.source.line}",
            agent="python",
            category=ctx.sink.category,
            cwe=ctx.sink.cwe,
            severity=severity,
            confidence=confidence,
            title=f"Tainted '{ctx.source.variable}' reaches {ctx.sink.expression}",
            description=ctx.exploit_narrative,
            evidence=Evidence(
                snippet="\n".join(
                    f"  {s['file']}:{s['line']}: {s['code']}" 
                    for s in ctx.taint_trace
                ),
                graph_context=f"Joern taint path: {len(ctx.taint_paths)} paths, "
                             f"{len(ctx.taint_trace)} steps",
                reasoning="\n".join([
                    f"STEP 1: {ctx.step1_reasoning}",
                    f"STEP 2: {ctx.step2_reasoning}",
                    f"STEP 3: {ctx.step3_reasoning}",
                    f"STEP 4: {ctx.step4_reasoning}",
                    f"STEP 5: {ctx.step5_reasoning}",
                ]),
            ),
            location=Location(
                file_path=ctx.source.file,
                start_line=ctx.source.line,
                end_line=ctx.sink.line,
            ),
            attack_path=[s["code"][:80] for s in ctx.taint_trace],
            blast_radius=ctx.blast_radius.get("resources", []),
            compliance_impact=compliance.get("violations", []),
        )
```

---

## Joern Integration

### Setup

```python
class JoernServer:
    """
    Manages Joern CPG generation and query execution.
    
    Two modes:
    1. joern-cli: Batch mode (generate CPG, run queries, exit)
    2. joern-server: REST API mode (persistent, faster queries)
    """

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.cpg_path = None
        self.server_process = None

    def generate_cpg(self) -> str:
        """
        Generate Code Property Graph for the repository.
        
        Joern command:
            joern-parse --language python --output cpg.bin /path/to/src
        
        This creates the full CPG with:
        - AST (complete parse tree)
        - CFG (control flow with all branches)
        - DFG (reaching definitions, proper def-use chains)
        - PDG (program dependence graph)
        - Call graph (inter-procedural)
        """
        import subprocess
        
        cpg_output = f"{self.repo_path}/.security-agent/cpg.bin"
        
        result = subprocess.run([
            "joern-parse",
            "--language", "python",
            "--output", cpg_output,
            self.repo_path + "/src"
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            raise RuntimeError(f"Joern CPG generation failed: {result.stderr}")
        
        self.cpg_path = cpg_output
        return cpg_output

    def start_server(self):
        """Start Joern server for interactive queries."""
        import subprocess
        
        self.server_process = subprocess.Popen(
            ["joern", "--server", "--server-host", "localhost", "--server-port", "8080"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # Wait for server to be ready
        import time
        time.sleep(5)

    def query(self, cpgql: str) -> list[dict]:
        """
        Execute a CPGQL query against the loaded CPG.
        
        Uses Joern's REST API:
            POST http://localhost:8080/query
            {"query": "cpg.method.name('lambda_handler').parameter.l"}
        """
        import requests
        
        response = requests.post(
            "http://localhost:8080/query",
            json={"query": cpgql}
        )
        return response.json()
```

### Key Joern Queries for This Codebase

```python
JOERN_QUERIES = {
    # Find all sources (user input entry points)
    "find_sources": """
        cpg.call("json.loads").argument.isCall.where(_.code(".*event.*body.*")).l
        ++ cpg.call(".*\\.get").where(_.argument.code(".*customer_id.*")).l
        ++ cpg.call(".*\\.get").where(_.argument.code(".*session_id.*")).l
    """,
    
    # Find all sinks (security-sensitive operations)
    "find_sinks": """
        cpg.call(".*put_item.*").l
        ++ cpg.call(".*generate_presigned_url.*").l
        ++ cpg.call(".*admin_create_user.*").l
        ++ cpg.call(".*invoke_model.*").l
        ++ cpg.call("table\\.query.*").l
    """,
    
    # Taint analysis: does user input reach DynamoDB?
    "taint_body_to_dynamodb": """
        val source = cpg.call("json.loads").argument.isCall.where(_.code(".*event.*body.*"))
        val sink = cpg.call(".*put_item.*").argument
        sink.reachableByFlows(source).l
    """,
    
    # Taint analysis: does body.get("customer_id") reach any sink?
    "taint_customer_id": """
        val source = cpg.call(".*\\.get").where(_.argument.code(".*customer_id.*"))
        val sink = cpg.call(".*put_item.*") ++ cpg.call(".*generate_presigned_url.*")
        sink.reachableByFlows(source).l
    """,
    
    # Find functions that don't access auth context
    "handlers_without_auth": """
        cpg.method.where(_.name(".*handler.*"))
            .whereNot(_.ast.isCall.code(".*requestContext.*authorizer.*"))
            .name.l
    """,
    
    # Find where tenant_id/customer_id is defined
    "tenant_id_definitions": """
        cpg.assignment.where(_.target.code(".*customer_id.*|.*tenant_id.*"))
            .map(a => (a.file.name.head, a.lineNumber.head, a.code))
            .l
    """,
    
    # Inter-procedural: trace from handler entry to DynamoDB call
    "cross_function_taint": """
        val source = cpg.method("lambda_handler").parameter.name("event")
        val sink = cpg.call("table.put_item")
        sink.reachableByFlows(source).path.l
    """,
    
    # Find all paths where body data reaches presigned URL generation
    "presigned_url_taint": """
        val source = cpg.call("body.get")
        val sink = cpg.call("generate_presigned_url")
        sink.reachableByFlows(source).path.l
    """,
    
    # Find sanitizers (permission checks, validations)
    "find_sanitizers": """
        cpg.call("check_permission").l
        ++ cpg.controlStructure.isIf
            .where(_.condition.code(".*tenant_id.*!=.*|.*not.*allowed.*"))
            .l
    """,
}
```

---

## Execution Flow (Complete)

```
┌──────────────────────────────────────────────────────────────────┐
│ PHASE 0: Setup                                                    │
│   1. Install/verify Joern                                         │
│   2. joern-parse → generate CPG binary (30-60s for this repo)    │
│   3. Load infrastructure graphs (our existing Python code)        │
│   4. Load knowledge base                                          │
└──────────────────────────────────────┬───────────────────────────┘
                                       ↓
┌──────────────────────────────────────────────────────────────────┐
│ PHASE 1: Discovery (Joern + Python, no LLM)                       │
│   1. Joern query: find all sources → 78 entry points              │
│   2. Joern query: find all sinks → 161 operations                 │
│   3. Joern taint: find all source→sink paths → N paths            │
│   4. Python: score paths by risk, prioritize                      │
│   5. Python: run deterministic infra checks                       │
│                                                                    │
│   Output: Ranked list of taint paths for CoT analysis             │
└──────────────────────────────────────┬───────────────────────────┘
                                       ↓
┌──────────────────────────────────────────────────────────────────┐
│ PHASE 2: CoT Analysis (per taint path)                            │
│                                                                    │
│   For each priority path:                                          │
│     CoT STEP 1 (IDENTIFY):                                        │
│       → joern.backward_slice(source)                              │
│       → knowledge.get_cwe(path.cwe)                               │
│       → REASON about source classification                        │
│                                                                    │
│     CoT STEP 2 (TRACE):                                           │
│       → joern.get_dataflow_paths(source, sink)                    │
│       → REASON about each propagation step                        │
│       → EXIT if no path exists                                    │
│                                                                    │
│     CoT STEP 3 (ASSESS):                                          │
│       → joern.find_sanitizers_between(source, sink)               │
│       → python.find_auth_context_usage(file)                      │
│       → REASON about sanitizer sufficiency                        │
│       → EXIT if properly sanitized                                │
│                                                                    │
│     CoT STEP 4 (CONCLUDE):                                        │
│       → python.check_iam_permissions(resource)                    │
│       → python.compute_blast_radius(resource)                     │
│       → knowledge.get_exploit_payloads(cwe)                       │
│       → REASON about exploitability and impact                    │
│                                                                    │
│     CoT STEP 5 (VERIFY):                                          │
│       → python.check_authorizer_coverage(handler)                 │
│       → knowledge.check_known_false_positive(pattern)             │
│       → REASON: try to prove it's SAFE                            │
│       → EXIT if counter-argument succeeds                         │
│                                                                    │
│     CoT STEP 6 (VERDICT):                                         │
│       → knowledge.get_compliance_mapping(cwe)                     │
│       → EMIT Finding with full evidence chain                     │
│                                                                    │
│   Checkpoint after each path.                                      │
└──────────────────────────────────────┬───────────────────────────┘
                                       ↓
┌──────────────────────────────────────────────────────────────────┐
│ PHASE 3: Validation (adversarial CoT, different persona)          │
│                                                                    │
│   For each finding:                                                │
│     → Switch to skeptic persona                                   │
│     → Load framework protection knowledge                         │
│     → Try to construct safety argument                            │
│     → DISMISS if convincing, CONFIRM if not                       │
└──────────────────────────────────────┬───────────────────────────┘
                                       ↓
┌──────────────────────────────────────────────────────────────────┐
│ PHASE 4: Cross-boundary correlation                               │
│                                                                    │
│   → Combine app findings + infra findings                         │
│   → Check toxic combination patterns                              │
│   → Compound severity assessment                                  │
└──────────────────────────────────────┬───────────────────────────┘
                                       ↓
┌──────────────────────────────────────────────────────────────────┐
│ PHASE 5: Report with full reasoning traces                        │
└──────────────────────────────────────────────────────────────────┘
```

---

## Why This Is Better

| Aspect | v1 (what we built) | v2 (this design) |
|--------|-------------------|-----------------|
| Graph quality | Regex-based, 0 taint paths found | Joern: production CPG, inter-procedural taint |
| CoT structure | Ad-hoc paragraphs | 6 explicit steps, each grounded in tool results |
| Grounding | LLM reads raw code and guesses | Each reasoning step backed by computed facts |
| False negatives | High (broken DFG) | Low (Joern finds all paths) |
| False positives | Unknown (no validation step) | Low (VERIFY step + adversarial validation) |
| Reproducibility | Non-deterministic | Tool calls are deterministic, reasoning is structured |
| Auditability | "I think it's vulnerable" | Full trace: source → step1 → step2 → ... → verdict |
| Cost efficiency | LLM reasons about everything | LLM only reasons about JOERN-CONFIRMED paths |

---

## Key Principle: LLM Does NOT Find Vulnerabilities

```
WRONG:  "LLM, here's some code. Find vulnerabilities."  → hallucinations, misses

RIGHT:  "Joern found 14 taint paths from body.get() to table.put_item().
         LLM, for EACH path: is there a sanitizer? Is it sufficient? 
         Is there a compensating control? What's the exploit?"
```

The LLM's job is JUDGMENT, not DETECTION:
- Joern DETECTS (finds paths with mathematical certainty)
- LLM JUDGES (are those paths actually exploitable given context?)

This matches the research perfectly:
- IRIS: CodeQL detects, LLM reasons → 2.5x improvement
- BugLens: static analysis detects, LLM validates → 7x precision
- Our v2: Joern detects, CoT reasons → same pattern

---

## Running From Claude Code

When executing from this session, the flow becomes:

1. **Python script** runs Joern + deterministic analysis → outputs structured results
2. **Claude (me)** receives the Joern taint paths and executes the CoT steps
3. For each step, I REQUEST data → **Python script** computes it → returns to me
4. I REASON about the result and proceed to next step
5. After all steps: I emit the structured finding

This is the same architecture, just with Claude Code as the CoT engine instead of API calls.
