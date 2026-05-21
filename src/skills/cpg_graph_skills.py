from __future__ import annotations

"""
Code Property Graph Construction Skills
=========================================
Skills for building and exploring the Code Property Graph (CPG) from
the compliance codebase's Python source.

CPG = AST ∪ CFG ∪ DFG

The CPG enables:
- Tracing data flow from sources to sinks (taint analysis)
- Understanding control flow (which branches lead to dangerous operations)
- Slicing minimal context for LLM analysis (67-91% token reduction)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# =============================================================================
# SKILL 1: Node & Edge Type Definitions
# =============================================================================

class NodeType(Enum):
    # AST node types (from tree-sitter)
    MODULE = "module"
    FUNCTION_DEF = "function_definition"
    CLASS_DEF = "class_definition"
    ASSIGNMENT = "assignment"
    EXPRESSION_STMT = "expression_statement"
    CALL = "call"
    ATTRIBUTE = "attribute"
    SUBSCRIPT = "subscript"
    IF_STMT = "if_statement"
    FOR_STMT = "for_statement"
    WHILE_STMT = "while_statement"
    TRY_STMT = "try_statement"
    RETURN_STMT = "return_statement"
    PARAMETER = "parameter"
    ARGUMENT = "argument"
    STRING = "string"
    IDENTIFIER = "identifier"
    DECORATOR = "decorated_definition"
    IMPORT = "import_statement"
    LAMBDA = "lambda"
    DICT_COMP = "dictionary_comprehension"
    LIST_COMP = "list_comprehension"


class EdgeType(Enum):
    # AST edges (structural)
    AST_CHILD = "ast_child"          # parent → child in syntax tree

    # CFG edges (control flow)
    CFG_NEXT = "cfg_next"            # sequential execution
    CFG_TRUE = "cfg_true"            # if condition is true
    CFG_FALSE = "cfg_false"          # if condition is false
    CFG_LOOP_BACK = "cfg_loop_back"  # loop iteration
    CFG_LOOP_EXIT = "cfg_loop_exit"  # loop termination
    CFG_EXCEPT = "cfg_except"        # exception handler
    CFG_FINALLY = "cfg_finally"      # finally block

    # DFG edges (data flow)
    DFG_DEF_USE = "dfg_def_use"      # variable defined → variable used
    DFG_PARAM = "dfg_param"          # argument passed to parameter
    DFG_RETURN = "dfg_return"        # function return to call site
    DFG_ATTRIBUTE = "dfg_attribute"  # object.attr access
    DFG_SUBSCRIPT = "dfg_subscript"  # dict['key'] or list[i] access
    DFG_ASSIGN = "dfg_assign"        # RHS → LHS of assignment

    # Call edges (inter-procedural)
    CALL_EDGE = "call"               # call site → function definition
    CALLBACK = "callback"            # function passed as argument (e.g., LangGraph node)


class NodeRole(Enum):
    SOURCE = "source"           # Taint source (user input enters)
    SINK = "sink"               # Security-sensitive operation
    SANITIZER = "sanitizer"     # Validation/escaping function
    PROPAGATOR = "propagator"   # Passes taint through unchanged
    GATE = "gate"               # Permission/auth check (blocks flow if denied)
    NEUTRAL = "neutral"         # No security significance


# =============================================================================
# SKILL 2: CPG Construction Rules (Python-Specific)
# =============================================================================

CPG_CONSTRUCTION_RULES = {
    "ast_extraction": {
        "tool": "tree-sitter with Python grammar",
        "node_creation": """
            For each tree-sitter node:
            - Create CPG node with: id, type, text, file, line, col
            - Add AST_CHILD edge from parent to child
            - Special handling for:
              * function_definition: extract name, parameters, decorators
              * call: extract function name, arguments
              * assignment: extract target and value
              * subscript: extract object and index (for dict['key'] patterns)
        """,
    },

    "cfg_construction": {
        "description": "Build control flow edges within each function",
        "rules": [
            {
                "pattern": "Sequential statements in a block",
                "edge": "CFG_NEXT from statement N to statement N+1",
            },
            {
                "pattern": "if-else",
                "edges": [
                    "CFG_TRUE from if-node to first statement of if-body",
                    "CFG_FALSE from if-node to first statement of else-body (or next stmt after if)",
                    "CFG_NEXT from last stmt of if-body to first stmt after if-block",
                    "CFG_NEXT from last stmt of else-body to first stmt after if-block",
                ],
            },
            {
                "pattern": "for/while loop",
                "edges": [
                    "CFG_TRUE from loop-head to first statement of loop-body",
                    "CFG_LOOP_BACK from last stmt of loop-body to loop-head",
                    "CFG_LOOP_EXIT from loop-head to first stmt after loop",
                ],
            },
            {
                "pattern": "try-except-finally",
                "edges": [
                    "CFG_NEXT from try-body statements normally",
                    "CFG_EXCEPT from any stmt in try-body to except handler",
                    "CFG_FINALLY from end of try/except to finally block",
                ],
            },
            {
                "pattern": "return/raise",
                "edges": [
                    "No CFG_NEXT edge from return/raise (terminates path)",
                    "DFG_RETURN from return value to function's call sites",
                ],
            },
            {
                "pattern": "early return guard (common in Lambda handlers)",
                "example": """
                    if not event.get('body'):
                        return {'statusCode': 400, ...}  # Guard: terminates here
                    # Code below only executes if body exists
                    body = json.loads(event['body'])
                """,
                "significance": "Guards reduce reachable paths — if a permission check "
                              "returns 403 early, code after it is only reachable when "
                              "permission is granted."
            },
        ],
    },

    "dfg_construction": {
        "description": "Build data flow edges (def-use chains)",
        "rules": [
            {
                "pattern": "Simple assignment: x = expr",
                "edge": "DFG_ASSIGN from expr-node to x-node (x is defined here)",
            },
            {
                "pattern": "Dict/subscript access: body['key']",
                "edge": "DFG_SUBSCRIPT from body-node to result-node",
                "taint": "If body is tainted, result is tainted (taint propagates through subscript)",
            },
            {
                "pattern": "Attribute access: event['requestContext']['authorizer']['tenant_id']",
                "edge": "Chain of DFG_SUBSCRIPT edges",
                "taint": "This is a SAFE source (from auth context, not user body)",
            },
            {
                "pattern": "Function call: result = func(arg1, arg2)",
                "edges": [
                    "DFG_PARAM from arg1 to func's first parameter",
                    "DFG_PARAM from arg2 to func's second parameter",
                    "DFG_RETURN from func's return value to result",
                ],
                "taint": "If any arg is tainted AND func is not a sanitizer → result is tainted",
            },
            {
                "pattern": "String formatting: f'TENANT#{customer_id}'",
                "edge": "DFG_DEF_USE from customer_id to the f-string expression",
                "taint": "Taint propagates through string formatting (the formatted string "
                        "carries the taint of its interpolated variables)",
            },
            {
                "pattern": "json.loads(event.get('body', '{}'))",
                "edge": "DFG_DEF_USE from event to json.loads input",
                "taint": "json.loads does NOT sanitize — it's a propagator (parsed JSON "
                        "is still user-controlled data)",
            },
        ],
    },

    "inter_procedural": {
        "description": "Connect function call sites to function definitions",
        "rules": [
            {
                "pattern": "Direct call: function_name(args)",
                "edge": "CALL_EDGE from call-site to function_definition",
                "resolution": "Match by function name within scope (imports, local defs)",
            },
            {
                "pattern": "Method call: obj.method(args)",
                "edge": "CALL_EDGE (requires type resolution for obj)",
                "limitation": "In Python, type resolution is limited without runtime info. "
                            "Use heuristics: boto3 client methods, known framework methods.",
            },
            {
                "pattern": "LangGraph graph.add_node('name', func)",
                "edge": "CALLBACK edge from graph.add_node to func definition",
                "significance": "This is how LangGraph connects nodes — the func will be "
                              "called during graph execution with state as argument.",
            },
            {
                "pattern": "Lambda handler dispatch: if path == '/chat': return handle_chat(event)",
                "edge": "CALL_EDGE from handler dispatch to sub-handler",
                "significance": "Lambda handlers often route internally. Each route is a "
                              "separate entry point for taint analysis.",
            },
        ],
    },
}


# =============================================================================
# SKILL 3: Compliance Codebase CPG Patterns
# =============================================================================

COMPLIANCE_CPG_PATTERNS = {
    "lambda_handler_structure": {
        "description": "Standard Lambda handler structure in this codebase",
        "pattern": """
            def lambda_handler(event, context):     # ENTRY NODE
                body = json.loads(event['body'])     # SOURCE: user input
                auth = event['requestContext']['authorizer']  # SAFE: auth context

                # ... routing logic ...

                result = process(body, auth)          # DATA FLOW
                return {'statusCode': 200, 'body': json.dumps(result)}  # SINK: response
        """,
        "cpg_annotations": [
            "event parameter → mark as SOURCE (http_input)",
            "event['requestContext']['authorizer'] → mark as SAFE_SOURCE",
            "event['body'] → mark as TAINTED_SOURCE",
            "return statement → mark as SINK (http_response)",
        ],
    },

    "langgraph_state_flow": {
        "description": "How data flows through LangGraph nodes",
        "pattern": """
            # Graph definition
            graph.add_node('router', router_func)
            graph.add_node('evaluation', evaluation_func)
            graph.add_edge('router', 'evaluation')

            # Each node function receives and returns state
            def router_func(state: AgentState) -> AgentState:
                messages = state['messages']  # TAINTED: user messages
                intent = classify(messages)    # LLM-influenced routing
                return {**state, 'intent': intent}

            def evaluation_func(state: AgentState) -> AgentState:
                control_id = state.get('control_id')  # Where did this come from?
                result = evaluate(control_id)
                return {**state, 'evaluation': result}
        """,
        "cpg_annotations": [
            "state parameter in each node → inherits taint from predecessor nodes",
            "state['messages'] → always TAINTED (user input)",
            "state fields set from LLM output → TAINTED (LLM influenced by user)",
            "Graph edges define state flow: predecessor's output = successor's input",
        ],
    },

    "boto3_dynamodb_call": {
        "description": "DynamoDB operations with key construction",
        "pattern": """
            table = dynamodb.Table(TABLE_NAME)

            # Pattern A: Key from auth context (SAFE)
            tenant_id = event['requestContext']['authorizer']['tenant_id']
            response = table.query(
                KeyConditionExpression=Key('pk').eq(f'TENANT#{tenant_id}')
            )

            # Pattern B: Key from body (UNSAFE)
            customer_id = body.get('customer_id')
            response = table.query(
                KeyConditionExpression=Key('pk').eq(f'TENANT#{customer_id}')
            )
        """,
        "cpg_annotations": [
            "table.query() → SINK (nosql_query)",
            "Key('pk').eq(f'TENANT#{variable}') → trace 'variable' backward",
            "If variable reaches auth context → SAFE path",
            "If variable reaches event['body'] → TAINTED path → FINDING",
        ],
    },

    "presigned_url_generation": {
        "description": "S3 presigned URL with key construction",
        "pattern": """
            filename = body.get('filename')        # TAINTED: user input
            customer_id = body.get('customer_id')  # TAINTED (or from auth?)

            key = f'{customer_id}/{filename}'      # Key construction

            url = s3.generate_presigned_url(
                ClientMethod='put_object',
                Params={'Bucket': BUCKET, 'Key': key}  # SINK
            )
        """,
        "cpg_annotations": [
            "generate_presigned_url → SINK (file_access)",
            "Params['Key'] → trace backward to find origin",
            "If any component of key is from body without sanitization → FINDING",
        ],
    },
}


# =============================================================================
# SKILL 4: CPG Exploration Algorithms
# =============================================================================

CPG_EXPLORATION = {
    "taint_path_enumeration": {
        "description": "Find all paths from sources to sinks in the CPG",
        "algorithm": """
def enumerate_taint_paths(cpg, sources, sinks, sanitizers, max_depth=15):
    '''
    BFS/DFS from each source, following DFG and CALL edges.
    Stop if: (a) reach a sink (finding!), (b) reach a sanitizer (safe),
             (c) exceed max_depth (abandon).
    '''
    findings = []

    for source in sources:
        # BFS with taint state
        queue = [(source, [source], set())]  # (current, path, visited)

        while queue:
            current, path, visited = queue.pop(0)

            if current in visited or len(path) > max_depth:
                continue
            visited = visited | {current}

            # Check: did we reach a sink?
            if cpg.get_role(current) == NodeRole.SINK:
                findings.append(TaintPath(
                    source=source,
                    sink=current,
                    path=path,
                    sanitized=False
                ))
                continue

            # Check: did we hit a sanitizer? (path is safe)
            if cpg.get_role(current) == NodeRole.SANITIZER:
                continue  # Don't explore further — taint removed

            # Check: did we hit a gate (permission check)?
            if cpg.get_role(current) == NodeRole.GATE:
                # Gate doesn't remove taint — it blocks execution
                # Only continue if we can't determine the gate always blocks
                pass  # Conservative: continue exploration

            # Expand: follow DFG and CALL edges
            for neighbor in cpg.successors(current, edge_types=[
                EdgeType.DFG_DEF_USE, EdgeType.DFG_PARAM,
                EdgeType.DFG_RETURN, EdgeType.DFG_SUBSCRIPT,
                EdgeType.DFG_ASSIGN, EdgeType.CALL_EDGE
            ]):
                queue.append((neighbor, path + [neighbor], visited))

    return findings
""",
    },

    "backward_slice": {
        "description": "Given a sink, find all nodes that influence its value",
        "algorithm": """
def backward_slice(cpg, sink_node, max_depth=20):
    '''
    Backward traversal from sink: what data flows INTO this operation?
    Used to determine: where does the DynamoDB key / S3 key come from?
    '''
    influencers = set()
    queue = [(sink_node, 0)]

    while queue:
        current, depth = queue.pop(0)
        if depth > max_depth or current in influencers:
            continue
        influencers.add(current)

        # Follow DFG edges BACKWARD (predecessors)
        for predecessor in cpg.predecessors(current, edge_types=[
            EdgeType.DFG_DEF_USE, EdgeType.DFG_PARAM,
            EdgeType.DFG_ASSIGN, EdgeType.DFG_SUBSCRIPT
        ]):
            queue.append((predecessor, depth + 1))

    return influencers
""",
    },

    "forward_slice": {
        "description": "Given a source, find all nodes it can influence",
        "algorithm": """
def forward_slice(cpg, source_node, max_depth=20):
    '''
    Forward traversal from source: where does this data flow TO?
    Used to determine: what does user input eventually reach?
    '''
    influenced = set()
    queue = [(source_node, 0)]

    while queue:
        current, depth = queue.pop(0)
        if depth > max_depth or current in influenced:
            continue
        influenced.add(current)

        # Follow DFG edges FORWARD (successors)
        for successor in cpg.successors(current, edge_types=[
            EdgeType.DFG_DEF_USE, EdgeType.DFG_PARAM,
            EdgeType.DFG_RETURN, EdgeType.DFG_ASSIGN,
            EdgeType.DFG_SUBSCRIPT
        ]):
            queue.append((successor, depth + 1))

    return influenced
""",
    },

    "cpg_slice_for_llm": {
        "description": "Extract minimal subgraph for LLM analysis (token reduction)",
        "algorithm": """
def extract_llm_slice(cpg, source, sink):
    '''
    Given a source and sink, extract the minimal CPG subgraph
    that contains all relevant context for LLM reasoning.

    Achieves 67-91% token reduction vs sending full files.
    '''
    # 1. Find all DFG paths between source and sink
    paths = find_all_dfg_paths(cpg, source, sink, max_paths=5)

    slice_nodes = set()
    for path in paths:
        slice_nodes.update(path)

    # 2. Add CFG branch conditions that gate the flow
    for node in list(slice_nodes):
        for pred in cpg.predecessors(node, edge_types=[EdgeType.CFG_TRUE, EdgeType.CFG_FALSE]):
            if cpg.node_type(pred) == NodeType.IF_STMT:
                slice_nodes.add(pred)
                # Also add the condition expression
                condition = cpg.get_child(pred, child_type='condition')
                if condition:
                    slice_nodes.add(condition)

    # 3. Add 1-hop AST context (function signatures)
    for node in list(slice_nodes):
        parent = cpg.ast_parent(node)
        if parent and cpg.node_type(parent) == NodeType.FUNCTION_DEF:
            slice_nodes.add(parent)  # Include function signature

    # 4. Render as LLM-friendly text
    # CRITICAL: Position source at beginning, sink at end (context window optimization)
    return render_slice(cpg, slice_nodes, source, sink)


def render_slice(cpg, nodes, source, sink):
    '''
    Render the CPG slice as readable code with annotations.
    Positioning: source first (beginning), sink last (end).
    '''
    lines = []

    # Source at beginning (strong position in context window)
    lines.append("# === SOURCE (user input enters here) ===")
    lines.append(cpg.get_code_context(source, lines_before=1, lines_after=1))
    lines.append("")

    # Intermediate nodes (middle — weaker position but necessary)
    ordered = topological_sort(nodes - {source, sink})
    for node in ordered:
        role = cpg.get_role(node)
        if role == NodeRole.GATE:
            lines.append("# --- PERMISSION CHECK ---")
        elif role == NodeRole.SANITIZER:
            lines.append("# --- SANITIZER ---")
        else:
            lines.append("# --- data flows through ---")
        lines.append(cpg.get_code_context(node, lines_before=0, lines_after=0))
        lines.append("")

    # Sink at end (strong position in context window)
    lines.append("# === SINK (security-sensitive operation) ===")
    lines.append(cpg.get_code_context(sink, lines_before=1, lines_after=1))

    return "\\n".join(lines)
''',
    },

    "tenant_id_trace": {
        "description": "Specialized query: trace where a tenant_id/customer_id comes from",
        "algorithm": """
def trace_tenant_id_origin(cpg, dynamodb_call_node):
    '''
    For a DynamoDB call node, trace the key parameter backward
    to determine if the tenant_id comes from a safe source (auth context)
    or unsafe source (request body).

    Returns: 'SAFE' | 'UNSAFE' | 'NEEDS_REVIEW'
    '''
    # Find the key parameter in the DynamoDB call
    key_node = find_key_argument(cpg, dynamodb_call_node)
    if not key_node:
        return 'NEEDS_REVIEW'

    # Backward slice from the key
    influencers = backward_slice(cpg, key_node)

    # Classify based on what we find in the influencer set
    has_auth_source = any(
        is_auth_context_access(cpg, node) for node in influencers
    )
    has_body_source = any(
        is_body_access(cpg, node) for node in influencers
    )

    if has_auth_source and not has_body_source:
        return 'SAFE'
    elif has_body_source and not has_auth_source:
        return 'UNSAFE'
    elif has_body_source and has_auth_source:
        # Both present — check if there's a validation comparison
        has_validation = any(
            is_equality_check(cpg, node) for node in influencers
            if cpg.node_type(node) == NodeType.IF_STMT
        )
        if has_validation:
            return 'SAFE'  # Validated before use
        return 'NEEDS_REVIEW'
    else:
        return 'NEEDS_REVIEW'


def is_auth_context_access(cpg, node):
    '''Check if node accesses event["requestContext"]["authorizer"]'''
    text = cpg.get_text(node)
    return any(pattern in text for pattern in [
        'requestContext', 'authorizer', 'auth_context',
    ])

def is_body_access(cpg, node):
    '''Check if node accesses event["body"] or request body'''
    text = cpg.get_text(node)
    return any(pattern in text for pattern in [
        "event['body']", 'event.get("body")', 'event.get(\'body\')',
        'json.loads(', 'body.get(',
    ])
''',
    },
}


# =============================================================================
# SKILL 5: Compliance Codebase Source/Sink Auto-Detection
# =============================================================================

AUTO_DETECTION_RULES = {
    "source_detection": [
        {
            "pattern": "json.loads(event.get('body",
            "role": NodeRole.SOURCE,
            "category": "http_input",
            "confidence": "HIGH",
        },
        {
            "pattern": "event['body']",
            "role": NodeRole.SOURCE,
            "category": "http_input",
            "confidence": "HIGH",
        },
        {
            "pattern": "event['queryStringParameters']",
            "role": NodeRole.SOURCE,
            "category": "http_input",
            "confidence": "HIGH",
        },
        {
            "pattern": "state['messages']",
            "role": NodeRole.SOURCE,
            "category": "user_message",
            "confidence": "HIGH",
        },
        {
            "pattern": "state.get('messages')",
            "role": NodeRole.SOURCE,
            "category": "user_message",
            "confidence": "HIGH",
        },
        {
            "pattern": ".get('customer_id')",
            "role": NodeRole.SOURCE,
            "category": "tenant_identifier",
            "confidence": "MEDIUM",
            "note": "Only a source if from body, not from auth context",
        },
    ],
    "sink_detection": [
        {
            "pattern": "table.query(",
            "role": NodeRole.SINK,
            "category": "nosql_query",
            "confidence": "HIGH",
        },
        {
            "pattern": "table.put_item(",
            "role": NodeRole.SINK,
            "category": "nosql_write",
            "confidence": "HIGH",
        },
        {
            "pattern": "table.update_item(",
            "role": NodeRole.SINK,
            "category": "nosql_write",
            "confidence": "HIGH",
        },
        {
            "pattern": "generate_presigned_url(",
            "role": NodeRole.SINK,
            "category": "file_access",
            "confidence": "HIGH",
        },
        {
            "pattern": "s3_client.put_object(",
            "role": NodeRole.SINK,
            "category": "file_write",
            "confidence": "HIGH",
        },
        {
            "pattern": "admin_create_user(",
            "role": NodeRole.SINK,
            "category": "identity_write",
            "confidence": "HIGH",
        },
        {
            "pattern": "invoke_model(",
            "role": NodeRole.SINK,
            "category": "llm_invocation",
            "confidence": "MEDIUM",
        },
    ],
    "sanitizer_detection": [
        {
            "pattern": "check_permission(",
            "role": NodeRole.GATE,
            "category": "authorization",
            "confidence": "HIGH",
        },
        {
            "pattern": "if.*tenant_id.*!=.*:.*return.*403",
            "role": NodeRole.GATE,
            "category": "tenant_validation",
            "confidence": "HIGH",
        },
        {
            "pattern": "ExpressionAttributeValues",
            "role": NodeRole.SANITIZER,
            "category": "parameterized_query",
            "confidence": "HIGH",
        },
        {
            "pattern": "os.path.basename(",
            "role": NodeRole.SANITIZER,
            "category": "path_sanitization",
            "confidence": "HIGH",
        },
    ],
}
