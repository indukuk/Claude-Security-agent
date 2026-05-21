"""
V4 Enhanced CPG Builder — inter-procedural, framework-aware, with call graph.

Builds on V1's CodePropertyGraph but adds:
- Full call graph with parameter binding (inter-procedural DFG)
- Lambda/DynamoDB/APIGW framework patterns for automatic source/sink classification
- Handler entry detection with auth metadata from infra
- Trust boundary nodes where privilege level changes
- Return flow tracking (callee → caller data propagation)
"""
from __future__ import annotations

import re
import logging
from pathlib import Path
from dataclasses import dataclass, field

from src.common.graph import CodePropertyGraph

logger = logging.getLogger(__name__)

try:
    import tree_sitter_python as tspython
    from tree_sitter import Language, Parser

    PY_LANGUAGE = Language(tspython.language())
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False


@dataclass
class FunctionInfo:
    """Metadata about a discovered function."""
    node_id: str
    name: str
    file_path: str
    line: int
    params: list[str]
    is_handler: bool = False
    auth_context: str = ""  # "authorizer" | "api_key" | "none" | ""
    return_nodes: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)


@dataclass
class CallSite:
    """A function call with argument mapping."""
    caller_node_id: str
    callee_name: str
    args: list[str]
    file_path: str
    line: int


# Framework-aware patterns for Lambda + API Gateway + DynamoDB + S3 + Bedrock
HANDLER_SIGNATURES = [
    r"def\s+(lambda_handler|handler)\s*\(",
    r"def\s+\w*handler\w*\s*\(",
]

SOURCE_PATTERNS_EXTENDED = [
    # Lambda event body
    ("event['body']", "http_body", "User-controlled HTTP request body"),
    ("event.get('body'", "http_body", "User-controlled HTTP request body"),
    ("json.loads(event", "http_body", "Parsed HTTP request body"),
    ("body.get(", "user_input", "User-controlled field from request body"),
    ("body['", "user_input", "User-controlled field from request body"),
    # Headers
    ("event['headers']", "http_header", "User-controlled HTTP header"),
    ("event.get('headers'", "http_header", "User-controlled HTTP header"),
    ("headers.get(", "http_header", "User-controlled HTTP header value"),
    # Path parameters
    ("event['pathParameters']", "path_param", "User-controlled URL path parameter"),
    ("event.get('pathParameters'", "path_param", "User-controlled URL path parameter"),
    # Query string
    ("event['queryStringParameters']", "query_param", "User-controlled query string"),
    ("event.get('queryStringParameters'", "query_param", "User-controlled query string"),
    # Authorizer context (trusted but important for tracking)
    ("event['requestContext']['authorizer']", "auth_context", "Authorizer-verified context"),
    # LangGraph state
    ("state['messages']", "ai_state", "AI agent message state"),
    ("state.get('messages'", "ai_state", "AI agent message state"),
]

SINK_PATTERNS_EXTENDED = [
    # DynamoDB operations
    ("table.query(", "dynamodb_read", "DynamoDB query — check tenant scoping"),
    ("table.put_item(", "dynamodb_write", "DynamoDB write — check authorization"),
    ("table.update_item(", "dynamodb_write", "DynamoDB update — check authorization"),
    ("table.get_item(", "dynamodb_read", "DynamoDB read — check ownership after load"),
    ("table.delete_item(", "dynamodb_delete", "DynamoDB delete — check authorization + audit"),
    # S3 operations
    ("generate_presigned_url(", "s3_presigned", "S3 presigned URL — check path traversal"),
    ("s3_client.put_object(", "s3_write", "S3 write — check key construction"),
    ("s3_client.get_object(", "s3_read", "S3 read — check authorization"),
    # Cognito operations
    ("admin_create_user(", "cognito_admin", "Cognito user creation — check authorization"),
    ("admin_update_user_attributes(", "cognito_admin", "Cognito attribute update"),
    ("admin_confirm_sign_up(", "cognito_admin", "Cognito auto-confirm — check if appropriate"),
    # Code execution
    ("exec(", "code_exec", "Code execution — check input sanitization"),
    ("eval(", "code_exec", "Code evaluation — check input sanitization"),
    ("subprocess", "code_exec", "Subprocess call — check input sanitization"),
    # AI/Bedrock
    ("invoke_model(", "bedrock_invoke", "Bedrock model invocation"),
    ("invoke_agent(", "bedrock_agent", "Bedrock agent invocation — check session attributes"),
    # HTTP response
    ("_json_response(", "http_response", "HTTP response — check for info disclosure"),
    ("return {", "http_response", "Lambda return — check response contents"),
]

SANITIZER_PATTERNS_EXTENDED = [
    ("check_permission(", "authz_check", "Permission/role check"),
    (".replace('/', '_')", "path_sanitize", "Path traversal sanitization"),
    (".replace('\\\\', '_')", "path_sanitize", "Path traversal sanitization"),
    (".replace('..', '_')", "path_sanitize", "Path traversal sanitization"),
    ("_safe_id(", "input_sanitize", "ID sanitization"),
    ("model_validate(", "schema_validate", "Pydantic schema validation"),
    ("validate_python(", "schema_validate", "Schema validation"),
    ("ExpressionAttributeValues", "parameterized_query", "Parameterized DynamoDB query"),
    ("os.path.basename(", "path_sanitize", "Path basename extraction"),
    ("shlex.quote(", "shell_sanitize", "Shell argument quoting"),
    ("DOMPurify", "xss_sanitize", "XSS sanitization"),
    ("textContent", "xss_sanitize", "Safe text assignment (no HTML parsing)"),
    ("jwt.decode(", "jwt_verify", "JWT signature verification"),
]

GATE_PATTERNS_EXTENDED = [
    (r"if.*tenant_id.*!=", "ownership_check", "Tenant ownership verification"),
    (r"if.*customer_id.*!=", "ownership_check", "Customer ownership verification"),
    (r"if not.*allowed", "authz_gate", "Authorization gate"),
    (r"return.*403", "authz_reject", "403 Forbidden response"),
    (r"return.*401", "authn_reject", "401 Unauthorized response"),
    (r"raise.*Unauthorized", "authn_reject", "Authentication rejection"),
    (r"raise.*Forbidden", "authz_reject", "Authorization rejection"),
    (r"if.*role.*not in", "role_check", "Role-based access check"),
    (r"if.*role.*!=", "role_check", "Role check"),
    (r"check_approval\(", "approval_gate", "Approval workflow gate"),
    (r"rate_limit", "rate_limit", "Rate limiting check"),
]

AUDIT_PATTERNS = [
    "audit_log(", "log_audit(", "audit_event(",
    "logger.info(f\".*{action}", "logger.info(f\".*{method}",
]


class EnhancedCPGBuilder:
    """
    Builds a V4 CPG with inter-procedural analysis and framework awareness.
    Produces a CodePropertyGraph compatible with V1/V3 consumers but with
    richer edges and metadata.
    """

    def __init__(self):
        self.functions: dict[str, FunctionInfo] = {}
        self.call_sites: list[CallSite] = []
        self._file_contents: dict[str, str] = {}

    def build(self, files: list[str], infra_auth_map: dict[str, str] | None = None) -> CodePropertyGraph:
        """
        Build enhanced CPG from Python files.

        Args:
            files: list of Python file paths to analyze
            infra_auth_map: mapping of handler function names to auth context
                           (from CDK infrastructure analysis)
                           e.g. {"handler_v3": "none", "handler": "authorizer"}
        """
        cpg = CodePropertyGraph()
        infra_auth_map = infra_auth_map or {}

        # Phase 1: Build per-file AST/CFG/DFG and discover functions
        for file_path in files:
            try:
                content = Path(file_path).read_text(encoding="utf-8")
                self._file_contents[file_path] = content
                self._process_file(cpg, file_path, content)
            except Exception as e:
                logger.warning(f"Failed to parse {file_path}: {e}")

        # Phase 2: Build call graph and inter-procedural DFG
        self._build_call_graph(cpg)
        self._build_interprocedural_dfg(cpg)

        # Phase 3: Mark security roles with extended patterns
        self._mark_roles_extended(cpg)

        # Phase 4: Annotate handlers with auth context from infra
        self._annotate_auth_context(cpg, infra_auth_map)

        logger.info(
            f"V4 CPG built: {cpg.node_count()} nodes, {cpg.edge_count()} edges, "
            f"{len(cpg.sources)} sources, {len(cpg.sinks)} sinks, "
            f"{len(cpg.sanitizers)} sanitizers, {len(cpg._gates)} gates, "
            f"{len(self.functions)} functions, {len(self.call_sites)} call sites"
        )
        return cpg

    def _process_file(self, cpg: CodePropertyGraph, file_path: str, content: str):
        lines = content.split("\n")
        if TREE_SITTER_AVAILABLE:
            self._process_with_tree_sitter(cpg, file_path, content, lines)
        else:
            self._process_with_regex(cpg, file_path, content, lines)

    # ═══════════════════════════════════════════════════════════════
    # TREE-SITTER PARSING
    # ═══════════════════════════════════════════════════════════════

    def _process_with_tree_sitter(self, cpg: CodePropertyGraph, file_path: str,
                                   content: str, lines: list[str]):
        parser = Parser(PY_LANGUAGE)
        tree = parser.parse(bytes(content, "utf-8"))

        self._visit_ts_node(cpg, tree.root_node, file_path, lines, parent_func=None)
        self._build_cfg_edges_ts(cpg, tree.root_node, file_path)
        self._build_dfg_edges(cpg, file_path, lines)
        self._extract_functions_ts(tree.root_node, file_path, lines)
        self._extract_call_sites_ts(tree.root_node, file_path, lines)

    def _visit_ts_node(self, cpg: CodePropertyGraph, node, file_path: str,
                       lines: list[str], parent_func: str | None):
        node_id = f"{file_path}:{node.start_point[0] + 1}:{node.start_point[1]}"
        line_num = node.start_point[0] + 1
        text = node.text.decode("utf-8") if node.text else ""

        significant_types = {
            "function_definition", "class_definition", "assignment",
            "expression_statement", "call", "if_statement", "for_statement",
            "while_statement", "return_statement", "try_statement",
            "import_statement", "import_from_statement", "decorated_definition",
        }

        if node.type in significant_types:
            cpg.add_node(node_id,
                        node_type=node.type,
                        text=text[:500],
                        file_path=file_path,
                        line=line_num,
                        func_scope=parent_func or "")

            if node.type == "function_definition":
                parent_func = node_id

        for child in node.children:
            self._visit_ts_node(cpg, child, file_path, lines, parent_func)

    def _build_cfg_edges_ts(self, cpg: CodePropertyGraph, root_node, file_path: str):
        functions = self._find_ts_functions(root_node)
        for func_node in functions:
            body = None
            for child in func_node.children:
                if child.type == "block":
                    body = child
                    break
            if not body:
                continue

            statements = [c for c in body.children
                         if c.type in ("expression_statement", "assignment",
                                      "return_statement", "if_statement",
                                      "for_statement", "while_statement",
                                      "try_statement")]
            for i in range(len(statements) - 1):
                src_id = f"{file_path}:{statements[i].start_point[0] + 1}:{statements[i].start_point[1]}"
                dst_id = f"{file_path}:{statements[i+1].start_point[0] + 1}:{statements[i+1].start_point[1]}"
                if src_id in cpg.graph and dst_id in cpg.graph:
                    cpg.add_edge(src_id, dst_id, edge_type="cfg_next")

    def _extract_functions_ts(self, root_node, file_path: str, lines: list[str]):
        for func_node in self._find_ts_functions(root_node):
            name = ""
            params = []
            for child in func_node.children:
                if child.type == "identifier":
                    name = child.text.decode("utf-8")
                elif child.type == "parameters":
                    for p in child.children:
                        if p.type == "identifier":
                            params.append(p.text.decode("utf-8"))
                        elif p.type in ("default_parameter", "typed_parameter", "typed_default_parameter"):
                            for pc in p.children:
                                if pc.type == "identifier":
                                    params.append(pc.text.decode("utf-8"))
                                    break

            if name:
                line_num = func_node.start_point[0] + 1
                node_id = f"{file_path}:{line_num}:{func_node.start_point[1]}"
                is_handler = any(re.search(pat, f"def {name}(") for pat in HANDLER_SIGNATURES)

                self.functions[f"{file_path}::{name}"] = FunctionInfo(
                    node_id=node_id,
                    name=name,
                    file_path=file_path,
                    line=line_num,
                    params=params,
                    is_handler=is_handler,
                )

    def _extract_call_sites_ts(self, root_node, file_path: str, lines: list[str]):
        self._walk_for_calls_ts(root_node, file_path, lines)

    def _walk_for_calls_ts(self, node, file_path: str, lines: list[str]):
        if node.type == "call":
            func_name = ""
            args = []
            for child in node.children:
                if child.type in ("identifier", "attribute"):
                    func_name = child.text.decode("utf-8")
                elif child.type == "argument_list":
                    for arg in child.children:
                        if arg.type not in ("(", ")", ","):
                            args.append(arg.text.decode("utf-8") if arg.text else "")

            if func_name:
                line_num = node.start_point[0] + 1
                caller_id = f"{file_path}:{line_num}:{node.start_point[1]}"
                self.call_sites.append(CallSite(
                    caller_node_id=caller_id,
                    callee_name=func_name,
                    args=args,
                    file_path=file_path,
                    line=line_num,
                ))

        for child in node.children:
            self._walk_for_calls_ts(child, file_path, lines)

    def _find_ts_functions(self, node) -> list:
        results = []
        if node.type == "function_definition":
            results.append(node)
        for child in node.children:
            results.extend(self._find_ts_functions(child))
        return results

    # ═══════════════════════════════════════════════════════════════
    # REGEX FALLBACK PARSING
    # ═══════════════════════════════════════════════════════════════

    def _process_with_regex(self, cpg: CodePropertyGraph, file_path: str,
                            content: str, lines: list[str]):
        current_func = None
        indent_stack: list[tuple[int, str]] = []

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            indent = len(line) - len(line.lstrip())

            # Track function scope
            func_match = re.match(r"def\s+(\w+)\s*\((.*?)\)", stripped)
            if func_match:
                func_name = func_match.group(1)
                params_str = func_match.group(2)
                params = [p.strip().split(":")[0].split("=")[0].strip()
                         for p in params_str.split(",") if p.strip()]

                node_id = f"{file_path}:{i}:0"
                current_func = f"{file_path}::{func_name}"
                is_handler = any(re.search(pat, stripped) for pat in HANDLER_SIGNATURES)

                self.functions[current_func] = FunctionInfo(
                    node_id=node_id,
                    name=func_name,
                    file_path=file_path,
                    line=i,
                    params=params,
                    is_handler=is_handler,
                )
                indent_stack = [(indent, current_func)]

            # Track indent to know when we leave a function
            elif indent_stack and indent <= indent_stack[-1][0]:
                current_func = None
                indent_stack = []

            node_id = f"{file_path}:{i}:0"
            node_type = self._classify_line(stripped)

            if node_type:
                cpg.add_node(node_id,
                            node_type=node_type,
                            text=stripped[:500],
                            file_path=file_path,
                            line=i,
                            func_scope=current_func or "")

            # Extract call sites
            call_match = re.findall(r"(\w[\w.]*)\s*\(", stripped)
            for callee in call_match:
                if callee not in ("if", "for", "while", "def", "class", "return", "print"):
                    self.call_sites.append(CallSite(
                        caller_node_id=node_id,
                        callee_name=callee,
                        args=[],  # regex can't reliably extract args
                        file_path=file_path,
                        line=i,
                    ))

            # Track return statements for the current function
            if current_func and stripped.startswith("return "):
                if current_func in self.functions:
                    self.functions[current_func].return_nodes.append(node_id)

        # Build sequential CFG within each file
        prev_id = None
        for node_id in sorted(
            (n for n in cpg.graph.nodes()
             if cpg.graph.nodes[n].get("file_path") == file_path),
            key=lambda n: cpg.graph.nodes[n].get("line", 0)
        ):
            if prev_id:
                cpg.add_edge(prev_id, node_id, edge_type="cfg_next")
            prev_id = node_id

        self._build_dfg_edges(cpg, file_path, lines)

    def _classify_line(self, line: str) -> str | None:
        if line.startswith("def "):
            return "function_definition"
        if line.startswith("class "):
            return "class_definition"
        if line.startswith("return "):
            return "return_statement"
        if line.startswith("if ") or line.startswith("elif "):
            return "if_statement"
        if line.startswith("for "):
            return "for_statement"
        if "=" in line and not line.startswith("==") and "==" not in line.split("=")[0]:
            return "assignment"
        if "(" in line:
            return "expression_statement"
        return None

    # ═══════════════════════════════════════════════════════════════
    # INTRA-PROCEDURAL DFG
    # ═══════════════════════════════════════════════════════════════

    def _build_dfg_edges(self, cpg: CodePropertyGraph, file_path: str, lines: list[str]):
        assignments: dict[str, str] = {}

        file_nodes = sorted(
            (nid for nid in cpg.graph.nodes()
             if cpg.graph.nodes[nid].get("file_path") == file_path),
            key=lambda n: cpg.graph.nodes[n].get("line", 0)
        )

        for node_id in file_nodes:
            attrs = cpg.graph.nodes[node_id]
            text = attrs.get("text", "")
            node_type = attrs.get("node_type", "")

            if node_type == "assignment" and "=" in text:
                lhs = text.split("=")[0].strip()
                # Handle tuple unpacking roughly
                var_names = [v.strip() for v in lhs.split(",")]
                for var_name in var_names:
                    if var_name and var_name.isidentifier():
                        assignments[var_name] = node_id

            elif node_type in ("expression_statement", "return_statement", "if_statement"):
                for var_name, def_node in assignments.items():
                    if var_name in text and def_node != node_id:
                        cpg.add_edge(def_node, node_id, edge_type="dfg_def_use",
                                    variable=var_name)

    # ═══════════════════════════════════════════════════════════════
    # INTER-PROCEDURAL ANALYSIS
    # ═══════════════════════════════════════════════════════════════

    def _build_call_graph(self, cpg: CodePropertyGraph):
        """Connect call sites to function definitions."""
        func_by_name: dict[str, list[FunctionInfo]] = {}
        for key, info in self.functions.items():
            func_by_name.setdefault(info.name, []).append(info)

        for cs in self.call_sites:
            # Resolve callee: try exact match, then basename of dotted name
            callee_base = cs.callee_name.split(".")[-1]
            targets = func_by_name.get(callee_base, [])

            for target in targets:
                # Add CALL edge from call site to function entry
                if cs.caller_node_id in cpg.graph and target.node_id in cpg.graph:
                    cpg.add_edge(cs.caller_node_id, target.node_id,
                                edge_type="call",
                                callee=target.name,
                                args=cs.args[:5])
                    target.calls.append(cs.caller_node_id)

    def _build_interprocedural_dfg(self, cpg: CodePropertyGraph):
        """
        Build parameter binding and return flow edges.
        - param_binding: caller arg N → callee param N
        - return_flow: callee return → caller call site
        """
        func_by_name: dict[str, list[FunctionInfo]] = {}
        for key, info in self.functions.items():
            func_by_name.setdefault(info.name, []).append(info)

        for cs in self.call_sites:
            callee_base = cs.callee_name.split(".")[-1]
            targets = func_by_name.get(callee_base, [])

            for target in targets:
                # Parameter binding: arg[i] → param[i]
                for i, arg in enumerate(cs.args):
                    if i < len(target.params):
                        # Find the first node in the callee that uses this param
                        param_name = target.params[i]
                        param_nodes = self._find_param_use_nodes(cpg, target, param_name)
                        for pn in param_nodes[:1]:  # Link to first use
                            if cs.caller_node_id in cpg.graph and pn in cpg.graph:
                                cpg.add_edge(cs.caller_node_id, pn,
                                            edge_type="dfg_param",
                                            variable=param_name,
                                            arg_index=i)

                # Return flow: callee return → caller call site
                for ret_node in target.return_nodes:
                    if ret_node in cpg.graph and cs.caller_node_id in cpg.graph:
                        cpg.add_edge(ret_node, cs.caller_node_id,
                                    edge_type="dfg_return",
                                    callee=target.name)

    def _find_param_use_nodes(self, cpg: CodePropertyGraph, func: FunctionInfo,
                              param_name: str) -> list[str]:
        """Find nodes in a function that use a given parameter."""
        results = []
        for node_id, attrs in cpg.graph.nodes(data=True):
            if (attrs.get("file_path") == func.file_path
                and attrs.get("func_scope") == f"{func.file_path}::{func.name}"
                and param_name in attrs.get("text", "")):
                results.append(node_id)
        return results

    # ═══════════════════════════════════════════════════════════════
    # SECURITY ROLE MARKING
    # ═══════════════════════════════════════════════════════════════

    def _mark_roles_extended(self, cpg: CodePropertyGraph):
        for node_id, attrs in cpg.graph.nodes(data=True):
            text = attrs.get("text", "")

            # Sources
            for pattern, source_type, desc in SOURCE_PATTERNS_EXTENDED:
                if pattern in text:
                    cpg.mark_node(node_id, "source")
                    cpg.graph.nodes[node_id]["source_type"] = source_type
                    cpg.graph.nodes[node_id]["source_desc"] = desc
                    break

            # Sinks
            for pattern, sink_type, desc in SINK_PATTERNS_EXTENDED:
                if pattern in text:
                    cpg.mark_node(node_id, "sink")
                    cpg.graph.nodes[node_id]["sink_type"] = sink_type
                    cpg.graph.nodes[node_id]["sink_desc"] = desc
                    break

            # Sanitizers
            for pattern, san_type, desc in SANITIZER_PATTERNS_EXTENDED:
                if pattern in text:
                    cpg.mark_node(node_id, "sanitizer")
                    cpg.graph.nodes[node_id]["sanitizer_type"] = san_type
                    cpg.graph.nodes[node_id]["sanitizer_desc"] = desc
                    break

            # Gates
            for pattern, gate_type, desc in GATE_PATTERNS_EXTENDED:
                if re.search(pattern, text):
                    cpg.mark_node(node_id, "gate")
                    cpg.graph.nodes[node_id]["gate_type"] = gate_type
                    cpg.graph.nodes[node_id]["gate_desc"] = desc
                    break

            # Handler entry (new role)
            if attrs.get("node_type") == "function_definition":
                func_key = None
                for key, info in self.functions.items():
                    if info.node_id == node_id and info.is_handler:
                        func_key = key
                        break
                if func_key:
                    cpg.graph.nodes[node_id]["role"] = "handler_entry"
                    cpg.graph.nodes[node_id]["handler_name"] = self.functions[func_key].name

    def _annotate_auth_context(self, cpg: CodePropertyGraph, infra_auth_map: dict[str, str]):
        """
        Annotate handler entry nodes with their infrastructure auth context.
        infra_auth_map: {"handler_v3": "none", "handler": "authorizer", "observer": "none"}
        """
        for func_key, info in self.functions.items():
            if info.is_handler and info.node_id in cpg.graph:
                # Check if this handler has auth configured in infra
                auth = infra_auth_map.get(info.name, "")
                if not auth:
                    # Heuristic: check if the handler reads authorizer context
                    content = self._file_contents.get(info.file_path, "")
                    if "requestContext" in content and "authorizer" in content:
                        auth = "authorizer_in_code"
                    else:
                        auth = "unknown"

                cpg.graph.nodes[info.node_id]["auth_context"] = auth
                info.auth_context = auth

    # ═══════════════════════════════════════════════════════════════
    # QUERY HELPERS
    # ═══════════════════════════════════════════════════════════════

    def get_handlers(self) -> list[FunctionInfo]:
        return [f for f in self.functions.values() if f.is_handler]

    def get_function_for_node(self, cpg: CodePropertyGraph, node_id: str) -> FunctionInfo | None:
        """Find which function contains a given node."""
        func_scope = cpg.graph.nodes.get(node_id, {}).get("func_scope", "")
        if func_scope:
            return self.functions.get(func_scope)
        # Fallback: match by file and line range
        node_attrs = cpg.graph.nodes.get(node_id, {})
        node_file = node_attrs.get("file_path", "")
        node_line = node_attrs.get("line", 0)
        best = None
        for info in self.functions.values():
            if info.file_path == node_file and info.line <= node_line:
                if best is None or info.line > best.line:
                    best = info
        return best

    def get_all_paths_to_sink(self, cpg: CodePropertyGraph, sink_id: str,
                              max_depth: int = 20) -> list[list[str]]:
        """Find all handler_entry → sink paths (for differential analysis)."""
        handler_ids = [f.node_id for f in self.functions.values() if f.is_handler]
        paths = []
        for hid in handler_ids:
            if hid not in cpg.graph or sink_id not in cpg.graph:
                continue
            try:
                for path in nx.all_simple_paths(cpg.graph, hid, sink_id, cutoff=max_depth):
                    paths.append(path)
            except (nx.NodeNotFound, nx.NetworkXError):
                continue
        return paths

    def get_guards_on_path(self, cpg: CodePropertyGraph, path: list[str]) -> list[dict]:
        """Extract all security gates/sanitizers on a given path."""
        guards = []
        for node_id in path:
            role = cpg.get_role(node_id)
            if role in ("gate", "sanitizer"):
                guards.append({
                    "node_id": node_id,
                    "role": role,
                    "type": cpg.graph.nodes[node_id].get(f"{role}_type", ""),
                    "desc": cpg.graph.nodes[node_id].get(f"{role}_desc", ""),
                    "text": cpg.get_text(node_id)[:200],
                })
        return guards
