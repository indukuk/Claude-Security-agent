"""
Code Property Graph builder for Python using tree-sitter.
Constructs AST + CFG + DFG in a single unified graph.
"""
from __future__ import annotations


import logging
from pathlib import Path

from src.common.graph import CodePropertyGraph

logger = logging.getLogger(__name__)

try:
    import tree_sitter_python as tspython
    from tree_sitter import Language, Parser

    PY_LANGUAGE = Language(tspython.language())
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    logger.warning("tree-sitter not available, falling back to regex-based parsing")


class PythonCPGBuilder:
    """
    Build a Code Property Graph from Python source files.
    Uses tree-sitter for AST, then constructs CFG and DFG edges.
    """

    # Patterns that identify security-relevant nodes
    SOURCE_PATTERNS = [
        "event['body']", "event.get('body'", "json.loads(event",
        "body.get(", "body['", "state['messages']", "state.get('messages'",
        "request.args", "request.form", "request.json",
    ]

    SINK_PATTERNS = [
        "table.query(", "table.put_item(", "table.update_item(",
        "table.get_item(", "table.delete_item(",
        "generate_presigned_url(", "s3_client.put_object(",
        "admin_create_user(", "admin_update_user_attributes(",
        "exec(", "eval(", "subprocess",
        "invoke_model(", "logger.info(", "print(",
    ]

    SANITIZER_PATTERNS = [
        "check_permission(", "model_validate(", "validate_python(",
        "ExpressionAttributeValues", "os.path.basename(",
        "shlex.quote(", "literal_eval(",
    ]

    GATE_PATTERNS = [
        "if.*tenant_id.*!=", "if not.*allowed", "return.*403",
        "return.*401", "raise.*Unauthorized", "raise.*Forbidden",
    ]

    def build(self, files: list[str], inferred_specs: dict) -> CodePropertyGraph:
        """Build CPG from a list of Python files."""
        cpg = CodePropertyGraph()

        for file_path in files:
            try:
                content = Path(file_path).read_text(encoding="utf-8")
                self._process_file(cpg, file_path, content)
            except Exception as e:
                logger.warning(f"Failed to parse {file_path}: {e}")
                continue

        # Mark roles based on patterns + inferred specs
        self._mark_roles(cpg, inferred_specs)

        logger.info(
            f"CPG built: {cpg.node_count()} nodes, {cpg.edge_count()} edges, "
            f"{len(cpg.sources)} sources, {len(cpg.sinks)} sinks"
        )
        return cpg

    def _process_file(self, cpg: CodePropertyGraph, file_path: str, content: str):
        """Process a single Python file into CPG nodes and edges."""
        lines = content.split("\n")

        if TREE_SITTER_AVAILABLE:
            self._process_with_tree_sitter(cpg, file_path, content, lines)
        else:
            self._process_with_regex(cpg, file_path, content, lines)

    def _process_with_tree_sitter(self, cpg: CodePropertyGraph, file_path: str,
                                   content: str, lines: list[str]):
        """Full tree-sitter based AST → CPG construction."""
        parser = Parser(PY_LANGUAGE)
        tree = parser.parse(bytes(content, "utf-8"))

        self._visit_node(cpg, tree.root_node, file_path, lines, parent_id=None)
        self._build_cfg_edges(cpg, tree.root_node, file_path, lines)
        self._build_dfg_edges(cpg, file_path, lines)

    def _visit_node(self, cpg: CodePropertyGraph, node, file_path: str,
                    lines: list[str], parent_id: str | None):
        """Recursively visit tree-sitter nodes, creating CPG nodes."""
        node_id = f"{file_path}:{node.start_point[0] + 1}:{node.start_point[1]}"
        line_num = node.start_point[0] + 1
        text = node.text.decode("utf-8") if node.text else ""

        # Only create nodes for significant constructs
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
                        line=line_num)

            if parent_id:
                cpg.add_edge(parent_id, node_id, edge_type="ast_child")

            parent_id = node_id

        for child in node.children:
            self._visit_node(cpg, child, file_path, lines, parent_id)

    def _build_cfg_edges(self, cpg: CodePropertyGraph, root_node, file_path: str,
                         lines: list[str]):
        """Build control flow edges between statements."""
        # Find function definitions and build CFG within each
        functions = self._find_functions(root_node)

        for func_node in functions:
            body = self._get_function_body(func_node)
            if not body:
                continue

            statements = [child for child in body.children
                         if child.type in ("expression_statement", "assignment",
                                          "return_statement", "if_statement",
                                          "for_statement", "while_statement",
                                          "try_statement")]

            for i in range(len(statements) - 1):
                src_id = f"{file_path}:{statements[i].start_point[0] + 1}:{statements[i].start_point[1]}"
                dst_id = f"{file_path}:{statements[i+1].start_point[0] + 1}:{statements[i+1].start_point[1]}"

                if src_id in cpg.graph and dst_id in cpg.graph:
                    cpg.add_edge(src_id, dst_id, edge_type="cfg_next")

    def _build_dfg_edges(self, cpg: CodePropertyGraph, file_path: str, lines: list[str]):
        """
        Build data flow edges based on variable assignments and uses.
        Simplified: track assignments and find subsequent uses of the same variable.
        """
        assignments: dict[str, str] = {}  # var_name → node_id of definition

        for node_id, attrs in cpg.graph.nodes(data=True):
            if attrs.get("file_path") != file_path:
                continue

            text = attrs.get("text", "")
            node_type = attrs.get("node_type", "")

            # Track assignments: var_name = value
            if node_type == "assignment" and "=" in text:
                var_name = text.split("=")[0].strip()
                if var_name and not var_name.startswith("#"):
                    assignments[var_name] = node_id

            # Track uses of previously assigned variables
            elif node_type in ("expression_statement", "call", "return_statement"):
                for var_name, def_node in assignments.items():
                    if var_name in text and def_node != node_id:
                        cpg.add_edge(def_node, node_id, edge_type="dfg_def_use",
                                    variable=var_name)

    def _process_with_regex(self, cpg: CodePropertyGraph, file_path: str,
                            content: str, lines: list[str]):
        """Fallback: regex-based parsing when tree-sitter isn't available."""
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            node_id = f"{file_path}:{i}:0"
            node_type = self._classify_line(stripped)

            if node_type:
                cpg.add_node(node_id,
                            node_type=node_type,
                            text=stripped[:500],
                            file_path=file_path,
                            line=i)

        # Build simple sequential CFG
        prev_id = None
        for node_id in sorted(cpg.graph.nodes(),
                             key=lambda n: cpg.graph.nodes[n].get("line", 0)
                             if cpg.graph.nodes[n].get("file_path") == file_path else 0):
            if cpg.graph.nodes[node_id].get("file_path") == file_path:
                if prev_id:
                    cpg.add_edge(prev_id, node_id, edge_type="cfg_next")
                prev_id = node_id

        # Build DFG (same logic as tree-sitter version)
        self._build_dfg_edges(cpg, file_path, lines)

    def _classify_line(self, line: str) -> str | None:
        """Classify a line of code by type (regex fallback)."""
        if line.startswith("def "):
            return "function_definition"
        if line.startswith("class "):
            return "class_definition"
        if "=" in line and not line.startswith("if ") and not line.startswith("return"):
            return "assignment"
        if line.startswith("return "):
            return "return_statement"
        if line.startswith("if "):
            return "if_statement"
        if line.startswith("for "):
            return "for_statement"
        if "(" in line:
            return "expression_statement"
        return None

    def _mark_roles(self, cpg: CodePropertyGraph, inferred_specs: dict):
        """Mark nodes with security roles based on pattern matching."""
        import re

        for node_id, attrs in cpg.graph.nodes(data=True):
            text = attrs.get("text", "")

            # Check source patterns
            for pattern in self.SOURCE_PATTERNS:
                if pattern in text:
                    cpg.mark_node(node_id, "source")
                    break

            # Check sink patterns
            for pattern in self.SINK_PATTERNS:
                if pattern in text:
                    cpg.mark_node(node_id, "sink")
                    break

            # Check sanitizer patterns
            for pattern in self.SANITIZER_PATTERNS:
                if pattern in text:
                    cpg.mark_node(node_id, "sanitizer")
                    break

            # Check gate patterns (regex for these)
            for pattern in self.GATE_PATTERNS:
                if re.search(pattern, text):
                    cpg.mark_node(node_id, "gate")
                    break

        # Apply inferred specs
        if inferred_specs:
            for spec in inferred_specs.get("sources", []):
                for node_id, attrs in cpg.graph.nodes(data=True):
                    if spec.get("function", "") in attrs.get("text", ""):
                        cpg.mark_node(node_id, "source")
            for spec in inferred_specs.get("sinks", []):
                for node_id, attrs in cpg.graph.nodes(data=True):
                    if spec.get("function", "") in attrs.get("text", ""):
                        cpg.mark_node(node_id, "sink")

    def _find_functions(self, root_node) -> list:
        """Find all function_definition nodes in the tree."""
        functions = []
        if root_node.type == "function_definition":
            functions.append(root_node)
        for child in root_node.children:
            functions.extend(self._find_functions(child))
        return functions

    def _get_function_body(self, func_node):
        """Get the body block of a function definition."""
        for child in func_node.children:
            if child.type == "block":
                return child
        return None
