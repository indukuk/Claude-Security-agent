"""
Evidence Walk Generator — produces step-by-step source→sink traces.

Given a finding (file, line, category) and the CPG, generates a 5-9 step
annotated trace showing how attacker-controlled input reaches a dangerous
operation, with semantic annotations at each hop.
"""
from __future__ import annotations

import re
import logging
from pathlib import Path
from dataclasses import dataclass, field

import networkx as nx

from src.common.graph import CodePropertyGraph
from v4.cpg.enhanced_builder import EnhancedCPGBuilder, FunctionInfo

logger = logging.getLogger(__name__)

MAX_WALK_STEPS = 9
MIN_WALK_STEPS = 3


@dataclass
class WalkStep:
    """A single step in an evidence walk."""
    file_path: str
    line: int
    text: str
    step_type: str  # entry_point | assignment | call_boundary | sink | missing_check | data_load | gate
    annotation: str  # semantic description of what happens at this step
    tainted_var: str = ""
    function_name: str = ""
    is_cross_file: bool = False


@dataclass
class EvidenceWalk:
    """Complete evidence walk from entry to impact."""
    finding_id: str
    title: str
    entry_description: str  # e.g. "POST /v2 {action: 'status', job_id: '<any-uuid>'}"
    steps: list[WalkStep] = field(default_factory=list)
    impact_description: str = ""
    missing_controls: list[str] = field(default_factory=list)

    def render(self) -> str:
        """Render the walk as human-readable text."""
        lines = []
        lines.append(f"Entry: {self.entry_description}")

        for i, step in enumerate(self.steps):
            prefix = "  " if step.is_cross_file else ""
            fname = Path(step.file_path).name if step.file_path else ""
            loc = f"{fname}:{step.line}" if fname else ""

            if step.step_type == "entry_point":
                lines.append(f"→ {step.text} ({loc})")
            elif step.step_type == "call_boundary":
                lines.append(f"→ {step.annotation} ({loc})")
            elif step.step_type == "assignment":
                lines.append(f"{prefix}→ {step.annotation} ({loc})")
            elif step.step_type == "data_load":
                lines.append(f"{prefix}→ {step.annotation} ({loc})")
            elif step.step_type == "sink":
                lines.append(f"{prefix}→ {step.annotation} ({loc})")
            elif step.step_type == "missing_check":
                lines.append(f"{prefix}  ✗ MISSING: {step.annotation}")
            elif step.step_type == "gate":
                lines.append(f"{prefix}  ✓ CHECK: {step.annotation} ({loc})")
            else:
                lines.append(f"{prefix}→ {step.text[:80]} ({loc})")

        if self.missing_controls:
            lines.append("")
            for mc in self.missing_controls:
                lines.append(f"  ✗ MISSING: {mc}")

        if self.impact_description:
            lines.append(f"\nImpact: {self.impact_description}")

        return "\n".join(lines)


class EvidenceWalker:
    """
    Generates evidence walks by traversing the CPG from source to sink.

    Algorithm:
    1. Find the sink node matching the finding's file:line
    2. BFS backward from sink to find reaching sources
    3. Forward-walk the shortest source→sink path
    4. Compress and annotate each step
    5. Insert "missing check" annotations where guards SHOULD exist
    """

    def __init__(self, cpg: CodePropertyGraph, builder: EnhancedCPGBuilder):
        self.cpg = cpg
        self.builder = builder
        self._file_contents: dict[str, list[str]] = {}

    def generate_walk(self, finding: dict) -> EvidenceWalk | None:
        """
        Generate an evidence walk for a finding.

        Args:
            finding: dict with keys: id, title, file_path, line, category, severity
        """
        file_path = finding.get("file_path", "")
        line = finding.get("line", 0)
        category = finding.get("category", "")
        title = finding.get("title", "")

        # Strategy 1: Finding points to a sink — walk backward to source
        sink_node = self._find_nearest_sink(file_path, line)
        if sink_node:
            source_node, path = self._find_reaching_source(sink_node)
            if source_node and path:
                return self._build_walk(finding, source_node, sink_node, path, category)

            source_node, path = self._find_source_via_slice(sink_node)
            if source_node and path:
                return self._build_walk(finding, source_node, sink_node, path, category)

        # Strategy 2: Finding points to a source — walk forward to nearest sink
        source_node = self._find_nearest_source(file_path, line)
        if source_node:
            sink_node, path = self._find_reachable_sink(source_node)
            if sink_node and path:
                return self._build_walk(finding, source_node, sink_node, path, category)

        # Strategy 3: Find any source→sink pair in the same function
        func_source, func_sink, path = self._find_pair_in_function(file_path, line)
        if func_source and func_sink and path:
            return self._build_walk(finding, func_source, func_sink, path, category)

        logger.debug(f"No evidence walk for {title} at {file_path}:{line}")
        return None

    def _find_node_at(self, file_path: str, line: int) -> str | None:
        """Find a CPG node at the given file:line."""
        candidates = []
        for node_id, attrs in self.cpg.graph.nodes(data=True):
            if attrs.get("file_path") == file_path and attrs.get("line") == line:
                candidates.append(node_id)

        if not candidates:
            # Try approximate match (within 2 lines)
            for node_id, attrs in self.cpg.graph.nodes(data=True):
                if (attrs.get("file_path") == file_path
                    and abs(attrs.get("line", 0) - line) <= 2):
                    candidates.append(node_id)

        return candidates[0] if candidates else None

    def _find_nearest_sink(self, file_path: str, line: int) -> str | None:
        """Find the nearest sink node to a given location."""
        best = None
        best_dist = float("inf")
        for sink_id in self.cpg.sinks:
            attrs = self.cpg.graph.nodes.get(sink_id, {})
            if attrs.get("file_path") == file_path:
                dist = abs(attrs.get("line", 0) - line)
                if dist < best_dist:
                    best = sink_id
                    best_dist = dist
        return best if best_dist <= 15 else None

    def _find_nearest_source(self, file_path: str, line: int) -> str | None:
        """Find the nearest source node to a given location."""
        best = None
        best_dist = float("inf")
        for src_id in self.cpg.sources:
            attrs = self.cpg.graph.nodes.get(src_id, {})
            if attrs.get("file_path") == file_path:
                dist = abs(attrs.get("line", 0) - line)
                if dist < best_dist:
                    best = src_id
                    best_dist = dist
        return best if best_dist <= 20 else None

    def _find_reachable_sink(self, source_node: str) -> tuple[str | None, list[str]]:
        """BFS forward from source to find the nearest reachable sink."""
        dfg_types = ["dfg_def_use", "dfg_param", "dfg_return", "dfg_assign", "dfg_subscript"]

        visited = set()
        queue = [(source_node, [source_node])]

        while queue:
            current, path = queue.pop(0)
            if current in visited or len(path) > 15:
                continue
            visited.add(current)

            if current in self.cpg.sinks and current != source_node:
                return current, path

            for succ in self.cpg.successors(current, edge_types=dfg_types):
                if succ not in visited:
                    queue.append((succ, path + [succ]))

            # Also try CFG successors
            for succ in self.cpg.successors(current, edge_types=["cfg_next"]):
                if succ not in visited:
                    queue.append((succ, path + [succ]))

        return None, []

    def _find_pair_in_function(self, file_path: str, line: int) -> tuple[str | None, str | None, list[str]]:
        """Find the best source→sink pair in the same function as the finding."""
        # Identify which function contains this line
        target_func = None
        for key, info in self.builder.functions.items():
            if info.file_path == file_path and info.line <= line <= info.line + 100:
                target_func = info
                break

        if not target_func:
            return None, None, []

        # Find sources and sinks within this function's scope
        func_sources = []
        func_sinks = []
        for nid, attrs in self.cpg.graph.nodes(data=True):
            if attrs.get("file_path") == file_path:
                node_line = attrs.get("line", 0)
                if target_func.line <= node_line <= target_func.line + 150:
                    role = attrs.get("role", "")
                    if role == "source":
                        func_sources.append(nid)
                    elif role == "sink":
                        func_sinks.append(nid)

        # Try to find a path between any source and sink in this function
        for src in func_sources:
            for sink in func_sinks:
                try:
                    path = nx.shortest_path(self.cpg.graph, src, sink)
                    if 2 <= len(path) <= 15:
                        return src, sink, path
                except (nx.NodeNotFound, nx.NetworkXNoPath):
                    continue

        return None, None, []

    def _find_reaching_source(self, sink_node: str) -> tuple[str | None, list[str]]:
        """BFS backward from sink to find the nearest reaching source."""
        dfg_types = ["dfg_def_use", "dfg_param", "dfg_return", "dfg_assign", "dfg_subscript"]

        visited = set()
        queue = [(sink_node, [sink_node])]

        while queue:
            current, path = queue.pop(0)
            if current in visited or len(path) > 15:
                continue
            visited.add(current)

            if current in self.cpg.sources and current != sink_node:
                return current, list(reversed(path))

            # Walk backward through DFG edges
            for pred in self.cpg.predecessors(current, edge_types=dfg_types):
                if pred not in visited:
                    queue.append((pred, path + [pred]))

            # Also try CFG predecessors (for control flow context)
            for pred in self.cpg.predecessors(current, edge_types=["cfg_next"]):
                if pred not in visited and self.cpg.get_role(pred) == "source":
                    queue.append((pred, path + [pred]))

        return None, []

    def _find_source_via_slice(self, sink_node: str) -> tuple[str | None, list[str]]:
        """Use backward slice to find any source influencing the sink."""
        slice_nodes = self.cpg.backward_slice(sink_node, max_depth=15)

        for node_id in slice_nodes:
            if node_id in self.cpg.sources:
                # Try to find a path through the graph
                try:
                    path = nx.shortest_path(self.cpg.graph, node_id, sink_node)
                    return node_id, path
                except (nx.NodeNotFound, nx.NetworkXNoPath):
                    continue

        return None, []

    def _build_walk(self, finding: dict, source_node: str, sink_node: str,
                    raw_path: list[str], category: str) -> EvidenceWalk:
        """Build an annotated evidence walk from the raw path."""
        # Compress the path to target length
        compressed = self._compress_path(raw_path)

        # Determine entry description
        entry_desc = self._make_entry_description(source_node, finding)

        walk = EvidenceWalk(
            finding_id=finding.get("id", ""),
            title=finding.get("title", ""),
            entry_description=entry_desc,
        )

        prev_file = ""
        for i, node_id in enumerate(compressed):
            attrs = self.cpg.graph.nodes.get(node_id, {})
            file_path = attrs.get("file_path", "")
            line = attrs.get("line", 0)
            text = attrs.get("text", "")
            role = attrs.get("role", "neutral")

            is_cross_file = file_path != prev_file and prev_file != ""
            prev_file = file_path

            # Determine step type and annotation
            step_type, annotation = self._annotate_step(
                node_id, attrs, role, i, len(compressed), category
            )

            # Determine tainted variable
            tainted_var = self._extract_tainted_var(attrs)

            # Get function context
            func = self.builder.get_function_for_node(self.cpg, node_id)
            func_name = func.name if func else ""

            walk.steps.append(WalkStep(
                file_path=file_path,
                line=line,
                text=text[:120],
                step_type=step_type,
                annotation=annotation,
                tainted_var=tainted_var,
                function_name=func_name,
                is_cross_file=is_cross_file,
            ))

        # Add missing control annotations
        walk.missing_controls = self._identify_missing_controls(
            raw_path, sink_node, category
        )

        # Impact description
        walk.impact_description = self._make_impact_description(sink_node, category)

        return walk

    def _compress_path(self, path: list[str]) -> list[str]:
        """Compress a path to 5-9 steps, keeping security-relevant nodes."""
        if len(path) <= MAX_WALK_STEPS:
            return path

        # Always keep: first (source), last (sink), and security-relevant nodes
        keep_indices = {0, len(path) - 1}

        for i, node_id in enumerate(path):
            role = self.cpg.get_role(node_id)
            if role in ("source", "sink", "sanitizer", "gate"):
                keep_indices.add(i)
            # Keep cross-file transitions
            if i > 0:
                prev_file = self.cpg.graph.nodes.get(path[i-1], {}).get("file_path")
                curr_file = self.cpg.graph.nodes.get(node_id, {}).get("file_path")
                if prev_file != curr_file:
                    keep_indices.add(i)
            # Keep call boundaries
            edge_data = self.cpg.graph.edges.get((path[i-1] if i > 0 else path[0], node_id), {})
            if edge_data.get("edge_type") in ("call", "dfg_param", "dfg_return"):
                keep_indices.add(i)

        # If still too many, sample evenly from the middle
        kept = sorted(keep_indices)
        if len(kept) > MAX_WALK_STEPS:
            # Keep first, last, and evenly spaced middle nodes
            middle = kept[1:-1]
            step = max(1, len(middle) // (MAX_WALK_STEPS - 2))
            kept = [kept[0]] + middle[::step][:MAX_WALK_STEPS - 2] + [kept[-1]]

        return [path[i] for i in kept]

    def _annotate_step(self, node_id: str, attrs: dict, role: str,
                       step_index: int, total_steps: int, category: str) -> tuple[str, str]:
        """Generate step type and annotation for a node."""
        text = attrs.get("text", "")
        node_type = attrs.get("node_type", "")

        # Source nodes
        if role == "source":
            source_desc = attrs.get("source_desc", "User-controlled input")
            var = self._extract_tainted_var(attrs)
            return "entry_point", f"{source_desc}: `{var}`" if var else source_desc

        # Sink nodes
        if role == "sink":
            sink_desc = attrs.get("sink_desc", "Security-sensitive operation")
            return "sink", f"{sink_desc}"

        # Gate nodes
        if role == "gate":
            gate_desc = attrs.get("gate_desc", "Security check")
            return "gate", gate_desc

        # Sanitizer nodes
        if role == "sanitizer":
            san_desc = attrs.get("sanitizer_desc", "Input sanitization")
            return "gate", f"Sanitization: {san_desc}"

        # Call boundaries (inter-procedural)
        edge_types_in = set()
        for _, _, data in self.cpg.graph.in_edges(node_id, data=True):
            edge_types_in.add(data.get("edge_type", ""))

        if "call" in edge_types_in or "dfg_param" in edge_types_in:
            func = self.builder.get_function_for_node(self.cpg, node_id)
            if func:
                return "call_boundary", f"Enters `{func.name}()` — tainted value passed as parameter"

        # Assignments
        if node_type == "assignment":
            var = text.split("=")[0].strip() if "=" in text else ""
            rhs = text.split("=", 1)[1].strip()[:60] if "=" in text else ""
            if var:
                return "assignment", f"`{var}` = {rhs}"

        # Data loads (DynamoDB get_item, etc)
        if "get_item" in text or "query(" in text:
            return "data_load", f"Database read: {text[:80]}"

        # Default
        return "assignment", text[:80]

    def _extract_tainted_var(self, attrs: dict) -> str:
        """Extract the primary variable name from a node."""
        text = attrs.get("text", "")
        if "=" in text and attrs.get("node_type") == "assignment":
            lhs = text.split("=")[0].strip()
            return lhs.split(",")[0].strip()
        # For body.get("X"), extract X
        match = re.search(r'\.get\(["\'](\w+)', text)
        if match:
            return match.group(1)
        # For body["X"], extract X
        match = re.search(r'\[["\'](\w+)', text)
        if match:
            return match.group(1)
        return ""

    def _identify_missing_controls(self, path: list[str], sink_node: str,
                                    category: str) -> list[str]:
        """Identify security controls that SHOULD exist on this path but don't."""
        missing = []

        # Check what guards exist on the path
        path_roles = {self.cpg.get_role(n) for n in path}
        path_gate_types = set()
        for n in path:
            gt = self.cpg.graph.nodes.get(n, {}).get("gate_type", "")
            if gt:
                path_gate_types.add(gt)

        sink_type = self.cpg.graph.nodes.get(sink_node, {}).get("sink_type", "")

        # Category-specific missing control detection
        if "cross-tenant" in category or "cross_tenant" in category:
            if "ownership_check" not in path_gate_types:
                missing.append("Ownership verification (tenant_id != requester.tenant_id)")

        if "path-traversal" in category:
            has_sanitizer = "sanitizer" in path_roles
            if not has_sanitizer:
                missing.append("Path traversal sanitization (remove /, .., \\)")

        if sink_type in ("dynamodb_write", "dynamodb_delete"):
            if "role_check" not in path_gate_types:
                missing.append("Role-based authorization check before write/delete")
            # Check for audit logging near the sink
            has_audit = any(
                any(pat in self.cpg.get_text(n) for pat in ("audit", "log_event"))
                for n in path
            )
            if not has_audit:
                missing.append("Audit logging for data modification")

        if sink_type == "dynamodb_read":
            if "ownership_check" not in path_gate_types:
                missing.append("Ownership verification after data load")

        if sink_type == "s3_presigned":
            has_sanitizer = "sanitizer" in path_roles
            if not has_sanitizer:
                missing.append("Filename/path sanitization before S3 key construction")

        if sink_type in ("cognito_admin",):
            if "role_check" not in path_gate_types:
                missing.append("Role authorization for admin Cognito operations")

        return missing

    def _make_entry_description(self, source_node: str, finding: dict) -> str:
        """Generate a concrete entry description (HTTP method, route, auth)."""
        source_attrs = self.cpg.graph.nodes.get(source_node, {})
        source_type = source_attrs.get("source_type", "")
        file_path = source_attrs.get("file_path", "")
        func = self.builder.get_function_for_node(self.cpg, source_node)

        # Determine HTTP method and route from handler context
        method = "POST"  # Lambda handlers are typically POST
        route = self._infer_route(file_path, func)
        auth = self._infer_auth(func)

        if source_type == "http_body":
            return f"{method} {route} (JSON body, {auth})"
        elif source_type == "http_header":
            return f"{method} {route} (HTTP headers, {auth})"
        elif source_type == "path_param":
            return f"{method} {route} (URL path params, {auth})"
        else:
            return f"{method} {route} ({auth})"

    def _infer_route(self, file_path: str, func: FunctionInfo | None) -> str:
        """Infer the API route from the handler file name."""
        fname = Path(file_path).stem if file_path else ""
        route_map = {
            "handler": "/v1/agent",
            "handler_v2": "/v2",
            "handler_v3": "/v3",
            "data_handler": "/data/{resource}",
            "risk_handler": "/risks",
            "auth_handler": "/auth",
            "user_management": "/users",
            "tenant_management": "/tenants",
            "authorizer": "/authorize",
        }
        return route_map.get(fname, f"/{fname}")

    def _infer_auth(self, func: FunctionInfo | None) -> str:
        """Infer authentication status from handler metadata."""
        if not func:
            return "auth unknown"
        auth = func.auth_context
        if auth == "none":
            return "NO authentication"
        elif auth == "authorizer":
            return "JWT authorizer"
        elif auth == "api_key":
            return "API key"
        return "auth context present"

    def _make_impact_description(self, sink_node: str, category: str) -> str:
        """Generate impact description based on category and sink."""
        sink_type = self.cpg.graph.nodes.get(sink_node, {}).get("sink_type", "")

        impacts = {
            "cross-tenant-access": "Attacker accesses or modifies another tenant's data",
            "cross_tenant_access": "Attacker accesses or modifies another tenant's data",
            "path-traversal": "Attacker reads/writes files outside intended tenant prefix",
            "privilege-escalation": "Lower-privilege user performs admin operations",
            "dom-xss": "Attacker executes JavaScript in victim's browser session",
            "info-disclosure": "Internal error details or sensitive data leaked to attacker",
            "cross-session-access": "Attacker accesses another user's session data",
        }

        return impacts.get(category, f"Security-sensitive operation ({sink_type}) reached with attacker-controlled input")

    def _get_file_lines(self, file_path: str) -> list[str]:
        """Get cached file lines."""
        if file_path not in self._file_contents:
            try:
                self._file_contents[file_path] = Path(file_path).read_text().split("\n")
            except (OSError, UnicodeDecodeError):
                self._file_contents[file_path] = []
        return self._file_contents[file_path]
