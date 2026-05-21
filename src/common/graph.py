"""
Graph utilities — NetworkX wrappers for CPG and infrastructure graphs.
"""
from __future__ import annotations


import json
import logging
from dataclasses import dataclass, field
from typing import Generator

import networkx as nx

logger = logging.getLogger(__name__)


@dataclass
class GraphNode:
    id: str
    node_type: str
    properties: dict = field(default_factory=dict)
    role: str = "neutral"  # source | sink | sanitizer | gate | neutral
    file_path: str = ""
    line: int = 0
    text: str = ""


class CodePropertyGraph:
    """
    Unified Code Property Graph: AST + CFG + DFG in one queryable structure.
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self._sources: list[str] = []
        self._sinks: list[str] = []
        self._sanitizers: list[str] = []
        self._gates: list[str] = []

    def add_node(self, node_id: str, **attrs):
        self.graph.add_node(node_id, **attrs)

    def add_edge(self, source: str, target: str, edge_type: str, **attrs):
        self.graph.add_edge(source, target, edge_type=edge_type, **attrs)

    def mark_node(self, node_id: str, role: str):
        if node_id in self.graph:
            self.graph.nodes[node_id]["role"] = role
            if role == "source":
                self._sources.append(node_id)
            elif role == "sink":
                self._sinks.append(node_id)
            elif role == "sanitizer":
                self._sanitizers.append(node_id)
            elif role == "gate":
                self._gates.append(node_id)

    @property
    def sources(self) -> list[str]:
        return self._sources

    @property
    def sinks(self) -> list[str]:
        return self._sinks

    @property
    def sanitizers(self) -> list[str]:
        return self._sanitizers

    def get_role(self, node_id: str) -> str:
        return self.graph.nodes.get(node_id, {}).get("role", "neutral")

    def get_text(self, node_id: str) -> str:
        return self.graph.nodes.get(node_id, {}).get("text", "")

    def get_file_line(self, node_id: str) -> tuple[str, int]:
        node = self.graph.nodes.get(node_id, {})
        return node.get("file_path", ""), node.get("line", 0)

    def successors(self, node_id: str, edge_types: list[str] | None = None) -> list[str]:
        if edge_types is None:
            return list(self.graph.successors(node_id))
        result = []
        for _, target, data in self.graph.out_edges(node_id, data=True):
            if data.get("edge_type") in edge_types:
                result.append(target)
        return result

    def predecessors(self, node_id: str, edge_types: list[str] | None = None) -> list[str]:
        if edge_types is None:
            return list(self.graph.predecessors(node_id))
        result = []
        for source, _, data in self.graph.in_edges(node_id, data=True):
            if data.get("edge_type") in edge_types:
                result.append(source)
        return result

    def find_taint_paths(
        self, max_depth: int = 15
    ) -> list[tuple[str, str, list[str]]]:
        """
        Find all paths from sources to sinks via DFG edges.
        Returns: list of (source, sink, path_nodes)
        """
        dfg_types = ["dfg_def_use", "dfg_param", "dfg_return", "dfg_assign", "dfg_subscript"]
        paths = []

        for source in self._sources:
            visited = set()
            queue = [(source, [source])]

            while queue:
                current, path = queue.pop(0)

                if current in visited or len(path) > max_depth:
                    continue
                visited.add(current)

                if current in self._sinks and current != source:
                    # Check: any sanitizer on path?
                    sanitized = any(n in self._sanitizers for n in path)
                    if not sanitized:
                        paths.append((source, current, list(path)))
                    continue

                if current in self._sanitizers:
                    continue  # Taint removed

                for neighbor in self.successors(current, edge_types=dfg_types):
                    if neighbor not in visited:
                        queue.append((neighbor, path + [neighbor]))

        return paths

    def backward_slice(self, node_id: str, max_depth: int = 20) -> set[str]:
        """Find all nodes that influence the given node's value."""
        dfg_types = ["dfg_def_use", "dfg_param", "dfg_assign", "dfg_subscript"]
        influencers = set()
        queue = [(node_id, 0)]

        while queue:
            current, depth = queue.pop(0)
            if depth > max_depth or current in influencers:
                continue
            influencers.add(current)

            for pred in self.predecessors(current, edge_types=dfg_types):
                queue.append((pred, depth + 1))

        return influencers

    def extract_slice(self, source: str, sink: str) -> "CPGSlice":
        """Extract minimal subgraph relevant to analyzing a source→sink path."""
        dfg_types = ["dfg_def_use", "dfg_param", "dfg_return", "dfg_assign", "dfg_subscript"]

        # Find DFG paths
        try:
            paths = list(nx.all_simple_paths(
                self.graph, source, sink, cutoff=15
            ))
        except nx.NodeNotFound:
            return CPGSlice(nodes=set(), source=source, sink=sink)

        # Filter to paths using DFG edges
        dfg_paths = []
        for path in paths[:5]:  # Limit to 5 paths
            is_dfg = all(
                self.graph.edges.get((path[i], path[i + 1]), {}).get("edge_type") in dfg_types
                for i in range(len(path) - 1)
            )
            if is_dfg:
                dfg_paths.append(path)

        slice_nodes = set()
        for path in dfg_paths:
            slice_nodes.update(path)

        # Add branch conditions
        for node in list(slice_nodes):
            for pred in self.predecessors(node, edge_types=["cfg_true", "cfg_false"]):
                if self.graph.nodes.get(pred, {}).get("node_type") == "if_statement":
                    slice_nodes.add(pred)

        # Add function context
        for node in list(slice_nodes):
            for pred in self.predecessors(node, edge_types=["ast_child"]):
                if self.graph.nodes.get(pred, {}).get("node_type") == "function_definition":
                    slice_nodes.add(pred)

        return CPGSlice(nodes=slice_nodes, source=source, sink=sink)

    def render_for_llm(self, slice_nodes: set[str]) -> str:
        """Render a set of nodes as LLM-friendly text."""
        lines = []
        for node_id in sorted(slice_nodes, key=lambda n: self.graph.nodes.get(n, {}).get("line", 0)):
            node = self.graph.nodes.get(node_id, {})
            role = node.get("role", "neutral")
            text = node.get("text", "")[:200]
            file_path = node.get("file_path", "")
            line = node.get("line", 0)

            prefix = ""
            if role == "source":
                prefix = "# [SOURCE] "
            elif role == "sink":
                prefix = "# [SINK] "
            elif role == "sanitizer":
                prefix = "# [SANITIZER] "
            elif role == "gate":
                prefix = "# [GATE] "

            if text:
                lines.append(f"{prefix}{file_path}:{line}: {text}")

        return "\n".join(lines)

    def node_count(self) -> int:
        return self.graph.number_of_nodes()

    def edge_count(self) -> int:
        return self.graph.number_of_edges()

    def serialize(self) -> dict:
        return nx.node_link_data(self.graph)

    @classmethod
    def deserialize(cls, data: dict) -> "CodePropertyGraph":
        cpg = cls()
        cpg.graph = nx.node_link_graph(data)
        # Rebuild role lists
        for node_id, attrs in cpg.graph.nodes(data=True):
            role = attrs.get("role", "neutral")
            if role == "source":
                cpg._sources.append(node_id)
            elif role == "sink":
                cpg._sinks.append(node_id)
            elif role == "sanitizer":
                cpg._sanitizers.append(node_id)
            elif role == "gate":
                cpg._gates.append(node_id)
        return cpg


@dataclass
class CPGSlice:
    nodes: set[str]
    source: str
    sink: str

    @property
    def node_count(self) -> int:
        return len(self.nodes)


class InfraGraph:
    """
    Infrastructure graph with three layers: network, IAM, data.
    """

    def __init__(self):
        self.network = nx.DiGraph()
        self.iam = nx.MultiDiGraph()
        self.data = nx.DiGraph()

    def add_resource(self, resource_id: str, resource_type: str, **attrs):
        self.network.add_node(resource_id, resource_type=resource_type, **attrs)

    def add_connection(self, source: str, target: str, relationship: str, **attrs):
        self.network.add_edge(source, target, relationship=relationship, **attrs)

    def add_permission(self, principal: str, resource: str, actions: list[str],
                       effect: str = "Allow", conditions: dict | None = None, **attrs):
        self.iam.add_edge(principal, resource, actions=actions, effect=effect,
                          conditions=conditions or {}, **attrs)

    def add_trust(self, source: str, target: str, **attrs):
        self.iam.add_edge(source, target, relationship="can_assume", **attrs)

    def get_publicly_reachable(self) -> list[str]:
        """Find all resources reachable from INTERNET node."""
        if "INTERNET" not in self.network:
            return []
        return list(nx.descendants(self.network, "INTERNET"))

    def get_blast_radius(self, node: str) -> set[str]:
        """Compute blast radius: network reachable ∩ IAM accessible."""
        net_reachable = set(nx.descendants(self.network, node))
        role = self.network.nodes.get(node, {}).get("iam_role")

        if not role:
            return net_reachable

        iam_accessible = set()
        for _, target, data in self.iam.out_edges(role, data=True):
            if data.get("effect") == "Allow":
                iam_accessible.add(target)

        return net_reachable & iam_accessible

    def find_attack_paths(self, targets: list[str]) -> list[list[str]]:
        """Find paths from INTERNET to high-value targets."""
        if "INTERNET" not in self.network:
            return []

        paths = []
        for target in targets:
            try:
                for path in nx.all_simple_paths(self.network, "INTERNET", target, cutoff=10):
                    paths.append(path)
            except nx.NodeNotFound:
                continue

        return paths

    def get_effective_permissions(self, role: str) -> set[str]:
        """Get all actions a role can perform (transitive via assume chains)."""
        all_actions = set()
        visited = set()
        queue = [role]

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            for _, target, data in self.iam.out_edges(current, data=True):
                if data.get("relationship") == "can_assume":
                    queue.append(target)
                elif data.get("effect") == "Allow":
                    all_actions.update(data.get("actions", []))

        return all_actions

    def serialize(self) -> dict:
        return {
            "network": nx.node_link_data(self.network),
            "iam": nx.node_link_data(self.iam),
            "data": nx.node_link_data(self.data),
        }

    @classmethod
    def deserialize(cls, data: dict) -> "InfraGraph":
        g = cls()
        g.network = nx.node_link_graph(data["network"])
        g.iam = nx.node_link_graph(data["iam"], multigraph=True)
        g.data = nx.node_link_graph(data["data"])
        return g
