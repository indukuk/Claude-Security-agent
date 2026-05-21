"""
Evidence Bundle — immutable, verifiable evidence for grounded debate.

Constructed BEFORE debate begins. Prosecution and defense can ONLY cite
items from this bundle. The judge discards any uncited claims.

This is the key innovation from AEGIS (Mar 2026): grounding debate in
verifiable code evidence prevents hallucinated cross-function dependencies
and reduces FPs by 54.4%.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class EvidenceItem:
    """A single piece of citable evidence."""
    id: int
    category: str  # "source" | "sink" | "path_node" | "branch" | "sanitizer" | "iam" | "network" | "z3_proof"
    file_path: str
    line: int
    text: str
    role: str = ""  # source | sink | sanitizer | gate | neutral
    metadata: dict = field(default_factory=dict)

    def cite(self) -> str:
        """Short citation for debate arguments."""
        return f"[E{self.id}] {self.file_path}:{self.line}"


@dataclass
class EvidenceBundle:
    """
    All verifiable evidence for a single finding.
    Immutable once constructed — debate participants cannot add new evidence.
    """
    finding_id: str
    finding_title: str
    items: list[EvidenceItem] = field(default_factory=list)

    # Structured summaries
    source_node: dict = field(default_factory=dict)
    sink_node: dict = field(default_factory=dict)
    taint_path: list[dict] = field(default_factory=list)
    sanitizers_on_path: list[dict] = field(default_factory=list)
    branch_conditions: list[dict] = field(default_factory=list)

    # Infrastructure evidence
    iam_permissions: list[dict] = field(default_factory=list)
    network_path: list[str] = field(default_factory=list)
    blast_radius: list[str] = field(default_factory=list)

    # Formal verification results
    z3_results: list[dict] = field(default_factory=list)

    def add_item(self, category: str, file_path: str, line: int, text: str,
                 role: str = "", **metadata) -> EvidenceItem:
        """Add an evidence item and return it."""
        item = EvidenceItem(
            id=len(self.items) + 1,
            category=category,
            file_path=file_path,
            line=line,
            text=text,
            role=role,
            metadata=metadata,
        )
        self.items.append(item)
        return item

    def render_for_debate(self) -> str:
        """Render all evidence as numbered items for debate participants."""
        lines = [f"# Evidence Bundle for: {self.finding_title}", ""]

        # Render taint path first (most important for debate)
        path_render = self.render_path_for_debate()
        if path_render:
            lines.append(path_render)

        # Render remaining evidence by category (skip path_node/branch_condition — already rendered above)
        by_category = {}
        rendered_categories = {"path_node", "branch_condition"} if path_render else set()
        for item in self.items:
            if item.category in rendered_categories:
                continue
            by_category.setdefault(item.category, []).append(item)

        for category, items in by_category.items():
            lines.append(f"## {category.upper()}")
            for item in items:
                role_tag = f" [{item.role}]" if item.role else ""
                lines.append(f"  [E{item.id}] {item.file_path}:{item.line}{role_tag}")
                lines.append(f"       {item.text[:200]}")
            lines.append("")

        if self.z3_results:
            lines.append("## Z3 FORMAL PROOFS")
            for result in self.z3_results:
                status = result.get("status", "unknown")
                prop = result.get("property", "")
                lines.append(f"  [{status.upper()}] {prop}")
            lines.append("")

        if self.iam_permissions:
            lines.append("## IAM PERMISSIONS")
            for perm in self.iam_permissions:
                lines.append(f"  {perm.get('principal', '')} → {perm.get('resource', '')}: {perm.get('actions', [])}")
            lines.append("")

        return "\n".join(lines)

    def render_path_for_debate(self) -> str:
        """
        Render taint paths as a numbered flow diagram for debate.
        Each step is separately citable via [E<id>].
        """
        path_items = [item for item in self.items if item.category == "path_node"]
        if not path_items:
            return ""

        lines = ["## TAINT PATH (source → sink)", ""]

        # Group path items by their path_index metadata (supports multiple paths)
        paths: dict[int, list[EvidenceItem]] = {}
        for item in path_items:
            path_idx = item.metadata.get("path_index", 0)
            paths.setdefault(path_idx, []).append(item)

        for path_idx, items in sorted(paths.items()):
            if len(paths) > 1:
                lines.append(f"### Path {path_idx + 1}")

            for i, item in enumerate(items):
                role_marker = ""
                if item.role == "source":
                    role_marker = " ← ATTACKER INPUT"
                elif item.role == "sink":
                    role_marker = " ← SENSITIVE OPERATION"
                elif item.role == "sanitizer":
                    role_marker = " ← SANITIZER"

                connector = "│" if i < len(items) - 1 else "└"
                lines.append(
                    f"  [E{item.id}] Step {item.metadata.get('step', i+1)}: "
                    f"{item.file_path}:{item.line}{role_marker}"
                )
                lines.append(f"  {connector}   {item.text[:150]}")

                if i < len(items) - 1:
                    edge_type = item.metadata.get("edge_to_next", "dfg")
                    lines.append(f"  │   ──({edge_type})──▶")

            lines.append("")

        # Add branch conditions if present
        branch_items = [item for item in self.items if item.category == "branch_condition"]
        if branch_items:
            lines.append("## BRANCH CONDITIONS ON PATH")
            for item in branch_items:
                lines.append(f"  [E{item.id}] {item.file_path}:{item.line}: {item.text[:150]}")
            lines.append("")

        return "\n".join(lines)

    def cited_lines(self) -> set[tuple[str, int]]:
        """All (file, line) pairs — verifiable ground truth."""
        return {(item.file_path, item.line) for item in self.items}

    def get_item(self, item_id: int) -> EvidenceItem | None:
        """Retrieve evidence by ID for citation verification."""
        for item in self.items:
            if item.id == item_id:
                return item
        return None
