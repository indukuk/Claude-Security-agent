"""
Evidence Package — assembles all Layer 0 deterministic outputs
into a structured context for LLM investigation agents.
"""
from __future__ import annotations

import json
from pathlib import Path
from dataclasses import dataclass, field

from src.common.graph import CodePropertyGraph, InfraGraph
from v4.analysis.evidence_walker import EvidenceWalk
from v4.analysis.absence_detector import AbsenceFinding
from v4.analysis.differential_analyzer import DifferentialFinding
from v4.analysis.chain_synthesizer import AttackChain
from v5.analysis.zero_trust_analyzer import ZeroTrustAssessment, BlastRadius
from v5.agents.base import AgentContext


@dataclass
class EvidencePackage:
    """All Layer 0 outputs collected for agent consumption."""
    # Target
    repo_path: str

    # Code analysis (V4)
    cpg: CodePropertyGraph
    semgrep_findings: list[dict] = field(default_factory=list)
    evidence_walks: list[tuple[dict, EvidenceWalk]] = field(default_factory=list)
    absence_findings: list[AbsenceFinding] = field(default_factory=list)
    differential_findings: list[DifferentialFinding] = field(default_factory=list)
    attack_chains: list[AttackChain] = field(default_factory=list)

    # Infrastructure (V5 Zero Trust)
    infra_graph: InfraGraph | None = None
    z3_findings: list[dict] = field(default_factory=list)
    zero_trust: ZeroTrustAssessment | None = None

    # Source code
    file_contents: dict[str, str] = field(default_factory=dict)
    handler_files: list[str] = field(default_factory=list)
    cdk_source: str = ""

    def to_agent_context(self) -> AgentContext:
        """Convert to AgentContext for agent consumption."""
        # CPG summary
        cpg_summary = (
            f"Nodes: {self.cpg.node_count()}, Edges: {self.cpg.edge_count()}\n"
            f"Sources: {len(self.cpg.sources)}, Sinks: {len(self.cpg.sinks)}, "
            f"Sanitizers: {len(self.cpg.sanitizers)}\n"
            f"Taint paths: {len(self.cpg.find_taint_paths(max_depth=10))}"
        )

        # Render evidence walks
        rendered_walks = []
        for finding_dict, walk in self.evidence_walks:
            rendered_walks.append(walk.render())

        # Absence findings as dicts
        absence_dicts = [
            {"title": f.title, "severity": f.severity, "file_path": f.file_path,
             "line": f.line, "missing_guard": f.missing_guard, "category": f.category}
            for f in self.absence_findings
        ]

        # Differential findings as dicts
        diff_dicts = [
            {"title": f.title, "severity": f.severity,
             "missing_guards": f.missing_guards,
             "weaker_path": f"{Path(f.weaker_path.entry_file).name}::{f.weaker_path.entry_handler}",
             "stronger_path": f"{Path(f.stronger_path.entry_file).name}::{f.stronger_path.entry_handler}"}
            for f in self.differential_findings
        ]

        # Attack chains rendered
        rendered_chains = [c.narrative for c in self.attack_chains]

        # Infra summary
        infra_summary = ""
        if self.infra_graph:
            infra_summary = (
                f"Network nodes: {self.infra_graph.network.number_of_nodes()}\n"
                f"IAM edges: {self.infra_graph.iam.number_of_edges()}\n"
                f"Publicly reachable: {len(self.infra_graph.get_publicly_reachable())}"
            )

        # Blast radii
        blast_dicts = []
        if self.zero_trust:
            for rid, br in self.zero_trust.blast_radii.items():
                blast_dicts.append({
                    "role": br.iam_role,
                    "score": f"{br.blast_radius_score:.0%}",
                    "status": br.containment_status,
                    "internet_facing": br.is_internet_facing,
                    "auth": br.auth_mechanism,
                    "can_all_tenants": br.can_access_all_tenants,
                    "can_exfil": br.can_exfiltrate_data,
                    "can_modify": br.can_modify_data,
                    "dangerous_actions": br.dangerous_actions[:5],
                })

        # Lateral paths
        lateral_dicts = []
        if self.zero_trust:
            for lp in self.zero_trust.lateral_paths[:20]:
                lateral_dicts.append({
                    "source": lp.source,
                    "target": lp.target,
                    "mechanism": lp.mechanism,
                    "description": lp.description[:150],
                })

        return AgentContext(
            file_contents=self.file_contents,
            handler_files=self.handler_files,
            cpg_summary=cpg_summary,
            semgrep_findings=self.semgrep_findings[:30],
            evidence_walks=rendered_walks,
            absence_findings=absence_dicts,
            differential_findings=diff_dicts,
            attack_chains=rendered_chains,
            infra_graph_summary=infra_summary,
            z3_proofs=self.z3_findings[:15],
            blast_radii=blast_dicts,
            lateral_paths=lateral_dicts,
            cdk_source=self.cdk_source,
        )
