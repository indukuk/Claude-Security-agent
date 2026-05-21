"""
V6 Evidence Package — assembles all Layer 0 outputs into the shared
context consumed by Layer 1 LLM agents.
"""
from __future__ import annotations

import json
from pathlib import Path
from dataclasses import dataclass, field

from src.common.graph import CodePropertyGraph, InfraGraph
from v4.analysis.absence_detector import AbsenceFinding
from v4.analysis.differential_analyzer import DifferentialFinding
from v4.analysis.chain_synthesizer import AttackChain
from v5.analysis.zero_trust_analyzer import ZeroTrustAssessment


@dataclass
class EvidencePackage:
    """Complete Layer 0 output — shared input for all Layer 1 agents."""

    # Code analysis
    cpg: CodePropertyGraph | None = None
    semgrep_findings: list[dict] = field(default_factory=list)
    evidence_walks: list[tuple[dict, object]] = field(default_factory=list)
    absence_findings: list[AbsenceFinding] = field(default_factory=list)
    differential_findings: list[DifferentialFinding] = field(default_factory=list)

    # Infrastructure + Zero Trust
    infra_graph: InfraGraph | None = None
    z3_findings: list[dict] = field(default_factory=list)
    iam_findings: list[dict] = field(default_factory=list)
    zero_trust: ZeroTrustAssessment | None = None
    synthetic_findings: list[dict] = field(default_factory=list)

    # Attack chains
    attack_chains: list[AttackChain] = field(default_factory=list)

    # Source code
    file_contents: dict[str, str] = field(default_factory=dict)
    handler_files: list[str] = field(default_factory=list)
    cdk_source: str = ""

    # Metadata
    repo_path: str = ""
    total_findings_layer0: int = 0

    def summary(self) -> dict:
        """Produce a summary dict of all Layer 0 outputs."""
        return {
            "repo": self.repo_path,
            "cpg_nodes": self.cpg.node_count() if self.cpg else 0,
            "cpg_edges": self.cpg.edge_count() if self.cpg else 0,
            "semgrep_findings": len(self.semgrep_findings),
            "evidence_walks": len(self.evidence_walks),
            "absence_findings": len(self.absence_findings),
            "differential_findings": len(self.differential_findings),
            "z3_findings": len(self.z3_findings),
            "iam_findings": len(self.iam_findings),
            "zero_trust_uncontained": self.zero_trust.summary.get("uncontained", 0) if self.zero_trust else 0,
            "lateral_paths": len(self.zero_trust.lateral_paths) if self.zero_trust else 0,
            "attack_chains": len(self.attack_chains),
            "synthetic_findings": len(self.synthetic_findings),
            "total_findings_layer0": self.total_findings_layer0,
        }

    def render_for_llm(self, max_chars: int = 250000) -> str:
        """Render the full evidence package as LLM-consumable text."""
        sections = []

        # Handler source code
        sections.append("## Handler Source Code\n")
        for fpath in self.handler_files[:12]:
            content = self.file_contents.get(fpath, "")
            if content:
                fname = Path(fpath).name
                sections.append(f"### {fname}\n```python\n{content[:10000]}\n```\n")

        # Semgrep findings (deduplicated by title)
        seen = set()
        sections.append("## Semgrep Findings\n")
        for f in self.semgrep_findings[:25]:
            if f["title"] not in seen:
                seen.add(f["title"])
                sections.append(f"- [{f['severity']}] {f['title']} — {Path(f.get('file_path','')).name}:{f.get('line')}")

        # Evidence walks
        sections.append("\n## Evidence Walks\n")
        for finding, walk in self.evidence_walks[:10]:
            sections.append(f"```\n{walk.render()}\n```\n")

        # Absence findings
        sections.append("## Missing Controls (Absence Detection)\n")
        for f in self.absence_findings:
            sections.append(f"- [{f.severity}] {f.title} ({Path(f.file_path).name}:{f.line})")

        # Differential findings
        sections.append("\n## Security Control Inconsistencies (Differential)\n")
        for f in self.differential_findings:
            sections.append(f"- [{f.severity}] {f.title}")

        # Z3 proofs
        sections.append("\n## Z3 Formal IAM Proofs\n")
        for f in self.z3_findings[:10]:
            sections.append(f"- [{f['severity']}] {f['title']}")
            if f.get("z3_proof"):
                sections.append(f"  Proof: {f['z3_proof'][:150]}")

        # Zero trust
        if self.zero_trust:
            sections.append("\n## Zero Trust Assessment\n")
            sections.append(f"Posture: {self.zero_trust.overall_posture}")
            sections.append(f"Uncontained: {self.zero_trust.summary.get('uncontained', 0)}")
            for rid, br in self.zero_trust.blast_radii.items():
                if br.containment_status == "UNCONTAINED":
                    sections.append(
                        f"- UNCONTAINED: {br.iam_role} | "
                        f"{'INTERNET' if br.is_internet_facing else 'internal'} | "
                        f"auth={br.auth_mechanism} | "
                        f"caps: tenants={br.can_access_all_tenants}, "
                        f"exfil={br.can_exfiltrate_data}, modify={br.can_modify_data}"
                    )

            sections.append("\n### Lateral Movement Paths\n")
            for lp in self.zero_trust.lateral_paths[:15]:
                sections.append(f"- {lp.source} → {lp.target} ({lp.mechanism})")

        # Attack chains
        sections.append("\n## Attack Chains\n")
        for chain in self.attack_chains[:5]:
            sections.append(chain.narrative)
            sections.append("")

        # CDK source
        if self.cdk_source:
            sections.append("\n## CDK Infrastructure Source\n")
            sections.append(f"```python\n{self.cdk_source[:15000]}\n```")

        full = "\n".join(sections)
        if len(full) > max_chars:
            full = full[:max_chars] + "\n\n... (truncated)"
        return full

    def get_known_finding_titles(self) -> list[str]:
        """Get all finding titles from Layer 0 — used as exclusion list for Layer 1."""
        titles = set()
        for f in self.semgrep_findings:
            titles.add(f.get("title", ""))
        for f in self.absence_findings:
            titles.add(f.title)
        for f in self.differential_findings:
            titles.add(f.title)
        for f in self.z3_findings:
            titles.add(f.get("title", ""))
        for f in self.synthetic_findings:
            titles.add(f.get("title", ""))
        return sorted(titles)

    def save(self, output_dir: Path):
        """Save evidence package to disk."""
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "summary.json").write_text(json.dumps(self.summary(), indent=2))
        (output_dir / "evidence_for_llm.md").write_text(self.render_for_llm())
        (output_dir / "known_findings.json").write_text(
            json.dumps(self.get_known_finding_titles(), indent=2)
        )
