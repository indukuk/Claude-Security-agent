"""
IAM permission analysis — escalation detection and blast radius computation.
"""
from __future__ import annotations


import logging

from src.common.findings import Finding, Severity, Confidence, Evidence, Location
from src.common.graph import InfraGraph
from src.skills.infra_security_skills import IAM_ESCALATION_CHECKS, BLAST_RADIUS_MAP

logger = logging.getLogger(__name__)


class IAMAnalyzer:
    """Analyze IAM permissions for escalation paths and over-permission."""

    def analyze(self, graph: InfraGraph) -> list[Finding]:
        findings = []
        findings.extend(self._check_escalation_primitives(graph))
        findings.extend(self._check_blast_radius(graph))
        return findings

    def _check_escalation_primitives(self, graph: InfraGraph) -> list[Finding]:
        """Check if any role has known escalation-capable permissions."""
        findings = []

        for node_id in graph.iam.nodes():
            if not node_id.startswith("role_"):
                continue

            effective_perms = graph.get_effective_permissions(node_id)

            for check in IAM_ESCALATION_CHECKS:
                required_perms = set(check.get("permissions_required", []))
                if required_perms and required_perms.issubset(effective_perms):
                    findings.append(Finding(
                        id=f"IAM-ESC-{len(findings)}",
                        agent="infrastructure",
                        category="privilege_escalation",
                        cwe="CWE-269",
                        severity=Severity[check["severity"]],
                        confidence=Confidence.HIGH,
                        title=check["title"],
                        description=check["description"],
                        evidence=Evidence(
                            snippet=f"Role: {node_id}\nPermissions: {', '.join(required_perms)}",
                        ),
                        location=Location(file_path="infra/", resource_id=node_id),
                        attack_path=[node_id, check["title"], "elevated_access"],
                    ))

        return findings

    def _check_blast_radius(self, graph: InfraGraph) -> list[Finding]:
        """Compute blast radius for publicly reachable compute resources."""
        findings = []

        public_resources = graph.get_publicly_reachable()
        compute_nodes = [
            n for n in public_resources
            if graph.network.nodes.get(n, {}).get("is_compute")
        ]

        for compute in compute_nodes:
            blast = graph.get_blast_radius(compute)
            if len(blast) > 5:  # High blast radius threshold
                findings.append(Finding(
                    id=f"IAM-BLAST-{len(findings)}",
                    agent="infrastructure",
                    category="blast_radius",
                    cwe="CWE-250",
                    severity=Severity.HIGH if len(blast) > 10 else Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    title=f"High blast radius: '{compute}' can reach {len(blast)} resources",
                    description=(
                        f"If publicly-reachable compute resource '{compute}' is compromised, "
                        f"attacker can access {len(blast)} resources: {', '.join(list(blast)[:5])}..."
                    ),
                    evidence=Evidence(
                        snippet=f"Resource: {compute}\nBlast radius: {len(blast)} resources\n"
                               f"Includes: {', '.join(list(blast)[:10])}",
                    ),
                    location=Location(file_path="infra/", resource_id=compute),
                    blast_radius=list(blast),
                ))

        return findings
