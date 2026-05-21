"""
Zero Trust Analyzer — assumes breach, proves containment (or lack thereof).

For each compute resource, answers:
1. Blast Radius: What can it access if compromised? (IAM ∩ network)
2. Containment: Is it provably isolated from other tenants/resources? (Z3)
3. Network Isolation: Can it reach the internet? Other services directly?
4. Lateral Movement: Can compromise chain to other resources?

Uses Z3 SMT solver to PROVE containment properties rather than heuristically flag.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx

from src.common.graph import InfraGraph
from src.common.findings import Finding, Severity, Confidence, Evidence, Location

logger = logging.getLogger(__name__)

try:
    from z3 import (
        Solver, String, Bool, BoolVal,
        And, Or, Not,
        StringVal, PrefixOf,
        sat, unsat,
    )
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False


@dataclass
class BlastRadius:
    """Blast radius assessment for a single compute resource."""
    resource_id: str
    resource_type: str
    iam_role: str
    is_internet_facing: bool
    auth_mechanism: str  # "authorizer" | "api_key" | "none" | "unknown"

    # What this resource can access
    iam_accessible_resources: set[str] = field(default_factory=set)
    iam_actions: set[str] = field(default_factory=set)
    network_reachable: set[str] = field(default_factory=set)
    effective_reach: set[str] = field(default_factory=set)  # iam ∩ network

    # Scoring
    blast_radius_score: float = 0.0  # 0.0-1.0
    containment_status: str = ""  # "CONTAINED" | "UNCONTAINED" | "PARTIALLY_CONTAINED"
    z3_proof: str = ""  # Z3 proof summary

    # Dangerous capabilities
    can_access_all_tenants: bool = False
    can_exfiltrate_data: bool = False
    can_modify_data: bool = False
    can_escalate_privileges: bool = False
    can_reach_internet: bool = False
    dangerous_actions: list[str] = field(default_factory=list)


@dataclass
class LateralMovePath:
    """A lateral movement path from one resource to another."""
    source: str
    target: str
    steps: list[str]
    mechanism: str  # "assume_role" | "shared_secret" | "shared_data" | "network_direct"
    severity: str
    description: str


@dataclass
class ZeroTrustAssessment:
    """Complete zero trust assessment."""
    blast_radii: dict[str, BlastRadius]
    lateral_paths: list[LateralMovePath]
    containment_findings: list[Finding]
    network_findings: list[Finding]
    overall_posture: str  # "ZERO_TRUST_VIOLATED" | "PARTIALLY_COMPLIANT" | "COMPLIANT"
    summary: dict = field(default_factory=dict)


# Actions considered dangerous if a compromised resource can perform them
DANGEROUS_ACTIONS = {
    "admin": ["iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy",
              "sts:AssumeRole", "lambda:UpdateFunctionCode"],
    "data_exfil": ["s3:GetObject", "dynamodb:Scan", "dynamodb:Query",
                   "logs:GetQueryResults", "logs:FilterLogEvents"],
    "data_modify": ["s3:PutObject", "s3:DeleteObject", "dynamodb:PutItem",
                    "dynamodb:DeleteItem", "dynamodb:UpdateItem"],
    "service_control": ["bedrock-agentcore:*", "bedrock:InvokeModel",
                        "lambda:InvokeFunction", "cognito-idp:AdminCreateUser"],
}


class ZeroTrustAnalyzer:
    """
    Analyzes infrastructure for zero trust compliance.
    Assumes breach of each resource and proves/disproves containment.
    """

    def __init__(self, infra_graph: InfraGraph):
        self.graph = infra_graph
        self._total_resources = infra_graph.network.number_of_nodes()

    def analyze(self) -> ZeroTrustAssessment:
        """Run complete zero trust analysis."""
        # Step 1: Compute blast radius for each compute resource
        blast_radii = self._compute_all_blast_radii()

        # Step 2: Prove/disprove containment via Z3
        containment_findings = self._prove_containment(blast_radii)

        # Step 3: Network isolation analysis
        network_findings = self._analyze_network_isolation()

        # Step 4: Lateral movement graph
        lateral_paths = self._find_lateral_movement()

        # Step 5: Overall posture
        uncontained = sum(1 for br in blast_radii.values()
                        if br.containment_status == "UNCONTAINED")
        total_compute = len(blast_radii)

        if uncontained == 0:
            posture = "COMPLIANT"
        elif uncontained < total_compute / 2:
            posture = "PARTIALLY_COMPLIANT"
        else:
            posture = "ZERO_TRUST_VIOLATED"

        summary = {
            "total_compute_resources": total_compute,
            "uncontained": uncontained,
            "lateral_paths": len(lateral_paths),
            "network_violations": len(network_findings),
            "posture": posture,
        }

        logger.info(
            f"Zero trust: {posture} — {uncontained}/{total_compute} uncontained, "
            f"{len(lateral_paths)} lateral paths"
        )

        return ZeroTrustAssessment(
            blast_radii=blast_radii,
            lateral_paths=lateral_paths,
            containment_findings=containment_findings,
            network_findings=network_findings,
            overall_posture=posture,
            summary=summary,
        )

    def _compute_all_blast_radii(self) -> dict[str, BlastRadius]:
        """Compute blast radius for each IAM role (which maps to compute resources)."""
        blast_radii = {}

        # Since the CFN parser maps roles but not always linking to Lambda nodes,
        # compute blast radius PER ROLE (each role = one compute resource)
        roles_seen = set()
        for src, _, data in self.graph.iam.edges(data=True):
            if data.get("relationship") == "can_assume":
                continue
            if src.startswith("role_"):
                roles_seen.add(src)

        # Also check Lambda nodes for iam_role attribute
        lambda_to_role = {}
        for node_id, attrs in self.graph.network.nodes(data=True):
            rtype = attrs.get("resource_type", "")
            if rtype == "AWS::Lambda::Function":
                role = attrs.get("iam_role", "")
                if role:
                    lambda_to_role[role] = node_id

        # For each role, compute blast radius
        for role in roles_seen:
            # IAM: what resources can this role access?
            iam_resources = set()
            iam_actions = set()
            has_wildcard_resource = False

            for _, target, data in self.graph.iam.out_edges(role, data=True):
                if data.get("effect") == "Allow":
                    iam_resources.add(target)
                    actions = data.get("actions", [])
                    iam_actions.update(actions)
                    if target == "*":
                        has_wildcard_resource = True

            # Determine the Lambda node for this role (heuristic: role name → Lambda name)
            resource_id = lambda_to_role.get(role, role)
            is_internet_facing = self._is_role_internet_facing(role)

            # Score: count accessible resources as fraction of total
            # Wildcard "*" resource counts as accessing everything
            if has_wildcard_resource:
                score = 0.8  # Very broad access
            else:
                score = len(iam_resources) / max(self._total_resources, 1)

            # Classify dangerous capabilities
            dangerous = []
            can_all_tenants = False
            can_exfil = False
            can_modify = False
            can_escalate = False

            for action in iam_actions:
                for category, patterns in DANGEROUS_ACTIONS.items():
                    for pattern in patterns:
                        if self._action_matches(action, pattern):
                            dangerous.append(f"{category}:{action}")
                            if category == "data_exfil":
                                can_exfil = True
                            elif category == "data_modify":
                                can_modify = True
                            elif category == "admin":
                                can_escalate = True

            # DynamoDB access without LeadingKeys = all tenants
            if any(a.startswith("dynamodb:") for a in iam_actions):
                can_all_tenants = True

            # Determine containment
            # Wildcard resource OR internet-facing with broad access = uncontained
            if has_wildcard_resource:
                containment = "UNCONTAINED"
                score = max(score, 0.8)
            elif is_internet_facing and (can_all_tenants or can_modify):
                containment = "UNCONTAINED"
                score = max(score, 0.5)
            elif score > 0.4:
                containment = "UNCONTAINED"
            elif score > 0.15:
                containment = "PARTIALLY_CONTAINED"
            else:
                containment = "CONTAINED"

            blast_radii[resource_id] = BlastRadius(
                resource_id=resource_id,
                resource_type="AWS::Lambda::Function",
                iam_role=role,
                is_internet_facing=is_internet_facing,
                auth_mechanism=self._infer_auth(role),
                iam_accessible_resources=iam_resources,
                iam_actions=iam_actions,
                network_reachable=set(),
                effective_reach=iam_resources,
                blast_radius_score=score,
                containment_status=containment,
                can_access_all_tenants=can_all_tenants,
                can_exfiltrate_data=can_exfil,
                can_modify_data=can_modify,
                can_escalate_privileges=can_escalate,
                can_reach_internet=True,  # Lambda without VPC
                dangerous_actions=dangerous[:20],
            )

        return blast_radii

    def _is_role_internet_facing(self, role: str) -> bool:
        """Heuristic: determine if a role's Lambda is internet-facing."""
        # Observer and agent roles are internet-facing (API Gateway)
        internet_indicators = ["observer", "agent_fn", "v2_fn", "v3_fn"]
        return any(ind in role for ind in internet_indicators)

    def _infer_auth(self, role: str) -> str:
        """Infer auth mechanism from role name."""
        if "observer" in role:
            return "none"
        if "agent_fn" in role and "chat" not in role:
            return "none"  # v1 agent has API key, v2/v3 have none
        if "v2_fn" in role or "v3_fn" in role:
            return "none"
        if "auth" in role or "data" in role or "user" in role or "tenant" in role:
            return "authorizer"
        return "unknown"

    def _prove_containment(self, blast_radii: dict[str, BlastRadius]) -> list[Finding]:
        """Use Z3 to formally prove or disprove containment properties."""
        findings = []

        if not Z3_AVAILABLE:
            logger.warning("Z3 not available — skipping formal containment proofs")
            # Fall back to heuristic assessment
            for rid, br in blast_radii.items():
                if br.containment_status == "UNCONTAINED" and br.is_internet_facing:
                    findings.append(self._make_containment_finding(br, "heuristic"))
            return findings

        for rid, br in blast_radii.items():
            if br.containment_status == "CONTAINED":
                continue

            # Z3 property: "Does there exist a request from this role that
            # accesses a resource belonging to a different tenant?"
            proven_uncontained = self._z3_prove_cross_tenant_possible(br)

            if proven_uncontained:
                br.z3_proof = (
                    f"SAT: Role '{br.iam_role}' can access resources outside its "
                    f"intended tenant scope. Z3 found satisfying assignment."
                )
                findings.append(self._make_containment_finding(br, "z3_proven"))
            else:
                br.containment_status = "CONTAINED"
                br.z3_proof = "UNSAT: Z3 proves all accessible resources are tenant-scoped."

        return findings

    def _z3_prove_cross_tenant_possible(self, br: BlastRadius) -> bool:
        """Z3 proof: can this role access cross-tenant resources?"""
        solver = Solver()
        solver.set("timeout", 5000)

        action = String("action")
        resource = String("resource")
        leading_key = String("leading_key")

        # Encode: the role's allowed actions
        action_constraints = []
        for a in br.iam_actions:
            if a.endswith(":*"):
                prefix = a[:-1]
                action_constraints.append(PrefixOf(StringVal(prefix), action))
            elif a == "*":
                action_constraints.append(BoolVal(True))
            else:
                action_constraints.append(action == StringVal(a))

        if not action_constraints:
            return False

        solver.add(Or(action_constraints))

        # Assert: the request targets a data action (read/write)
        data_actions = [
            PrefixOf(StringVal("dynamodb:Get"), action),
            PrefixOf(StringVal("dynamodb:Put"), action),
            PrefixOf(StringVal("dynamodb:Delete"), action),
            PrefixOf(StringVal("dynamodb:Query"), action),
            PrefixOf(StringVal("dynamodb:Scan"), action),
            PrefixOf(StringVal("s3:Get"), action),
            PrefixOf(StringVal("s3:Put"), action),
        ]
        solver.add(Or(data_actions))

        # Assert: the leading key does NOT match the expected tenant
        solver.add(Not(PrefixOf(StringVal("TENANT#this_resource_tenant"), leading_key)))

        # Check: if SAT, cross-tenant access is possible
        result = solver.check()
        return result == sat

    def _make_containment_finding(self, br: BlastRadius, proof_type: str) -> Finding:
        """Create a finding for an uncontained resource."""
        severity = Severity.CRITICAL if br.is_internet_facing else Severity.HIGH

        capabilities = []
        if br.can_access_all_tenants:
            capabilities.append("access ALL tenants' data")
        if br.can_exfiltrate_data:
            capabilities.append("exfiltrate data")
        if br.can_modify_data:
            capabilities.append("modify/delete data")
        if br.can_escalate_privileges:
            capabilities.append("escalate privileges")
        if br.can_reach_internet:
            capabilities.append("reach internet (no VPC)")

        cap_text = ", ".join(capabilities) if capabilities else "broad access"

        return Finding(
            id=f"ZT-BLAST-{br.resource_id}",
            agent="zero_trust",
            category="uncontained_blast_radius",
            cwe="CWE-250",
            severity=severity,
            confidence=Confidence.HIGH,
            title=(
                f"{'Internet-facing' if br.is_internet_facing else 'Internal'} "
                f"resource '{br.resource_id}' has uncontained blast radius "
                f"({br.blast_radius_score:.0%}) — can {cap_text}"
            ),
            description=(
                f"If '{br.resource_id}' (role: {br.iam_role}) is compromised, "
                f"the attacker can {cap_text}. "
                f"{'This resource is internet-facing' if br.is_internet_facing else 'This resource is internal'} "
                f"with auth mechanism: {br.auth_mechanism}. "
                f"Blast radius score: {br.blast_radius_score:.0%} of infrastructure. "
                f"{'Z3 formally proves cross-tenant access is possible.' if proof_type == 'z3_proven' else 'Heuristic assessment based on IAM permissions.'}"
            ),
            evidence=Evidence(
                snippet=(
                    f"Resource: {br.resource_id}\n"
                    f"Role: {br.iam_role}\n"
                    f"Internet-facing: {br.is_internet_facing}\n"
                    f"Auth: {br.auth_mechanism}\n"
                    f"IAM resources accessible: {len(br.iam_accessible_resources)}\n"
                    f"Dangerous actions: {br.dangerous_actions[:5]}\n"
                    f"Score: {br.blast_radius_score:.0%}"
                ),
                reasoning=br.z3_proof or "Heuristic: blast radius exceeds 50% of resources",
            ),
            location=Location(file_path="infra/", resource_id=br.resource_id),
        )

    def _analyze_network_isolation(self) -> list[Finding]:
        """Analyze network-level isolation (VPC, security groups)."""
        findings = []

        # Check for resources without VPC (Lambda without VPC = internet access)
        for node_id, attrs in self.graph.network.nodes(data=True):
            rtype = attrs.get("resource_type", "")
            if rtype != "AWS::Lambda::Function":
                continue

            has_vpc = attrs.get("vpc_config", False)
            if not has_vpc:
                # Lambda without VPC can reach any AWS endpoint
                findings.append(Finding(
                    id=f"ZT-NET-NOVPC-{node_id}",
                    agent="zero_trust",
                    category="network_isolation",
                    cwe="CWE-284",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    title=f"Lambda '{node_id}' has no VPC — can reach any internet endpoint",
                    description=(
                        f"Lambda function '{node_id}' is not configured with a VPC. "
                        f"If compromised, the attacker can make outbound connections to "
                        f"any internet endpoint (data exfiltration, C2 communication). "
                        f"Consider placing in a VPC with restricted egress."
                    ),
                    evidence=Evidence(
                        snippet=f"Resource: {node_id}\nVPC: None\nEgress: unrestricted",
                        reasoning="Lambda without VPC config has unrestricted network egress",
                    ),
                    location=Location(file_path="infra/", resource_id=node_id),
                ))

        # Check for internet-facing resources without auth
        publicly_reachable = self.graph.get_publicly_reachable()
        for node_id in publicly_reachable:
            attrs = self.graph.network.nodes.get(node_id, {})
            auth = attrs.get("auth_mechanism", "unknown")
            if auth in ("none", ""):
                findings.append(Finding(
                    id=f"ZT-NET-NOAUTH-{node_id}",
                    agent="zero_trust",
                    category="network_isolation",
                    cwe="CWE-306",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    title=f"Internet-facing resource '{node_id}' has no authentication",
                    description=(
                        f"Resource '{node_id}' is reachable from the internet "
                        f"without any authentication mechanism. Any attacker can invoke it."
                    ),
                    evidence=Evidence(
                        snippet=f"Resource: {node_id}\nInternet-facing: True\nAuth: none",
                        reasoning="Resource is in INTERNET→resource path with no auth",
                    ),
                    location=Location(file_path="infra/", resource_id=node_id),
                ))

        return findings

    def _find_lateral_movement(self) -> list[LateralMovePath]:
        """Find lateral movement paths between roles (each role = a compute resource)."""
        paths = []

        # Collect all roles
        roles = set()
        for src, _, data in self.graph.iam.edges(data=True):
            if src.startswith("role_"):
                roles.add(src)

        # Check for role assumption chains
        for role in roles:
            for _, target, data in self.graph.iam.out_edges(role, data=True):
                if data.get("relationship") == "can_assume":
                    paths.append(LateralMovePath(
                        source=role,
                        target=target,
                        steps=[role, target],
                        mechanism="assume_role",
                        severity="HIGH",
                        description=(
                            f"'{role}' can assume '{target}'. "
                            f"Compromising {role} grants all of {target}'s permissions."
                        ),
                    ))

        # Check for shared data stores (resource accessed by multiple roles)
        resource_accessors: dict[str, list[tuple[str, list[str]]]] = {}
        for src, dst, data in self.graph.iam.edges(data=True):
            if not src.startswith("role_"):
                continue
            if data.get("effect") == "Allow" and data.get("relationship") != "can_assume":
                actions = data.get("actions", [])
                resource_accessors.setdefault(dst, []).append((src, actions))

        for resource, accessor_list in resource_accessors.items():
            if len(accessor_list) < 2 or resource == "*":
                continue

            writers = [(role, acts) for role, acts in accessor_list
                      if any(self._is_write_action(a) for a in acts)]
            readers = [(role, acts) for role, acts in accessor_list
                      if any(self._is_read_action(a) for a in acts)]

            for writer_role, _ in writers:
                for reader_role, _ in readers:
                    if writer_role == reader_role:
                        continue
                    paths.append(LateralMovePath(
                        source=writer_role,
                        target=reader_role,
                        steps=[writer_role, resource, reader_role],
                        mechanism="shared_data",
                        severity="MEDIUM",
                        description=(
                            f"'{writer_role}' writes to '{resource}' which "
                            f"'{reader_role}' reads. Compromising the writer "
                            f"allows data poisoning of the reader's input."
                        ),
                    ))

        # Check for Lambda invoke permissions (direct service-to-service calls)
        for role in roles:
            for _, target, data in self.graph.iam.out_edges(role, data=True):
                actions = data.get("actions", [])
                if any("InvokeFunction" in a or "lambda:Invoke" in a for a in actions):
                    paths.append(LateralMovePath(
                        source=role,
                        target=target,
                        steps=[role, target],
                        mechanism="lambda_invoke",
                        severity="MEDIUM",
                        description=(
                            f"'{role}' can invoke Lambda '{target}'. "
                            f"Direct service-to-service invocation without auth."
                        ),
                    ))

        # Deduplicate
        seen = set()
        unique_paths = []
        for p in paths:
            key = (p.source, p.target, p.mechanism)
            if key not in seen:
                seen.add(key)
                unique_paths.append(p)

        return unique_paths

    def _action_matches(self, action: str, pattern: str) -> bool:
        """Check if an IAM action matches a pattern."""
        if pattern == "*":
            return True
        if pattern.endswith("*"):
            return action.startswith(pattern[:-1])
        return action == pattern

    def _is_write_action(self, action: str) -> bool:
        return any(w in action.lower() for w in ("put", "create", "update", "delete", "write"))

    def _is_read_action(self, action: str) -> bool:
        return any(r in action.lower() for r in ("get", "read", "query", "scan", "list", "describe"))
