"""
Attack Chain Synthesizer — composes individual findings into multi-step exploits.

Models each finding as a node with preconditions (what attacker needs) and
postconditions (what attacker gains). Builds a composition graph where edges
represent capability transfer. Finds maximal-impact paths.

Example chain:
1. Observer endpoint unauthenticated → gains: unauthenticated_access:/observer
2. Observer queries CloudWatch logs → gains: knows:session_id
3. Status endpoint has no ownership check → gains: read_access:any_tenant
Combined: CRITICAL (unauthenticated cross-tenant data access)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import IntEnum

import networkx as nx

logger = logging.getLogger(__name__)


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class FindingNode:
    """A finding annotated with attacker capabilities."""
    id: str
    title: str
    severity: str
    category: str
    file_path: str
    preconditions: set[str] = field(default_factory=set)
    postconditions: set[str] = field(default_factory=set)


@dataclass
class AttackChain:
    """A composed multi-step attack."""
    id: str
    title: str
    steps: list[FindingNode]
    capabilities_at_each_step: list[set[str]]
    composite_severity: str
    narrative: str
    individual_severities: list[str] = field(default_factory=list)


# Attacker's initial capabilities (what they have without exploiting anything)
ATTACKER_INITIAL = {
    "network_reach",
    "can_craft_http_request",
}

# High-value terminal capabilities (worth building chains toward)
HIGH_VALUE_CAPS = {
    "read_access:any_tenant",
    "write_access:any_tenant",
    "admin_role",
    "cross_tenant_data",
    "credential_theft",
    "code_execution",
}

# Category → (preconditions, postconditions) mapping
CAPABILITY_MAP = {
    "missing_auth": (
        {"network_reach"},
        {"unauthenticated_access"},
    ),
    "cross-tenant-access": (
        {"authenticated_access"},
        {"read_access:any_tenant", "cross_tenant_data"},
    ),
    "cross_tenant_access": (
        {"authenticated_access"},
        {"read_access:any_tenant", "cross_tenant_data"},
    ),
    "cross-session-access": (
        {"authenticated_access", "knows:session_id"},
        {"read_access:any_tenant"},
    ),
    "missing_ownership_check": (
        {"authenticated_access", "knows:session_id"},
        {"read_access:any_tenant"},
    ),
    "path-traversal": (
        {"authenticated_access"},
        {"write_access:any_tenant", "read_access:any_tenant"},
    ),
    "privilege-escalation": (
        {"authenticated_access"},
        {"admin_role"},
    ),
    "missing_role_check": (
        {"authenticated_access"},
        {"write_access:any_tenant"},
    ),
    "info-disclosure": (
        {"unauthenticated_access"},
        {"knows:session_id", "knows:tenant_id"},
    ),
    "dom-xss": (
        {"authenticated_access"},
        {"credential_theft"},
    ),
    "security_bypass": (
        {"authenticated_access"},
        {"bypass_controls", "write_access:any_tenant"},
    ),
    "missing_audit_log": (
        {"write_access:any_tenant"},
        {"undetectable_actions"},
    ),
    "missing_rate_limit": (
        {"network_reach"},
        {"brute_force_capability"},
    ),
    "deviant_behavior": (
        {"authenticated_access"},
        {"exploitable_inconsistency"},
    ),
    "self_signup_admin": (
        {"network_reach"},
        {"admin_role", "authenticated_access"},
    ),
    "api_key_exposed": (
        {"network_reach"},
        {"authenticated_access"},
    ),
    "cors_wildcard": (
        {"network_reach"},
        {"cross_origin_request"},
    ),
    "log_exposure": (
        {"unauthenticated_access"},
        {"knows:session_id", "knows:tenant_id", "knows:internal_state"},
    ),
    "missing_input_sanitization": (
        {"authenticated_access"},
        {"path_traversal_capability"},
    ),
}


class ChainSynthesizer:
    """Builds attack chains from a set of findings."""

    def __init__(self):
        self.finding_nodes: list[FindingNode] = []
        self.chain_graph = nx.DiGraph()

    def synthesize(self, findings: list[dict]) -> list[AttackChain]:
        """
        Synthesize attack chains from findings.

        Args:
            findings: list of dicts with keys: id, title, severity, category, file_path
        """
        # Step 1: Annotate findings with capabilities
        self.finding_nodes = [self._annotate_finding(f) for f in findings]

        # Step 2: Build composition graph
        self._build_composition_graph()

        # Step 3: Find chains (entry nodes → high-value terminals)
        chains = self._discover_chains()

        # Step 4: Rank and deduplicate
        chains = self._rank_and_dedup(chains)

        logger.info(f"Chain synthesizer: {len(chains)} chains from {len(self.finding_nodes)} findings")
        return chains

    def _annotate_finding(self, finding: dict) -> FindingNode:
        """Map a finding to preconditions and postconditions."""
        category = finding.get("category", "")
        title = finding.get("title", "")

        # Try exact category match
        pre, post = CAPABILITY_MAP.get(category, (set(), set()))

        # If no match, try partial matching
        if not pre and not post:
            for cat_key, (p, q) in CAPABILITY_MAP.items():
                if cat_key in category or cat_key in title:
                    pre, post = p, q
                    break

        # Special heuristics based on title keywords
        if "unauth" in title.lower() or "no auth" in title.lower():
            pre = {"network_reach"}
            post = post | {"unauthenticated_access"}

        if "observer" in finding.get("file_path", "").lower():
            if "unauthenticated_access" in post or not pre - ATTACKER_INITIAL:
                post = post | {"knows:session_id", "knows:tenant_id"}

        return FindingNode(
            id=finding.get("id", ""),
            title=finding.get("title", title),
            severity=finding.get("severity", "MEDIUM"),
            category=category,
            file_path=finding.get("file_path", ""),
            preconditions=set(pre),
            postconditions=set(post),
        )

    def _build_composition_graph(self):
        """Build directed graph where edges mean 'A enables B'."""
        self.chain_graph = nx.DiGraph()

        for node in self.finding_nodes:
            self.chain_graph.add_node(node.id, finding=node)

        for a in self.finding_nodes:
            for b in self.finding_nodes:
                if a is b:
                    continue
                # Edge A → B if A's postconditions satisfy any of B's preconditions
                if a.postconditions & b.preconditions:
                    overlap = a.postconditions & b.preconditions
                    self.chain_graph.add_edge(a.id, b.id, enables=overlap)

    def _discover_chains(self) -> list[AttackChain]:
        """Find all meaningful attack chains."""
        chains = []

        # Entry nodes: findings with preconditions satisfiable by attacker's initial caps
        entry_ids = [
            n.id for n in self.finding_nodes
            if n.preconditions <= ATTACKER_INITIAL
        ]

        # Terminal nodes: findings whose postconditions include high-value capabilities
        terminal_ids = [
            n.id for n in self.finding_nodes
            if n.postconditions & HIGH_VALUE_CAPS
        ]

        # Find all simple paths from entries to terminals (depth-bounded)
        for entry_id in entry_ids:
            for terminal_id in terminal_ids:
                if entry_id == terminal_id:
                    # Single-step chain (entry directly reaches high value)
                    node = self._get_node(entry_id)
                    if node and node.postconditions & HIGH_VALUE_CAPS:
                        chain = self._build_chain([entry_id])
                        if chain:
                            chains.append(chain)
                    continue

                try:
                    for path in nx.all_simple_paths(
                        self.chain_graph, entry_id, terminal_id, cutoff=4
                    ):
                        if len(path) >= 2:
                            chain = self._build_chain(path)
                            if chain:
                                chains.append(chain)
                except (nx.NodeNotFound, nx.NetworkXError):
                    continue

        return chains

    def _build_chain(self, path: list[str]) -> AttackChain | None:
        """Build an AttackChain from a path of finding IDs."""
        steps = []
        caps_at_step = []
        cumulative_caps = set(ATTACKER_INITIAL)

        for node_id in path:
            node = self._get_node(node_id)
            if not node:
                return None
            steps.append(node)
            cumulative_caps = cumulative_caps | node.postconditions
            caps_at_step.append(set(cumulative_caps))

        # Composite severity
        composite = self._compute_composite_severity(steps, cumulative_caps)

        # Narrative
        narrative = self._generate_narrative(steps, caps_at_step, composite)

        title = self._generate_chain_title(steps, cumulative_caps)

        return AttackChain(
            id=f"chain-{'-'.join(s.id[:8] for s in steps)}",
            title=title,
            steps=steps,
            capabilities_at_each_step=caps_at_step,
            composite_severity=composite,
            narrative=narrative,
            individual_severities=[s.severity for s in steps],
        )

    def _compute_composite_severity(self, steps: list[FindingNode],
                                     final_caps: set[str]) -> str:
        """Compute the composite severity of a chain."""
        max_individual = max(
            Severity[s.severity] for s in steps
        )

        # Escalation rules
        if final_caps & {"read_access:any_tenant", "write_access:any_tenant", "cross_tenant_data"}:
            return "CRITICAL"
        if "admin_role" in final_caps and len(steps) >= 2:
            return "CRITICAL"
        if len(steps) >= 3 and max_individual >= Severity.MEDIUM:
            return "HIGH"
        if len(steps) >= 2 and max_individual >= Severity.HIGH:
            return "HIGH"
        return max_individual.name

    def _generate_chain_title(self, steps: list[FindingNode], final_caps: set[str]) -> str:
        """Generate a descriptive title for the chain."""
        if "cross_tenant_data" in final_caps or "read_access:any_tenant" in final_caps:
            if any(s.preconditions <= ATTACKER_INITIAL and "unauthenticated_access" in s.postconditions
                   for s in steps):
                return "Unauthenticated Cross-Tenant Data Exfiltration"
            return "Cross-Tenant Data Access Chain"

        if "admin_role" in final_caps:
            return "Privilege Escalation to Admin"

        if "credential_theft" in final_caps:
            return "Credential Theft via Multi-Step Attack"

        if "write_access:any_tenant" in final_caps:
            return "Unauthorized Cross-Tenant Write Access"

        return f"Attack Chain ({len(steps)} steps)"

    def _generate_narrative(self, steps: list[FindingNode],
                            caps_at_step: list[set[str]], composite: str) -> str:
        """Generate a natural-language attack narrative."""
        lines = []
        lines.append(f"**Attack Chain** (Composite: {composite})")
        lines.append("")
        lines.append("Steps:")

        for i, (step, caps) in enumerate(zip(steps, caps_at_step)):
            new_caps = caps - (caps_at_step[i-1] if i > 0 else ATTACKER_INITIAL)
            new_caps_str = ", ".join(sorted(new_caps)) if new_caps else "enables next step"
            lines.append(
                f"  {i+1}. [{step.severity}] {step.title} "
                f"→ gains: {new_caps_str}"
            )

        lines.append("")
        final_caps = caps_at_step[-1] if caps_at_step else set()
        high_value_reached = final_caps & HIGH_VALUE_CAPS
        if high_value_reached:
            lines.append(f"Combined impact: Attacker achieves {', '.join(sorted(high_value_reached))}")

        sev_list = [s.severity for s in steps]
        lines.append(f"Individual: {'+'.join(sev_list)} → Combined: {composite}")

        return "\n".join(lines)

    def _rank_and_dedup(self, chains: list[AttackChain]) -> list[AttackChain]:
        """Rank chains by severity and remove subsumed/duplicate chains."""
        # Sort by composite severity (descending) then length (longer = more interesting)
        sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        chains.sort(key=lambda c: (sev_order.get(c.composite_severity, 0), len(c.steps)), reverse=True)

        # Deduplicate by chain "shape" (sequence of categories, not specific finding IDs)
        kept = []
        seen_shapes = set()
        seen_step_sets = []
        for chain in chains:
            # Shape = tuple of step categories in order
            shape = tuple(s.category for s in chain.steps)
            if shape in seen_shapes:
                continue
            seen_shapes.add(shape)

            # Also remove sub-paths
            step_ids = frozenset(s.id for s in chain.steps)
            is_subsumed = any(step_ids < existing for existing in seen_step_sets)
            if not is_subsumed:
                kept.append(chain)
                seen_step_sets.append(step_ids)

        return kept[:10]  # Cap at 10 unique chains

    def _get_node(self, node_id: str) -> FindingNode | None:
        for n in self.finding_nodes:
            if n.id == node_id:
                return n
        return None
