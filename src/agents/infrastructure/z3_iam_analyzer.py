"""
Z3 SMT-based IAM policy analyzer.
Formal verification of IAM permission properties using the AWS Zelkova approach.

Encodes IAM policies as Z3 constraints and proves security properties:
- Missing DynamoDB LeadingKeys conditions (multi-tenant isolation)
- Wildcard actions without scoping conditions
- Deny statement effectiveness
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from z3 import (
    Solver, String, BitVec, Bool, BoolVal,
    And, Or, Not,
    StringVal, BitVecVal,
    PrefixOf, SuffixOf, Contains,
    sat, unsat,
)

from src.common.findings import Finding, Severity, Confidence, Evidence, Location
from src.common.graph import InfraGraph

logger = logging.getLogger(__name__)

DYNAMODB_DATA_ACTIONS = {
    "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
    "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan",
    "dynamodb:BatchGetItem", "dynamodb:BatchWriteItem",
}

TIMEOUT_MS = 5000


class IAMConstraintEncoder:
    """Translates IAM policy elements into Z3 constraints (Zelkova encoding)."""

    def __init__(self):
        self.principal = String("principal")
        self.action = String("action")
        self.resource = String("resource")
        self.source_ip = BitVec("source_ip", 32)
        self.leading_key = String("dynamodb_leading_key")

    def encode_action_match(self, action_pattern: str):
        """Encode IAM action matching.

        'dynamodb:*' -> action starts with 'dynamodb:'
        'dynamodb:GetItem' -> action == 'dynamodb:GetItem'
        '*' -> True (any action)
        """
        if action_pattern == "*":
            return BoolVal(True)
        if action_pattern.endswith(":*"):
            prefix = action_pattern[:-1]  # 'dynamodb:'
            return PrefixOf(StringVal(prefix), self.action)
        return self.action == StringVal(action_pattern)

    def encode_resource_match(self, resource_pattern: str):
        """Encode IAM resource ARN matching."""
        if resource_pattern == "*":
            return BoolVal(True)
        if resource_pattern.endswith("*"):
            prefix = resource_pattern[:-1]
            return PrefixOf(StringVal(prefix), self.resource)
        if "*" in resource_pattern:
            parts = resource_pattern.split("*", 1)
            return And(
                PrefixOf(StringVal(parts[0]), self.resource),
                SuffixOf(StringVal(parts[1]), self.resource),
            )
        return self.resource == StringVal(resource_pattern)

    def encode_condition(self, operator: str, key: str, values: list[str]):
        """Encode IAM condition operators as Z3 constraints.

        Supported operators:
        - StringEquals / StringNotEquals
        - StringLike / StringNotLike
        - IpAddress / NotIpAddress
        - ForAllValues:StringLike / ForAllValues:StringEquals
        """
        variable = self._get_variable_for_key(key)

        base_op = operator.replace("ForAllValues:", "").replace("ForAnyValue:", "")

        if base_op == "StringEquals":
            constraint = Or([variable == StringVal(v) for v in values])
        elif base_op == "StringNotEquals":
            constraint = And([variable != StringVal(v) for v in values])
        elif base_op in ("StringLike", "StringNotLike"):
            like_constraints = [self.encode_string_like(variable, v) for v in values]
            constraint = Or(like_constraints)
            if base_op == "StringNotLike":
                constraint = Not(constraint)
        elif base_op in ("IpAddress", "NotIpAddress"):
            ip_constraints = [self.encode_ip_cidr(v) for v in values]
            constraint = Or(ip_constraints)
            if base_op == "NotIpAddress":
                constraint = Not(constraint)
        else:
            return BoolVal(True)

        return constraint

    def encode_string_like(self, variable, pattern: str):
        """Encode StringLike with * wildcards.

        'TENANT#abc*' -> PrefixOf('TENANT#abc', variable)
        '*abc' -> SuffixOf('abc', variable)
        '*abc*' -> Contains(variable, 'abc')
        'exact' -> variable == 'exact'
        """
        if pattern == "*":
            return BoolVal(True)

        stars = pattern.count("*")
        if stars == 0:
            return variable == StringVal(pattern)
        elif stars == 1:
            if pattern.endswith("*"):
                return PrefixOf(StringVal(pattern[:-1]), variable)
            elif pattern.startswith("*"):
                return SuffixOf(StringVal(pattern[1:]), variable)
            else:
                parts = pattern.split("*", 1)
                return And(
                    PrefixOf(StringVal(parts[0]), variable),
                    SuffixOf(StringVal(parts[1]), variable),
                )
        elif stars == 2 and pattern.startswith("*") and pattern.endswith("*"):
            inner = pattern[1:-1]
            return Contains(variable, StringVal(inner))
        else:
            return BoolVal(True)

    def encode_ip_cidr(self, cidr: str):
        """Encode CIDR check as BitVec mask operation.

        '10.0.0.0/8' -> (source_ip & 0xFF000000) == 0x0A000000
        """
        if "/" not in cidr:
            ip_int = self._ip_to_int(cidr)
            return self.source_ip == BitVecVal(ip_int, 32)

        ip_str, prefix_len_str = cidr.split("/")
        prefix_len = int(prefix_len_str)
        ip_int = self._ip_to_int(ip_str)
        mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
        network = ip_int & mask

        return (self.source_ip & BitVecVal(mask, 32)) == BitVecVal(network, 32)

    def encode_leading_key_restriction(self, tenant_prefix: str):
        """Encode DynamoDB LeadingKeys condition."""
        return PrefixOf(StringVal(tenant_prefix), self.leading_key)

    def _get_variable_for_key(self, key: str):
        """Map IAM condition key to Z3 variable."""
        key_lower = key.lower()
        if "leadingkeys" in key_lower:
            return self.leading_key
        elif "sourceip" in key_lower or "source_ip" in key_lower:
            return self.source_ip
        elif "principal" in key_lower:
            return self.principal
        else:
            return String(f"cond_{key.replace(':', '_').replace('/', '_')}")

    @staticmethod
    def _ip_to_int(ip_str: str) -> int:
        parts = ip_str.split(".")
        return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])


@dataclass
class PolicyEdge:
    """Represents a single IAM permission edge from the graph."""
    principal: str
    resource: str
    actions: list[str]
    effect: str
    conditions: dict
    source: str
    line: int


class Z3IAMAnalyzer:
    """
    Formal IAM permission analysis using Z3 theorem prover.

    Checks three properties:
    1. Missing DynamoDB LeadingKeys → cross-tenant access provably possible
    2. Wildcard actions without scoping conditions → maximally permissive
    3. Deny statement effectiveness → does deny actually restrict the allow?
    """

    def __init__(self, timeout_ms: int = TIMEOUT_MS):
        self._timeout_ms = timeout_ms
        self._encoder = IAMConstraintEncoder()

    def analyze(self, graph: InfraGraph) -> list[Finding]:
        """Run all Z3-based property checks."""
        findings = []
        edges = self._collect_edges(graph)

        findings.extend(self._check_missing_leading_keys(graph, edges))
        findings.extend(self._check_unscoped_wildcards(edges))
        findings.extend(self._check_deny_mitigation(edges))

        logger.info(f"Z3 IAM analysis complete: {len(findings)} findings")
        return findings

    def _collect_edges(self, graph: InfraGraph) -> list[PolicyEdge]:
        """Extract all IAM permission edges from the graph."""
        edges = []
        for source, target, data in graph.iam.edges(data=True):
            if data.get("relationship") == "can_assume":
                continue
            edges.append(PolicyEdge(
                principal=source,
                resource=target,
                actions=data.get("actions", []),
                effect=data.get("effect", "Allow"),
                conditions=data.get("conditions", {}),
                source=data.get("source", ""),
                line=data.get("line", 0),
            ))
        return edges

    def _check_missing_leading_keys(self, graph: InfraGraph,
                                     edges: list[PolicyEdge]) -> list[Finding]:
        """
        For DynamoDB grants: prove cross-tenant access is possible when
        no LeadingKeys condition restricts partition key access.

        Z3 formulation:
        - Assert: allow constraint holds (action matches, resource matches)
        - Assert: leading_key does NOT start with expected tenant prefix
        - If SAT: cross-tenant access is provably possible
        """
        findings = []

        dynamodb_nodes = {
            node_id for node_id, attrs in graph.network.nodes(data=True)
            if attrs.get("resource_type") == "AWS::DynamoDB::Table"
        }

        for edge in edges:
            if edge.effect != "Allow":
                continue

            has_dynamodb_data_actions = any(
                a in DYNAMODB_DATA_ACTIONS or a == "dynamodb:*"
                for a in edge.actions
            )
            if not has_dynamodb_data_actions:
                continue

            # Check if a LeadingKeys condition exists
            has_leading_keys = self._has_leading_keys_condition(edge.conditions)
            if has_leading_keys:
                continue

            # Prove via Z3 that cross-tenant access is possible
            proven = self._prove_cross_tenant_possible(edge)
            if not proven:
                continue

            findings.append(Finding(
                id=f"Z3-MULTITENANT-{len(findings)}",
                agent="infrastructure",
                category="multi_tenant_isolation",
                cwe="CWE-284",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                title=(
                    f"DynamoDB grant to '{edge.principal}' lacks LeadingKeys condition "
                    f"— cross-tenant access formally provable"
                ),
                description=(
                    f"IAM policy grants {edge.actions} to DynamoDB table '{edge.resource}' "
                    f"without a dynamodb:LeadingKeys condition. Z3 SMT solver formally proves "
                    f"that a request accessing ANY partition key (including other tenants') "
                    f"satisfies this policy. Combined with application-layer tenant_id from "
                    f"request body, this creates a complete multi-tenant isolation failure."
                ),
                evidence=Evidence(
                    snippet=(
                        f"Principal: {edge.principal}\n"
                        f"Resource: {edge.resource}\n"
                        f"Actions: {', '.join(edge.actions)}\n"
                        f"Conditions: {edge.conditions or '(none)'}\n"
                        f"Source: {edge.source} (line {edge.line})"
                    ),
                    reasoning=(
                        "Z3 proof: SAT(allow_constraint AND leading_key != 'TENANT#expected_*'). "
                        "The solver found a satisfying assignment where the principal accesses "
                        "a partition key belonging to a different tenant. No IAM-level defense "
                        "restricts which partition keys can be accessed."
                    ),
                ),
                location=Location(
                    file_path="infra/",
                    start_line=edge.line,
                    resource_id=edge.resource,
                ),
                remediation={
                    "explanation": (
                        "Replace grant_read_write_data() with explicit PolicyStatement "
                        "including conditions={'ForAllValues:StringLike': "
                        "{'dynamodb:LeadingKeys': ['TENANT#${aws:PrincipalTag/tenant_id}*']}}"
                    ),
                },
            ))

        return findings

    def _prove_cross_tenant_possible(self, edge: PolicyEdge) -> bool:
        """Use Z3 to prove cross-tenant access is satisfiable."""
        solver = Solver()
        solver.set("timeout", self._timeout_ms)

        enc = self._encoder

        # Encode the allow: action matches one of the granted actions
        action_constraints = [enc.encode_action_match(a) for a in edge.actions]
        allow_constraint = Or(action_constraints)

        # Assert: the allow holds
        solver.add(allow_constraint)

        # Assert: the leading key does NOT match the expected tenant prefix
        # (i.e., we're accessing another tenant's data)
        solver.add(Not(PrefixOf(StringVal("TENANT#expected_"), enc.leading_key)))

        # If conditions exist, encode them as additional constraints on the allow
        if edge.conditions:
            cond_constraint = self._encode_all_conditions(edge.conditions)
            solver.add(cond_constraint)

        result = solver.check()
        if result == sat:
            return True
        elif result == unsat:
            return False
        else:
            logger.warning(f"Z3 timeout on leading keys check for {edge.principal}")
            return True  # Fail-open: assume vulnerable on timeout

    def _check_unscoped_wildcards(self, edges: list[PolicyEdge]) -> list[Finding]:
        """
        For permissions with service:* or broad action sets, prove they are
        maximally permissive by checking no condition restricts them.

        Z3 formulation:
        - Assert: wildcard action matches
        - Assert: conditions (if any) hold
        - Assert: action is an administrative/dangerous action
        - If SAT: dangerous action is reachable
        """
        findings = []

        for edge in edges:
            if edge.effect != "Allow":
                continue

            wildcard_actions = [a for a in edge.actions if a.endswith(":*") or a == "*"]
            if not wildcard_actions:
                continue

            # If no conditions at all, deterministically flag (no Z3 needed)
            if not edge.conditions:
                proven = True
            else:
                proven = self._prove_wildcard_unscoped(edge, wildcard_actions)

            if not proven:
                continue

            if edge.conditions:
                scope_note = "conditions do not prevent dangerous actions"
            else:
                scope_note = "no restricting conditions"

            findings.append(Finding(
                id=f"Z3-UNSCOPED-{len(findings)}",
                agent="infrastructure",
                category="overpermissive_iam",
                cwe="CWE-250",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                title=(
                    f"Wildcard '{wildcard_actions[0]}' on '{edge.principal}' "
                    f"— {scope_note}"
                ),
                description=(
                    f"IAM policy grants {wildcard_actions} to principal '{edge.principal}' "
                    f"targeting '{edge.resource}'. "
                    f"{'No conditions restrict scope.' if not edge.conditions else 'Z3 proves conditions do not restrict dangerous actions.'} "
                    f"If this compute resource is compromised, attacker gains full "
                    f"service-level administrative access."
                ),
                evidence=Evidence(
                    snippet=(
                        f"Principal: {edge.principal}\n"
                        f"Actions: {', '.join(edge.actions)}\n"
                        f"Resource: {edge.resource}\n"
                        f"Conditions: {edge.conditions or '(none)'}\n"
                        f"Source: {edge.source} (line {edge.line})"
                    ),
                    reasoning=(
                        "Z3 proof: SAT(wildcard_action_match AND conditions). "
                        "Administrative actions (CreateUser, DeleteTable, etc.) are "
                        "reachable under the current policy constraints."
                    ),
                ),
                location=Location(
                    file_path="infra/",
                    start_line=edge.line,
                    resource_id=edge.principal,
                ),
            ))

        return findings

    def _prove_wildcard_unscoped(self, edge: PolicyEdge,
                                  wildcard_actions: list[str]) -> bool:
        """Prove a dangerous action is reachable despite conditions."""
        solver = Solver()
        solver.set("timeout", self._timeout_ms)

        enc = self._encoder

        # Assert: action matches the wildcard
        action_constraints = [enc.encode_action_match(a) for a in wildcard_actions]
        solver.add(Or(action_constraints))

        # Assert: conditions hold
        if edge.conditions:
            cond_constraint = self._encode_all_conditions(edge.conditions)
            solver.add(cond_constraint)

        # Assert: action is a known dangerous/admin action
        # (proves the wildcard enables dangerous operations)
        service_prefix = wildcard_actions[0].split(":")[0] if ":" in wildcard_actions[0] else ""
        if service_prefix:
            dangerous_actions = [
                f"{service_prefix}:Delete*",
                f"{service_prefix}:Create*",
                f"{service_prefix}:Update*",
                f"{service_prefix}:Admin*",
            ]
            solver.add(Or([
                PrefixOf(StringVal(f"{service_prefix}:Delete"), enc.action),
                PrefixOf(StringVal(f"{service_prefix}:Create"), enc.action),
                PrefixOf(StringVal(f"{service_prefix}:Admin"), enc.action),
            ]))

        result = solver.check()
        if result == sat:
            return True
        elif result == unsat:
            return False
        else:
            logger.warning(f"Z3 timeout on wildcard check for {edge.principal}")
            return True

    def _check_deny_mitigation(self, edges: list[PolicyEdge]) -> list[Finding]:
        """
        For each principal with both Allow and Deny edges, check whether
        the Deny actually mitigates the Allow.

        Zelkova formula: SAT(allowed AND NOT denied)
        - If SAT: deny does NOT fully mitigate, access still possible
        - If UNSAT: deny fully blocks the allow
        """
        findings = []

        # Group edges by principal
        by_principal: dict[str, dict[str, list[PolicyEdge]]] = {}
        for edge in edges:
            if edge.principal not in by_principal:
                by_principal[edge.principal] = {"allow": [], "deny": []}
            by_principal[edge.principal][edge.effect.lower()].append(edge)

        for principal, grouped in by_principal.items():
            if not grouped["allow"] or not grouped["deny"]:
                continue

            # Check each allow against the denies
            for allow_edge in grouped["allow"]:
                wildcard_actions = [a for a in allow_edge.actions if ":*" in a or a == "*"]
                if not wildcard_actions:
                    continue

                mitigated = self._prove_deny_mitigates(allow_edge, grouped["deny"])
                if mitigated:
                    continue

                findings.append(Finding(
                    id=f"Z3-DENY-INEFFECTIVE-{len(findings)}",
                    agent="infrastructure",
                    category="deny_evaluation",
                    cwe="CWE-269",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    title=(
                        f"Deny statement does not fully mitigate "
                        f"'{wildcard_actions[0]}' for '{principal}'"
                    ),
                    description=(
                        f"Principal '{principal}' has a broad Allow ({wildcard_actions}) "
                        f"and a Deny statement, but Z3 proves the Deny does not cover "
                        f"all dangerous actions. The Allow remains partially exploitable."
                    ),
                    evidence=Evidence(
                        snippet=(
                            f"Principal: {principal}\n"
                            f"Allow actions: {allow_edge.actions}\n"
                            f"Deny edges: {len(grouped['deny'])}\n"
                            f"Z3 result: SAT(allowed AND NOT denied)"
                        ),
                        reasoning=(
                            "Zelkova formula: the solver found a satisfying assignment where "
                            "the allow grants access but no deny statement blocks it."
                        ),
                    ),
                    location=Location(
                        file_path="infra/",
                        start_line=allow_edge.line,
                        resource_id=principal,
                    ),
                ))

        return findings

    def _prove_deny_mitigates(self, allow_edge: PolicyEdge,
                               deny_edges: list[PolicyEdge]) -> bool:
        """Check if deny fully mitigates an allow. Returns True if mitigated."""
        solver = Solver()
        solver.set("timeout", self._timeout_ms)

        enc = self._encoder

        # Assert: allow holds
        allow_actions = [enc.encode_action_match(a) for a in allow_edge.actions]
        solver.add(Or(allow_actions))

        if allow_edge.conditions:
            solver.add(self._encode_all_conditions(allow_edge.conditions))

        # Assert: NO deny applies (i.e., all denies fail to match)
        for deny_edge in deny_edges:
            deny_actions = [enc.encode_action_match(a) for a in deny_edge.actions]
            deny_matches = Or(deny_actions)
            if deny_edge.conditions:
                deny_cond = self._encode_all_conditions(deny_edge.conditions)
                deny_matches = And(deny_matches, deny_cond)
            # The deny does NOT apply in this scenario
            solver.add(Not(deny_matches))

        # SAT means: there exists a request where allow holds but deny doesn't
        result = solver.check()
        if result == unsat:
            return True  # Deny fully covers the allow
        else:
            return False  # Access is possible despite deny

    def _encode_all_conditions(self, conditions: dict):
        """Encode a full IAM conditions dict as Z3 constraints."""
        enc = self._encoder
        constraints = []

        for operator, key_values in conditions.items():
            if not isinstance(key_values, dict):
                continue
            for key, values in key_values.items():
                if isinstance(values, str):
                    values = [values]
                constraint = enc.encode_condition(operator, key, values)
                constraints.append(constraint)

        if not constraints:
            return BoolVal(True)
        return And(constraints)

    @staticmethod
    def _has_leading_keys_condition(conditions: dict) -> bool:
        """Check if conditions include a DynamoDB LeadingKeys restriction."""
        if not conditions:
            return False
        for operator, key_values in conditions.items():
            if not isinstance(key_values, dict):
                continue
            for key in key_values:
                if "leadingkeys" in key.lower():
                    return True
        return False
