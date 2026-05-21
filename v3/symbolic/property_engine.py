"""
Symbolic Property Engine — evaluates declarative YAML rules against InfraGraph.

Replaces hardcoded checks with a data-driven rule system.
Rules with context_needed=false emit final findings (zero FP).
Rules with context_needed=true produce candidates for Layer 2 neural judgment.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from src.common.findings import Finding, Severity, Confidence, Evidence, Location
from src.common.graph import InfraGraph
from v3.symbolic.rule_schema import SymbolicRule, RuleCondition, SymbolicCandidate

logger = logging.getLogger(__name__)

RULES_DIR = Path(__file__).parent / "rules"


class PropertyEngine:
    """
    Loads YAML rules and evaluates them against an InfraGraph.

    IntelliSA-inspired: symbolic rules define WHAT to check,
    neural layer handles WHY it matters for context-dependent findings.
    """

    def __init__(self, rules_dir: Path = RULES_DIR):
        self.rules: list[SymbolicRule] = []
        self._load_rules(rules_dir)

    def _load_rules(self, rules_dir: Path):
        """Load all YAML rule files from the rules directory."""
        if not rules_dir.exists():
            logger.warning(f"Rules directory not found: {rules_dir}")
            return

        for yaml_file in sorted(rules_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(yaml_file.read_text())
                for rule_data in data.get("rules", []):
                    self.rules.append(SymbolicRule.from_dict(rule_data))
            except Exception as e:
                logger.error(f"Failed to load rules from {yaml_file}: {e}")

        logger.info(f"Loaded {len(self.rules)} symbolic rules from {rules_dir}")

    def evaluate(self, graph: InfraGraph) -> tuple[list[Finding], list[SymbolicCandidate]]:
        """
        Evaluate all rules against the graph.

        Returns:
            findings: Final findings from context_needed=false rules (zero FP)
            candidates: Candidates requiring Layer 2 judgment (context_needed=true)
        """
        findings: list[Finding] = []
        candidates: list[SymbolicCandidate] = []

        for rule in self.rules:
            matches = self._evaluate_rule(rule, graph)
            for match in matches:
                if rule.context_needed:
                    candidates.append(match)
                else:
                    findings.append(self._candidate_to_finding(match))

        logger.info(
            f"Property engine: {len(findings)} definitive findings, "
            f"{len(candidates)} candidates for neural judgment"
        )
        return findings, candidates

    def _evaluate_rule(self, rule: SymbolicRule, graph: InfraGraph) -> list[SymbolicCandidate]:
        """Evaluate a single rule against the graph."""
        condition = rule.condition

        if condition.type == "graph_query":
            return self._eval_graph_query(rule, graph)
        elif condition.type == "edge_query":
            return self._eval_edge_query(rule, graph)
        elif condition.type == "z3_sat":
            return self._eval_z3(rule, graph)
        elif condition.type == "composite":
            return self._eval_composite(rule, graph)
        else:
            logger.warning(f"Unknown condition type: {condition.type}")
            return []

    def _eval_graph_query(self, rule: SymbolicRule, graph: InfraGraph) -> list[SymbolicCandidate]:
        """Evaluate a graph_query rule: filter nodes, check property."""
        results = []
        node_filter = rule.condition.node_filter
        property_check = rule.condition.property_check

        for node_id, attrs in graph.network.nodes(data=True):
            if not self._matches_filter(attrs, node_filter):
                continue

            props = attrs.get("properties", {})
            if property_check and not self._eval_property_check(property_check, props, attrs, graph, node_id):
                continue

            title = rule.title_template.format(resource_id=node_id, **attrs)
            description = rule.description_template.format(resource_id=node_id, **attrs)

            results.append(SymbolicCandidate(
                rule_id=rule.id,
                resource_id=node_id,
                severity=rule.severity,
                title=title,
                description=description,
                category=rule.category,
                cwe=rule.cwe,
                evidence={"resource_id": node_id, "resource_type": attrs.get("resource_type", ""),
                          "properties": {k: v for k, v in props.items() if k != "RawContent"}},
                context_needed=rule.context_needed,
                context_questions=rule.context_questions,
                remediation=rule.remediation_template,
            ))

        return results

    def _eval_edge_query(self, rule: SymbolicRule, graph: InfraGraph) -> list[SymbolicCandidate]:
        """Evaluate an edge_query rule: filter IAM edges."""
        results = []
        edge_filter = rule.condition.edge_filter

        for source, target, data in graph.iam.edges(data=True):
            if not self._matches_edge_filter(data, edge_filter):
                continue

            title = rule.title_template.format(
                principal=source, resource=target,
                actions=data.get("actions", []),
            )
            description = rule.description_template.format(
                principal=source, resource=target,
                actions=data.get("actions", []),
            )

            results.append(SymbolicCandidate(
                rule_id=rule.id,
                resource_id=source,
                severity=rule.severity,
                title=title,
                description=description,
                category=rule.category,
                cwe=rule.cwe,
                evidence={"principal": source, "resource": target,
                          "actions": data.get("actions", []),
                          "effect": data.get("effect", "Allow"),
                          "conditions": data.get("conditions", {})},
                context_needed=rule.context_needed,
                context_questions=rule.context_questions,
                remediation=rule.remediation_template,
            ))

        return results

    def _eval_z3(self, rule: SymbolicRule, graph: InfraGraph) -> list[SymbolicCandidate]:
        """Delegate to Z3 property checker."""
        try:
            from src.agents.infrastructure.z3_iam_analyzer import Z3IAMAnalyzer
            analyzer = Z3IAMAnalyzer()
            z3_findings = analyzer.analyze(graph)

            results = []
            for f in z3_findings:
                results.append(SymbolicCandidate(
                    rule_id=rule.id,
                    resource_id=f.location.resource_id if f.location else "",
                    severity=f.severity.name,
                    title=f.title,
                    description=f.description,
                    category=f.category,
                    cwe=f.cwe or "",
                    evidence={"snippet": f.evidence.snippet if f.evidence else "",
                              "reasoning": f.evidence.reasoning if f.evidence else ""},
                    context_needed=False,
                ))
            return results
        except ImportError:
            logger.warning("Z3 not available for rule %s", rule.id)
            return []

    def _eval_composite(self, rule: SymbolicRule, graph: InfraGraph) -> list[SymbolicCandidate]:
        """Evaluate composite conditions (all_of, any_of, none_of)."""
        # For now, treat composite as all_of sub-conditions must match at least one node
        # This is a simplified implementation
        return []

    def _matches_filter(self, attrs: dict, node_filter: dict) -> bool:
        """Check if node attributes match the filter criteria."""
        for key, value in node_filter.items():
            if attrs.get(key) != value:
                return False
        return True

    def _matches_edge_filter(self, data: dict, edge_filter: dict) -> bool:
        """Check if edge data matches the filter criteria."""
        for key, value in edge_filter.items():
            if key == "actions_contains":
                if value not in data.get("actions", []):
                    return False
            elif key == "actions_any_wildcard":
                actions = data.get("actions", [])
                if not any(a.endswith(":*") or a == "*" for a in actions):
                    return False
            elif data.get(key) != value:
                return False
        return True

    def _eval_property_check(self, check: str, props: dict, attrs: dict,
                              graph: InfraGraph, node_id: str) -> bool:
        """Evaluate a property_check expression safely."""
        safe_ns = {
            "props": props,
            "attrs": attrs,
            "node_id": node_id,
            "graph": graph,
            "is_publicly_reachable": lambda: node_id in graph.get_publicly_reachable(),
            "has_iam_wildcard": lambda: any(
                any(a.endswith(":*") or a == "*" for a in d.get("actions", []))
                for _, t, d in graph.iam.edges(data=True)
                if t == node_id or _ == f"role_{node_id}"
            ),
        }
        try:
            return bool(eval(check, {"__builtins__": {}}, safe_ns))
        except Exception as e:
            logger.debug(f"Property check failed for {node_id}: {check} — {e}")
            return False

    @staticmethod
    def _candidate_to_finding(candidate: SymbolicCandidate) -> Finding:
        """Convert a definitive symbolic candidate to a Finding."""
        return Finding(
            id=f"{candidate.rule_id}-{candidate.resource_id}",
            agent="symbolic_engine",
            category=candidate.category,
            cwe=candidate.cwe or None,
            severity=Severity[candidate.severity],
            confidence=Confidence.HIGH,
            title=candidate.title,
            description=candidate.description,
            evidence=Evidence(
                snippet=str(candidate.evidence),
            ),
            location=Location(
                file_path="infra/",
                resource_id=candidate.resource_id,
            ),
            remediation={"explanation": candidate.remediation} if candidate.remediation else None,
        )
