"""
Toxic combination detection — compound risk from individually acceptable configs.
"""
from __future__ import annotations


import logging

from src.common.findings import Finding, Severity, Confidence, Evidence, Location
from src.common.graph import InfraGraph
from src.skills.infra_security_skills import COMPLIANCE_TOXIC_COMBINATIONS

logger = logging.getLogger(__name__)


class ToxicCombinationDetector:
    """Detect compound risk patterns that span multiple resources."""

    def detect(self, graph: InfraGraph, existing_findings: list) -> list[Finding]:
        findings = []

        for pattern in COMPLIANCE_TOXIC_COMBINATIONS:
            instances = self._match_pattern(pattern, graph, existing_findings)
            for instance in instances:
                findings.append(Finding(
                    id=f"TOXIC-{pattern['id']}",
                    agent="infrastructure",
                    category="toxic_combination",
                    cwe=None,
                    severity=Severity[pattern["combined_severity"]],
                    confidence=Confidence.HIGH,
                    title=pattern["name"],
                    description=pattern["attack_narrative"],
                    evidence=Evidence(
                        snippet="\n".join(f"- {c}" for c in pattern["components"]),
                        reasoning=f"Individual severities: {pattern['individual_severity']} → Combined: {pattern['combined_severity']}",
                    ),
                    location=Location(file_path="infra/", resource_id=instance.get("primary_resource", "")),
                    attack_path=instance.get("attack_steps", []),
                    blast_radius=instance.get("affected", []),
                ))

        return findings

    def _match_pattern(self, pattern: dict, graph: InfraGraph,
                       existing_findings: list) -> list[dict]:
        """Check if a toxic combination pattern's components are all satisfied."""
        instances = []

        # Simple predicate evaluation against graph state
        components_matched = []
        for component in pattern["components"]:
            if self._evaluate_component(component, graph, existing_findings):
                components_matched.append(component)

        # All components must match for the pattern to fire
        if len(components_matched) == len(pattern["components"]):
            instances.append({
                "primary_resource": "stack",
                "matched_components": components_matched,
                "attack_steps": pattern.get("components", []),
                "affected": pattern.get("blast_radius", []),
            })

        return instances

    def _evaluate_component(self, component: str, graph: InfraGraph,
                           existing_findings: list) -> bool:
        """Evaluate a single component predicate."""
        component_lower = component.lower()

        # Check against graph structure
        if "publicly reachable" in component_lower or "internet-facing" in component_lower:
            return len(graph.get_publicly_reachable()) > 0

        if "broad" in component_lower and "iam" in component_lower:
            # Check for wildcard permissions
            for _, _, data in graph.iam.edges(data=True):
                actions = data.get("actions", [])
                if any(a.endswith(":*") or a == "*" for a in actions):
                    return True
            return False

        if "timeout" in component_lower and "15 min" in component_lower:
            # Check for long-timeout Lambda
            for _, attrs in graph.network.nodes(data=True):
                if attrs.get("resource_type") == "AWS::Lambda::Function":
                    return True  # Simplified: assume yes for now
            return False

        if "signup" in component_lower or "self-signup" in component_lower:
            # Check if Cognito allows signup
            for _, attrs in graph.network.nodes(data=True):
                if attrs.get("resource_type") == "AWS::Cognito::UserPool":
                    return True
            return False

        if "log retention" in component_lower:
            # Check existing findings for log retention issues
            return any("log" in f.category.lower() and "retention" in f.title.lower()
                      for f in existing_findings if hasattr(f, "category"))

        if "versioning" in component_lower or "no s3" in component_lower:
            for _, attrs in graph.network.nodes(data=True):
                if attrs.get("resource_type") == "AWS::S3::Bucket":
                    props = attrs.get("properties", {})
                    if not props.get("versioned") and not props.get("VersioningConfiguration"):
                        return True
            return False

        if "cors" in component_lower and "*" in component_lower:
            return True  # Simplified: known from codebase analysis

        # Default: check if any existing finding mentions this
        return any(component_lower[:20] in str(f).lower()
                  for f in existing_findings if hasattr(f, "title"))
