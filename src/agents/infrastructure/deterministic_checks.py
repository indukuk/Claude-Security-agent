"""
Deterministic security checks — no LLM needed.
Fast, zero false positives for the checks they cover.
"""
from __future__ import annotations


import re
import logging

from src.common.findings import Finding, Severity, Confidence, Evidence, Location
from src.common.graph import InfraGraph

logger = logging.getLogger(__name__)


class DeterministicChecker:
    """Run rule-based checks on the infrastructure graph."""

    def check(self, graph: InfraGraph) -> list[Finding]:
        findings = []
        findings.extend(self._check_iam_wildcards(graph))
        findings.extend(self._check_public_access(graph))
        findings.extend(self._check_encryption(graph))
        findings.extend(self._check_logging(graph))
        return findings

    def _check_iam_wildcards(self, graph: InfraGraph) -> list[Finding]:
        """Check for wildcard actions and resources in IAM permissions."""
        findings = []

        for source, target, data in graph.iam.edges(data=True):
            actions = data.get("actions", [])
            effect = data.get("effect", "Allow")

            if effect != "Allow":
                continue

            # Check for service:* patterns
            for action in actions:
                if action.endswith(":*"):
                    # Known exceptions
                    if action in ("bedrock:*",):  # Bedrock doesn't support resource-level
                        continue

                    findings.append(Finding(
                        id=f"DET-IAM-WILDCARD-{len(findings)}",
                        agent="infrastructure",
                        category="overpermissive_iam",
                        cwe="CWE-250",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        title=f"Wildcard action '{action}' grants all service permissions",
                        description=(
                            f"IAM policy grants {action} which includes all current and future "
                            f"actions for this service. Principal '{source}' can perform "
                            f"administrative operations beyond what is needed."
                        ),
                        evidence=Evidence(
                            snippet=f"Principal: {source}\nAction: {action}\nResource: {target}",
                        ),
                        location=Location(
                            file_path=data.get("source_file", "infra/"),
                            start_line=data.get("line", 0),
                            resource_id=source,
                        ),
                    ))

            # Check for Action: '*' (all services, all actions)
            if "*" in actions and len(actions) == 1:
                findings.append(Finding(
                    id=f"DET-IAM-ADMIN-{len(findings)}",
                    agent="infrastructure",
                    category="overpermissive_iam",
                    cwe="CWE-250",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    title=f"AdministratorAccess-equivalent permissions on {source}",
                    description=f"Principal '{source}' has Action: * on Resource: * — equivalent to full admin access.",
                    evidence=Evidence(snippet=f"Principal: {source}\nAction: *\nResource: {target}"),
                    location=Location(file_path="infra/", resource_id=source),
                ))

        return findings

    def _check_public_access(self, graph: InfraGraph) -> list[Finding]:
        """Check for publicly accessible resources that shouldn't be."""
        findings = []

        publicly_reachable = graph.get_publicly_reachable()

        for resource_id in publicly_reachable:
            attrs = graph.network.nodes.get(resource_id, {})
            resource_type = attrs.get("resource_type", "")

            # Data stores should never be publicly reachable
            if attrs.get("is_data"):
                findings.append(Finding(
                    id=f"DET-NET-PUBLIC-DATA-{len(findings)}",
                    agent="infrastructure",
                    category="network_exposure",
                    cwe="CWE-284",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    title=f"Data store '{resource_id}' is publicly reachable",
                    description=(
                        f"Resource {resource_id} ({resource_type}) is reachable from the "
                        f"internet. Data stores should never have direct public access."
                    ),
                    evidence=Evidence(
                        snippet=f"Resource: {resource_id}\nType: {resource_type}\nPath: INTERNET → {resource_id}",
                    ),
                    location=Location(file_path="infra/", resource_id=resource_id),
                ))

        return findings

    def _check_encryption(self, graph: InfraGraph) -> list[Finding]:
        """Check for missing encryption at rest."""
        findings = []

        for node_id, attrs in graph.network.nodes(data=True):
            resource_type = attrs.get("resource_type", "")
            properties = attrs.get("properties", {})

            if resource_type == "AWS::S3::Bucket":
                if not properties.get("BucketEncryption") and not properties.get("encryption"):
                    findings.append(Finding(
                        id=f"DET-ENC-S3-{len(findings)}",
                        agent="infrastructure",
                        category="encryption",
                        cwe="CWE-311",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        title=f"S3 bucket '{node_id}' missing encryption configuration",
                        description="S3 bucket does not have explicit encryption at rest configured.",
                        evidence=Evidence(snippet=f"Resource: {node_id}"),
                        location=Location(file_path="infra/", resource_id=node_id),
                    ))

            if resource_type == "AWS::DynamoDB::Table":
                if not properties.get("SSESpecification"):
                    findings.append(Finding(
                        id=f"DET-ENC-DDB-{len(findings)}",
                        agent="infrastructure",
                        category="encryption",
                        cwe="CWE-311",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        title=f"DynamoDB table '{node_id}' uses default encryption",
                        description="DynamoDB table uses AWS-owned key (default). Consider CMK for compliance.",
                        evidence=Evidence(snippet=f"Resource: {node_id}"),
                        location=Location(file_path="infra/", resource_id=node_id),
                    ))

        return findings

    def _check_logging(self, graph: InfraGraph) -> list[Finding]:
        """Check for missing logging/monitoring."""
        findings = []

        for node_id, attrs in graph.network.nodes(data=True):
            resource_type = attrs.get("resource_type", "")
            properties = attrs.get("properties", {})

            if resource_type == "AWS::S3::Bucket":
                if not properties.get("LoggingConfiguration") and not properties.get("server_access_logs_bucket"):
                    findings.append(Finding(
                        id=f"DET-LOG-S3-{len(findings)}",
                        agent="infrastructure",
                        category="logging",
                        cwe="CWE-778",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        title=f"S3 bucket '{node_id}' has no access logging",
                        description="No server access logging configured. Cannot audit who accessed objects.",
                        evidence=Evidence(snippet=f"Resource: {node_id}"),
                        location=Location(file_path="infra/", resource_id=node_id),
                    ))

        return findings
