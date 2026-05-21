"""
Terraform parser — converts terraform plan JSON or HCL into InfraGraph.

Supports two input modes:
1. Plan JSON: `terraform show -json tfplan` output (preferred — resolves all variables)
2. HCL files: Direct .tf parsing via python-hcl2 (fallback — no interpolation)

Produces the same InfraGraph as the CDK parser, so ALL downstream analysis
(Z3 IAM, symbolic rules, blast radius, debate) works unchanged.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from src.common.graph import InfraGraph
from v3.parsers.tf_type_mapping import (
    TF_TO_CFN_TYPE, COMPUTE_TYPES, DATA_TYPES, PUBLIC_TYPES,
)

logger = logging.getLogger(__name__)


class TerraformParser:
    """Parse Terraform plan JSON or HCL into InfraGraph."""

    def parse_plan_json(self, plan_path: str | Path) -> InfraGraph:
        """Parse `terraform show -json` output into InfraGraph."""
        plan_path = Path(plan_path)
        data = json.loads(plan_path.read_text())
        return self._parse_plan_data(data)

    def parse_plan_data(self, plan_data: dict) -> InfraGraph:
        """Parse plan JSON data dict directly."""
        return self._parse_plan_data(plan_data)

    def parse_hcl_directory(self, tf_dir: str | Path) -> InfraGraph:
        """Parse .tf files directly (fallback when plan not available)."""
        try:
            import hcl2
        except ImportError:
            logger.error("python-hcl2 not installed. Run: pip install python-hcl2")
            return InfraGraph()

        tf_dir = Path(tf_dir)
        graph = InfraGraph()
        graph.network.add_node("INTERNET", resource_type="virtual", is_public=True)

        for tf_file in tf_dir.rglob("*.tf"):
            try:
                with open(tf_file) as f:
                    config = hcl2.load(f)
                self._parse_hcl_resources(graph, config, str(tf_file))
            except Exception as e:
                logger.warning(f"Failed to parse {tf_file}: {e}")

        logger.info(
            f"Terraform HCL parsed: {graph.network.number_of_nodes()} nodes, "
            f"{graph.iam.number_of_edges()} IAM edges"
        )
        return graph

    def _parse_plan_data(self, data: dict) -> InfraGraph:
        """Internal: build InfraGraph from plan JSON structure."""
        graph = InfraGraph()
        graph.network.add_node("INTERNET", resource_type="virtual", is_public=True)

        # Extract resources from planned_values
        planned = data.get("planned_values", {})
        root_module = planned.get("root_module", {})

        resources = root_module.get("resources", [])
        # Also get resources from child modules
        for child in root_module.get("child_modules", []):
            resources.extend(child.get("resources", []))
            for nested in child.get("child_modules", []):
                resources.extend(nested.get("resources", []))

        logger.info(f"Terraform plan: {len(resources)} resources")

        for resource in resources:
            self._add_resource(graph, resource)

        # Second pass: build IAM edges from policy resources
        for resource in resources:
            self._extract_iam(graph, resource)

        # Build network edges
        self._build_network_edges(graph, resources)

        logger.info(
            f"Terraform graph: {graph.network.number_of_nodes()} nodes, "
            f"{graph.network.number_of_edges()} network edges, "
            f"{graph.iam.number_of_edges()} IAM edges"
        )
        return graph

    def _add_resource(self, graph: InfraGraph, resource: dict):
        """Add a single Terraform resource to the graph."""
        tf_type = resource.get("type", "")
        address = resource.get("address", "")
        values = resource.get("values", {})

        cfn_type = TF_TO_CFN_TYPE.get(tf_type, f"TF::{tf_type}")

        graph.add_resource(
            address,
            cfn_type,
            properties=values,
            is_compute=cfn_type in COMPUTE_TYPES,
            is_data=cfn_type in DATA_TYPES,
            is_public=cfn_type in PUBLIC_TYPES,
            source_file=resource.get("provider_name", "terraform"),
            tf_type=tf_type,
        )

        # Public access edges
        if cfn_type in PUBLIC_TYPES:
            graph.add_connection("INTERNET", address, "public_access")

        # Load balancers: check internal flag
        if tf_type in ("aws_lb", "aws_alb"):
            if not values.get("internal", False):
                graph.add_connection("INTERNET", address, "public_access")

    def _extract_iam(self, graph: InfraGraph, resource: dict):
        """Extract IAM permissions from policy resources."""
        tf_type = resource.get("type", "")
        address = resource.get("address", "")
        values = resource.get("values", {})

        if tf_type == "aws_iam_role_policy":
            role = values.get("role", "")
            policy_json = values.get("policy", "")
            if isinstance(policy_json, str):
                try:
                    policy = json.loads(policy_json)
                except (json.JSONDecodeError, TypeError):
                    return
            elif isinstance(policy_json, dict):
                policy = policy_json
            else:
                return

            self._add_policy_statements(graph, f"role_{role}", policy)

        elif tf_type == "aws_iam_policy":
            policy_json = values.get("policy", "")
            if isinstance(policy_json, str):
                try:
                    policy = json.loads(policy_json)
                except (json.JSONDecodeError, TypeError):
                    return
            elif isinstance(policy_json, dict):
                policy = policy_json
            else:
                return
            # Store policy for later attachment resolution
            graph.network.nodes[address]["policy_document"] = policy

        elif tf_type == "aws_iam_role_policy_attachment":
            role = values.get("role", "")
            policy_arn = values.get("policy_arn", "")
            # Find the policy resource and link
            for node_id, attrs in graph.network.nodes(data=True):
                if attrs.get("tf_type") == "aws_iam_policy":
                    policy_doc = attrs.get("policy_document")
                    if policy_doc:
                        self._add_policy_statements(graph, f"role_{role}", policy_doc)

        elif tf_type == "aws_lambda_function":
            role_arn = values.get("role", "")
            if role_arn:
                role_name = role_arn.split("/")[-1] if "/" in role_arn else role_arn
                graph.network.nodes[address]["iam_role"] = f"role_{role_name}"

    def _add_policy_statements(self, graph: InfraGraph, principal: str, policy: dict):
        """Parse IAM policy document and add permission edges."""
        statements = policy.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        for stmt in statements:
            effect = stmt.get("Effect", "Allow")
            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", ["*"])
            conditions = stmt.get("Condition", {})

            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]

            for resource in resources:
                graph.add_permission(
                    principal, resource,
                    actions=actions,
                    effect=effect,
                    conditions=conditions,
                    source="terraform_policy",
                )

    def _build_network_edges(self, graph: InfraGraph, resources: list[dict]):
        """Build network connectivity edges from security groups and references."""
        for resource in resources:
            tf_type = resource.get("type", "")
            address = resource.get("address", "")
            values = resource.get("values", {})

            # Security group rules with 0.0.0.0/0 → public access
            if tf_type == "aws_security_group_rule":
                if values.get("type") == "ingress":
                    cidr_blocks = values.get("cidr_blocks", [])
                    if "0.0.0.0/0" in cidr_blocks:
                        sg_id = values.get("security_group_id", "")
                        if sg_id:
                            graph.add_connection("INTERNET", sg_id, "public_ingress")

    def _parse_hcl_resources(self, graph: InfraGraph, config: dict, source_file: str):
        """Parse HCL config dict (from python-hcl2) into graph."""
        for resource_block in config.get("resource", []):
            for tf_type, instances in resource_block.items():
                for instance in instances:
                    for name, values in instance.items():
                        address = f"{tf_type}.{name}"
                        cfn_type = TF_TO_CFN_TYPE.get(tf_type, f"TF::{tf_type}")

                        graph.add_resource(
                            address,
                            cfn_type,
                            properties=values if isinstance(values, dict) else {},
                            is_compute=cfn_type in COMPUTE_TYPES,
                            is_data=cfn_type in DATA_TYPES,
                            is_public=cfn_type in PUBLIC_TYPES,
                            source_file=source_file,
                            tf_type=tf_type,
                        )

                        if cfn_type in PUBLIC_TYPES:
                            graph.add_connection("INTERNET", address, "public_access")
