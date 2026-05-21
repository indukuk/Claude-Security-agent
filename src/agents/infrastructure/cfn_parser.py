"""
CloudFormation/CDK template parser.
Builds infrastructure graph from template resources.
"""
from __future__ import annotations


import ast
import json
import re
import logging
from pathlib import Path

from src.common.graph import InfraGraph

logger = logging.getLogger(__name__)


class CloudFormationParser:
    """Parse CFN template or CDK source into InfraGraph."""

    COMPUTE_TYPES = {
        "AWS::Lambda::Function", "AWS::ECS::TaskDefinition",
        "AWS::EC2::Instance", "AWS::AppRunner::Service",
    }
    DATA_TYPES = {
        "AWS::DynamoDB::Table", "AWS::RDS::DBInstance",
        "AWS::S3::Bucket", "AWS::ElastiCache::CacheCluster",
        "AWS::SecretsManager::Secret", "AWS::SSM::Parameter",
    }
    PUBLIC_TYPES = {
        "AWS::ApiGateway::RestApi", "AWS::ApiGatewayV2::Api",
        "AWS::ElasticLoadBalancingV2::LoadBalancer",
        "AWS::CloudFront::Distribution",
    }

    def parse(self, template: dict) -> InfraGraph:
        """Parse template into InfraGraph with network, IAM, and data layers."""
        graph = InfraGraph()

        resources = template.get("Resources", {})
        raw_content = template.get("RawContent", "")

        # Add INTERNET virtual node
        graph.network.add_node("INTERNET", resource_type="virtual", is_public=True)

        # Process each resource
        for logical_id, resource in resources.items():
            resource_type = resource.get("Type", "Unknown")
            properties = resource.get("Properties", {})

            graph.add_resource(
                logical_id,
                resource_type,
                properties=properties,
                is_compute=resource_type in self.COMPUTE_TYPES,
                is_data=resource_type in self.DATA_TYPES,
                is_public=resource_type in self.PUBLIC_TYPES,
                source_file=resource.get("SourceFile", ""),
                source_line=properties.get("SourceLine", 0),
            )

            # Public access edges
            if resource_type in self.PUBLIC_TYPES:
                graph.add_connection("INTERNET", logical_id, "public_access")

        # Build edges from references
        self._build_reference_edges(graph, resources)

        # If we have raw CDK source, extract IAM permissions
        if raw_content:
            self._extract_iam_from_cdk(graph, raw_content)

        logger.info(
            f"Parsed template: {graph.network.number_of_nodes()} nodes, "
            f"{graph.network.number_of_edges()} edges"
        )
        return graph

    def _build_reference_edges(self, graph: InfraGraph, resources: dict):
        """Build edges from resource references (Ref, GetAtt, Sub)."""
        for logical_id, resource in resources.items():
            refs = self._extract_refs(resource)
            for ref_target in refs:
                if ref_target in resources and ref_target != logical_id:
                    graph.add_connection(logical_id, ref_target, "references")

    def _extract_refs(self, obj) -> list[str]:
        """Recursively extract all Ref/GetAtt/Sub references."""
        refs = []
        if isinstance(obj, dict):
            if "Ref" in obj:
                refs.append(obj["Ref"])
            elif "Fn::GetAtt" in obj:
                refs.append(obj["Fn::GetAtt"][0] if isinstance(obj["Fn::GetAtt"], list) else obj["Fn::GetAtt"])
            elif "Fn::Sub" in obj:
                sub_str = obj["Fn::Sub"] if isinstance(obj["Fn::Sub"], str) else obj["Fn::Sub"][0]
                refs.extend(re.findall(r'\$\{(\w+)', sub_str))
            for value in obj.values():
                refs.extend(self._extract_refs(value))
        elif isinstance(obj, list):
            for item in obj:
                refs.extend(self._extract_refs(item))
        return refs

    def _extract_iam_from_cdk(self, graph: InfraGraph, content: str):
        """Extract IAM permissions from CDK Python source code."""
        lines = content.split("\n")

        current_lambda = None

        for i, line in enumerate(lines):
            # Track which Lambda we're adding permissions to
            if "lambda_.Function(" in line or "lambda_.DockerImageFunction(" in line:
                # Extract variable name
                match = re.match(r'\s*(\w+)\s*=', line)
                if match:
                    current_lambda = match.group(1)

            # grant_read_write_data — DynamoDB full access
            if "grant_read_write_data(" in line and current_lambda:
                target_match = re.search(r'(\w+)\.grant_read_write_data', line)
                if target_match:
                    table_var = target_match.group(1)
                    graph.add_permission(
                        f"role_{current_lambda}", table_var,
                        actions=["dynamodb:GetItem", "dynamodb:PutItem",
                                "dynamodb:UpdateItem", "dynamodb:DeleteItem",
                                "dynamodb:Query", "dynamodb:Scan"],
                        conditions={},
                        source="grant_read_write_data",
                        line=i + 1,
                    )

            # grant_read_write — S3 full access
            if "grant_read_write(" in line and current_lambda:
                target_match = re.search(r'(\w+)\.grant_read_write\(', line)
                if target_match:
                    bucket_var = target_match.group(1)
                    graph.add_permission(
                        f"role_{current_lambda}", bucket_var,
                        actions=["s3:GetObject", "s3:PutObject",
                                "s3:DeleteObject", "s3:ListBucket"],
                        conditions={},
                        source="grant_read_write",
                        line=i + 1,
                    )

            # Explicit PolicyStatement
            if "PolicyStatement(" in line:
                stmt_block = self._extract_policy_statement(lines, i)
                if stmt_block and current_lambda:
                    actions = stmt_block.get("actions", [])
                    resources = stmt_block.get("resources", ["*"])
                    conditions = stmt_block.get("conditions", {})
                    effect = stmt_block.get("effect", "Allow")
                    graph.add_permission(
                        f"role_{current_lambda}", resources[0] if resources else "*",
                        actions=actions,
                        effect=effect,
                        conditions=conditions,
                        source="PolicyStatement",
                        line=i + 1,
                    )

    def _extract_policy_statement(self, lines: list[str], start_line: int) -> dict | None:
        """Extract actions, resources, conditions, and effect from a PolicyStatement block."""
        block = ""
        paren_depth = 0
        for i in range(start_line, min(start_line + 30, len(lines))):
            line = lines[i]
            block += line + "\n"
            paren_depth += line.count("(") - line.count(")")
            if paren_depth <= 0 and i > start_line:
                break

        actions = re.findall(r"""["']([a-z0-9-]+:[A-Za-z*]+)["']""", block)
        resources = re.findall(r"resources=\[([^\]]+)\]", block)

        effect = "Allow"
        effect_match = re.search(r"effect\s*=\s*iam\.Effect\.(\w+)", block)
        if effect_match:
            effect = effect_match.group(1).capitalize()

        conditions = self._extract_conditions_block(block)

        if actions:
            return {"actions": actions, "resources": resources,
                    "conditions": conditions, "effect": effect}
        return None

    def _extract_conditions_block(self, block: str) -> dict:
        """Extract conditions={...} from a PolicyStatement block string."""
        match = re.search(r"conditions\s*=\s*\{", block)
        if not match:
            return {}

        start = match.start() + len("conditions=")
        brace_depth = 0
        end = start
        for i in range(start, len(block)):
            if block[i] == "{":
                brace_depth += 1
            elif block[i] == "}":
                brace_depth -= 1
                if brace_depth == 0:
                    end = i + 1
                    break

        conditions_str = block[start:end]
        try:
            return ast.literal_eval(conditions_str)
        except (ValueError, SyntaxError):
            logger.debug(f"Failed to parse conditions block: {conditions_str[:100]}")
            return {}
