from __future__ import annotations

"""
Infrastructure Graph Construction & Exploration Skills
========================================================
Skills for building and querying the three infrastructure graphs:
- G_net (Resource Topology / Network Reachability)
- G_iam (IAM Permission Graph)
- G_data (Data Classification Graph)

And their overlay (compound analysis).
"""

from dataclasses import dataclass
from enum import Enum


# =============================================================================
# SKILL 1: Resource Graph (G_net) Construction
# =============================================================================

RESOURCE_GRAPH_RULES = {
    "node_creation": {
        "description": "Every resource in the CFN template becomes a node",
        "attributes": [
            "logical_id: unique identifier in template",
            "resource_type: AWS::Service::Resource",
            "is_compute: bool (Lambda, EC2, ECS, etc.)",
            "is_data_store: bool (DynamoDB, S3, RDS, etc.)",
            "is_network: bool (VPC, Subnet, SG, etc.)",
            "is_public: bool (internet-reachable)",
            "properties: all configuration (for deterministic checks)",
        ],
        "virtual_nodes": [
            "INTERNET — represents external/public access",
            "VPC_ENDPOINT — represents private AWS service access",
        ],
    },

    "edge_rules": [
        {
            "name": "Reference edges (explicit)",
            "source": "Any resource with Ref, Fn::GetAtt, Fn::Sub referencing another",
            "edge_type": "references",
            "detection": "Parse all intrinsic functions recursively",
        },
        {
            "name": "Internet exposure (API Gateway)",
            "source": "INTERNET",
            "target": "AWS::ApiGateway::RestApi or AWS::ApiGatewayV2::Api",
            "edge_type": "public_access",
            "condition": "Always (API Gateways are internet-facing by default)",
        },
        {
            "name": "Internet exposure (Lambda Function URL)",
            "source": "INTERNET",
            "target": "AWS::Lambda::Url",
            "edge_type": "public_access",
            "condition": "auth_type == NONE (if AWS_IAM, partially protected)",
        },
        {
            "name": "API Gateway → Lambda integration",
            "source": "AWS::ApiGateway::Method",
            "target": "AWS::Lambda::Function",
            "edge_type": "invokes",
            "detection": "Method's Integration.Uri references Lambda ARN",
        },
        {
            "name": "Lambda → DynamoDB",
            "source": "AWS::Lambda::Function",
            "target": "AWS::DynamoDB::Table",
            "edge_type": "accesses",
            "detection": "Lambda's env vars reference table name AND IAM grants table access",
        },
        {
            "name": "Lambda → S3",
            "source": "AWS::Lambda::Function",
            "target": "AWS::S3::Bucket",
            "edge_type": "accesses",
            "detection": "Lambda's env vars reference bucket name AND IAM grants bucket access",
        },
        {
            "name": "Lambda → Lambda (invoke)",
            "source": "AWS::Lambda::Function",
            "target": "AWS::Lambda::Function",
            "edge_type": "invokes",
            "detection": "IAM policy grants lambda:InvokeFunction on target's ARN",
        },
        {
            "name": "Lambda → Bedrock",
            "source": "AWS::Lambda::Function",
            "target": "Bedrock (virtual node)",
            "edge_type": "invokes",
            "detection": "IAM policy grants bedrock:InvokeModel",
        },
        {
            "name": "Cognito → Lambda (trigger)",
            "source": "AWS::Cognito::UserPool",
            "target": "AWS::Lambda::Function",
            "edge_type": "triggers",
            "detection": "UserPool LambdaTriggers configuration",
        },
    ],

    "compliance_codebase_topology": """
        Expected graph for this codebase:

        INTERNET
          ├─→ API Gateway (v1) ──→ Lambda Authorizer
          │         │                    └─→ DynamoDB (policies)
          │         ├─→ Agent Lambda v1 ──→ DynamoDB (sessions)
          │         │                  ├─→ S3 (evidence)
          │         │                  ├─→ Bedrock
          │         │                  └─→ Agent Lambda v2/v3 (invoke)
          │         ├─→ Auth Lambda ──→ Cognito
          │         │              ├─→ DynamoDB (tenants)
          │         │              ├─→ DynamoDB (policies)
          │         │              └─→ DynamoDB (user_tenants)
          │         ├─→ Data Handler ──→ DynamoDB (tenants)
          │         └─→ Observer Lambda ──→ CloudWatch Logs
          │
          └─→ Function URL ──→ Agent Lambda v3
                                    └─→ (same as v1)
    """,
}


# =============================================================================
# SKILL 2: IAM Permission Graph (G_iam) Construction
# =============================================================================

IAM_GRAPH_RULES = {
    "node_types": [
        "Principal: IAM roles attached to Lambda functions",
        "Resource: DynamoDB tables, S3 buckets, Cognito pools, Bedrock, CloudWatch",
        "Policy: Inline policies, managed policy ARNs",
    ],

    "edge_construction": [
        {
            "source": "CDK grant methods",
            "detection": "table.grant_read_write_data(lambda_fn)",
            "produces": "Permission edge: lambda_role → table with actions [GetItem, PutItem, ...]",
            "note": "CDK grant methods are the PRIMARY way permissions are defined in this codebase",
        },
        {
            "source": "Explicit PolicyStatement",
            "detection": "iam.PolicyStatement(actions=[...], resources=[...])",
            "produces": "Permission edge: role → resource with specified actions",
        },
        {
            "source": "Managed policy attachment",
            "detection": "role.add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name(...))",
            "produces": "Permission edge: role → * with managed policy's actions (expanded from bundle)",
        },
    ],

    "permission_resolution": """
        For each Lambda function in this codebase:

        1. Find the Lambda's execution role (CDK creates one per function)
        2. Collect all permission sources:
           a. grant_*() calls on resources pointing to this Lambda
           b. add_to_role_policy() calls on the Lambda
           c. Managed policies attached to the role
        3. Expand wildcards: 's3:*' → all S3 actions, 'bedrock-agentcore:*' → all agentcore actions
        4. Resolve resources: specific ARN vs '*'
        5. Check for deny statements (explicit deny overrides allow)
        6. Check for permission boundaries (caps effective permissions)
    """,

    "compliance_codebase_iam": {
        "agent_lambda_role": {
            "permissions": [
                ("bedrock:InvokeModel", "*"),
                ("bedrock:Retrieve", "*"),
                ("bedrock:RetrieveAndGenerate", "*"),
                ("textract:DetectDocumentText", "*"),
                ("textract:AnalyzeDocument", "*"),
                ("textract:StartDocumentTextDetection", "*"),
                ("textract:GetDocumentTextDetection", "*"),
                ("bedrock-agentcore:*", "*"),
                ("s3:GetObject", "evidence-bucket-arn/*"),
                ("s3:PutObject", "evidence-bucket-arn/*"),
                ("s3:DeleteObject", "evidence-bucket-arn/*"),
                ("s3:ListBucket", "evidence-bucket-arn"),
                ("dynamodb:GetItem", "sessions-table-arn"),
                ("dynamodb:PutItem", "sessions-table-arn"),
                ("dynamodb:UpdateItem", "sessions-table-arn"),
                ("dynamodb:Query", "sessions-table-arn"),
                ("dynamodb:DeleteItem", "sessions-table-arn"),
                ("lambda:InvokeFunction", "agent-v2-arn"),
                ("lambda:InvokeFunction", "agent-v3-arn"),
                ("logs:FilterLogEvents", "*"),
                ("logs:DescribeLogGroups", "*"),
                ("logs:StartQuery", "*"),
                ("logs:GetQueryResults", "*"),
            ],
            "risk_assessment": "HIGH — broad access across multiple services. "
                             "bedrock-agentcore:* is the most concerning (admin-level)."
        },
        "auth_lambda_role": {
            "permissions": [
                ("cognito-idp:AdminCreateUser", "user-pool-arn"),
                ("cognito-idp:AdminSetUserPassword", "user-pool-arn"),
                ("cognito-idp:AdminInitiateAuth", "user-pool-arn"),
                ("cognito-idp:AdminUpdateUserAttributes", "user-pool-arn"),
                ("cognito-idp:AdminGetUser", "user-pool-arn"),
                ("cognito-idp:GlobalSignOut", "user-pool-arn"),
                ("dynamodb:*", "tenants-table-arn"),
                ("dynamodb:*", "policies-table-arn"),
                ("dynamodb:*", "user-tenants-table-arn"),
            ],
            "risk_assessment": "CRITICAL — can create/modify any user in any tenant. "
                             "Cognito admin powers + full DynamoDB access to auth tables."
        },
        "authorizer_lambda_role": {
            "permissions": [
                ("dynamodb:GetItem", "policies-table-arn"),
                ("dynamodb:Query", "policies-table-arn"),
            ],
            "risk_assessment": "LOW (permissions) but CRITICAL (impact) — read-only to policies "
                             "BUT the authorizer's output CONTROLS all downstream access."
        },
    },
}


# =============================================================================
# SKILL 3: Graph Exploration Algorithms (Infrastructure)
# =============================================================================

INFRA_GRAPH_EXPLORATION = {
    "attack_path_enumeration": {
        "description": "Find all paths from INTERNET to high-value targets",
        "algorithm": """
def find_attack_paths(G_net, G_iam, high_value_targets):
    '''
    An attack path exists when:
    1. There's a network path from INTERNET to a resource
    2. The resource (or its role) has permissions to reach the target
    3. Each hop is either network-reachable or IAM-invocable

    Returns paths sorted by: (shortest path first, highest impact first)
    '''
    paths = []

    # Find all internet-facing resources
    internet_facing = list(G_net.successors('INTERNET'))

    for entry in internet_facing:
        for target in high_value_targets:
            # BFS from entry to target using BOTH network and IAM edges
            attack_paths = bfs_with_constraints(
                G_net, G_iam, entry, target,
                constraint=lambda node: has_permission_to_next(node, G_iam)
            )
            for path in attack_paths:
                paths.append(AttackPath(
                    entry_point=entry,
                    target=target,
                    hops=path,
                    hop_count=len(path),
                    requires_auth=has_authorizer_on_path(path, G_net),
                    blast_radius=compute_blast_radius(path[-1], G_net, G_iam)
                ))

    # Sort: unauthenticated paths first, then by hop count
    paths.sort(key=lambda p: (p.requires_auth, p.hop_count))
    return paths
''',
    },

    "blast_radius_computation": {
        "description": "Compute what an attacker can reach from a compromised resource",
        "algorithm": """
def compute_blast_radius(compromised_node, G_net, G_iam):
    '''
    Blast radius = everything reachable via network AND accessible via IAM
    from the compromised node's role.

    BlastRadius(n) = NetworkReachable(n) ∩ IAMAccessible(role_of(n))
    '''
    # What can this node reach via network?
    network_reachable = set(nx.descendants(G_net, compromised_node))

    # What does this node's IAM role allow access to?
    role = G_net.nodes[compromised_node].get('iam_role')
    if not role:
        return network_reachable  # No role = limited by network only

    iam_accessible = set()
    for _, target, data in G_iam.out_edges(role, data=True):
        if data.get('effect') == 'Allow':
            iam_accessible.add(target)

    # Blast radius = intersection (can reach AND has permission)
    blast = network_reachable & iam_accessible

    # Score by sensitivity
    score = sum(
        sensitivity_score(G_net.nodes[r].get('resource_type', ''))
        for r in blast
    )

    return BlastRadius(
        resources=blast,
        score=score,
        network_only=network_reachable - blast,
        iam_only=iam_accessible - blast
    )


def sensitivity_score(resource_type):
    SCORES = {
        'AWS::DynamoDB::Table': 0.8,
        'AWS::S3::Bucket': 0.9,
        'AWS::RDS::DBInstance': 1.0,
        'AWS::SecretsManager::Secret': 1.0,
        'AWS::Cognito::UserPool': 0.9,
        'AWS::Lambda::Function': 0.5,
        'AWS::Logs::LogGroup': 0.3,
    }
    return SCORES.get(resource_type, 0.2)
''',
    },

    "privilege_escalation_paths": {
        "description": "Find paths in IAM graph where a principal can elevate privileges",
        "algorithm": """
def find_escalation_paths(G_iam, escalation_primitives):
    '''
    For each principal, check if their effective permissions include
    any combination that enables privilege escalation.

    An escalation path exists when:
    - Principal has action A (e.g., iam:PassRole)
    - AND there exists a target role with higher permissions
    - AND the principal can reach that role (via PassRole + CreateFunction, etc.)
    '''
    escalation_findings = []

    for principal in get_all_principals(G_iam):
        effective = get_effective_permissions(principal, G_iam)

        for primitive_name, primitive_def in escalation_primitives.items():
            if primitive_def.get('requires_all'):
                required_actions = set(primitive_name.split(' + '))
                if required_actions.issubset(effective.actions):
                    # Check: does the escalation target exist?
                    targets = find_escalation_targets(
                        principal, primitive_def, G_iam
                    )
                    if targets:
                        escalation_findings.append(EscalationFinding(
                            principal=principal,
                            method=primitive_name,
                            targets=targets,
                            severity=primitive_def['severity'],
                            description=primitive_def['description']
                        ))
            else:
                if primitive_name in effective.actions:
                    escalation_findings.append(EscalationFinding(
                        principal=principal,
                        method=primitive_name,
                        severity=primitive_def['severity'],
                        description=primitive_def['description']
                    ))

    return escalation_findings
''',
    },

    "toxic_combination_detection": {
        "description": "Query across all three graphs for compound risk patterns",
        "algorithm": """
def detect_toxic_combinations(G_net, G_iam, G_data, patterns):
    '''
    For each toxic combination pattern:
    1. Evaluate each component predicate against the graphs
    2. Find resource groups where ALL predicates are satisfied
    3. Generate compound finding with elevated severity
    '''
    findings = []

    for pattern in patterns:
        # Evaluate each component
        component_results = []
        for predicate_name in pattern['component_predicates']:
            matching_resources = evaluate_predicate(
                predicate_name, G_net, G_iam, G_data
            )
            component_results.append(matching_resources)

        # Find intersection (resources that satisfy ALL components)
        if all(component_results):
            # For cross-resource patterns: find connected groups
            toxic_groups = find_connected_groups(component_results, G_net)

            for group in toxic_groups:
                findings.append(CompoundFinding(
                    pattern_id=pattern['id'],
                    resources=group,
                    severity=pattern['combined_severity'],
                    narrative=pattern['attack_narrative'],
                    individual_severities=pattern['individual_severity']
                ))

    return findings
''',
    },

    "graph_overlay": {
        "description": "Combine network + IAM graphs for compound analysis",
        "algorithm": """
def build_overlay_graph(G_net, G_iam):
    '''
    Create compound graph where an edge exists only if BOTH
    network connectivity AND IAM permission exist.

    This answers: "What can this resource ACTUALLY do?"
    (not just what it can reach, or what it's permitted — but both)
    '''
    G_overlay = nx.DiGraph()

    for compute_node in get_compute_nodes(G_net):
        role = G_net.nodes[compute_node].get('iam_role')
        if not role:
            continue

        # Network: what can this compute reach?
        net_reachable = set(nx.descendants(G_net, compute_node))

        # IAM: what does this role permit access to?
        iam_targets = set()
        for _, target, data in G_iam.out_edges(role, data=True):
            if data.get('effect') == 'Allow':
                iam_targets.add(target)

        # Overlay: only add edge if BOTH conditions met
        effective_access = net_reachable & iam_targets
        for target in effective_access:
            G_overlay.add_edge(compute_node, target,
                             via_network=True,
                             via_iam=True,
                             actions=get_permitted_actions(role, target, G_iam))

    return G_overlay
''',
    },
}


# =============================================================================
# SKILL 4: Graph Visualization / Serialization for LLM
# =============================================================================

GRAPH_SERIALIZATION = {
    "for_llm_context": {
        "description": "Render graph subsets in LLM-friendly text format",
        "format": """
            Resource Topology (relevant subgraph):
              INTERNET →(public)→ APIGateway-v1
              APIGateway-v1 →(authorizer)→ Authorizer-Lambda
              APIGateway-v1 →(integration)→ Agent-Lambda-v1
              Agent-Lambda-v1 →(read_write)→ Sessions-Table
              Agent-Lambda-v1 →(read_write)→ Evidence-Bucket
              Agent-Lambda-v1 →(invoke)→ Bedrock

            IAM Permissions (for Agent-Lambda-v1):
              Agent-Role:
                → Sessions-Table: [GetItem, PutItem, UpdateItem, Query, DeleteItem]
                → Evidence-Bucket: [GetObject, PutObject, DeleteObject, ListBucket]
                → Bedrock: [InvokeModel, Retrieve, RetrieveAndGenerate]
                → AgentCore: [* (ALL ACTIONS)]  ⚠️ OVERPERMISSIVE
                → CloudWatch: [FilterLogEvents, DescribeLogGroups, StartQuery]

            Attack Path:
              INTERNET → APIGateway → [Authorizer validates JWT] → Agent-Lambda
                → can reach: Sessions-Table (all tenants), Evidence-Bucket (all tenants)
                → blast radius: 9.2/10
        """,
        "token_estimate": "~500-800 tokens for a typical subgraph rendering",
    },

    "for_checkpoint": {
        "description": "Serialize full graph for checkpoint persistence",
        "format": "NetworkX node_link_data JSON format",
        "includes": "All node attributes, all edge attributes, all metadata",
    },
}
