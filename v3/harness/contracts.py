"""
Agent contracts — explicit interfaces between agents.
Each agent declares its inputs, outputs, and capabilities.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentContract:
    """Defines what an agent expects and produces."""
    agent_name: str
    stage: str  # generator | verifier | prover
    description: str
    input_fields: list[str]
    output_fields: list[str]
    tools_allowed: list[str]
    deliberation_budget: int  # extended thinking tokens
    persona: str = ""


# ═══════════════════════════════════════════════════════════════
# Stage 1: Generator Contracts
# ═══════════════════════════════════════════════════════════════

CROSS_TENANT_SCANNER = AgentContract(
    agent_name="cross_tenant_scanner",
    stage="generator",
    description="Detects cross-tenant data access via user-controlled tenant/customer IDs",
    input_fields=["file_path", "source_code", "semgrep_findings", "auth_context_usage"],
    output_fields=["candidates"],
    tools_allowed=["read_file", "grep_pattern", "query_semgrep"],
    deliberation_budget=4000,
    persona="You are a security engineer specializing in multi-tenant isolation failures.",
)

IAM_ESCALATION_SCANNER = AgentContract(
    agent_name="iam_escalation_scanner",
    stage="generator",
    description="Detects IAM privilege escalation paths and overpermissive roles",
    input_fields=["cdk_source", "iam_graph"],
    output_fields=["candidates"],
    tools_allowed=["read_cdk", "query_iam_graph", "check_escalation_primitives"],
    deliberation_budget=4000,
    persona="You are an AWS IAM security specialist focused on privilege escalation.",
)

DOM_XSS_SCANNER = AgentContract(
    agent_name="dom_xss_scanner",
    stage="generator",
    description="Detects DOM XSS via innerHTML with API response data",
    input_fields=["js_files", "semgrep_findings"],
    output_fields=["candidates"],
    tools_allowed=["read_file", "grep_pattern", "trace_data_source"],
    deliberation_budget=4000,
    persona="You are a frontend security engineer specializing in DOM XSS.",
)

PROMPT_INJECTION_SCANNER = AgentContract(
    agent_name="prompt_injection_scanner",
    stage="generator",
    description="Detects prompt injection paths from user messages to tool execution",
    input_fields=["graph_source", "agent_config", "state_definition"],
    output_fields=["candidates"],
    tools_allowed=["read_file", "trace_state_flow", "check_permission_gates"],
    deliberation_budget=6000,
    persona="You are an AI security researcher specializing in LLM agent attacks.",
)

GRAPH_TOPOLOGY_SCANNER = AgentContract(
    agent_name="graph_topology_scanner",
    stage="generator",
    description="Detects missing permission checks in LangGraph routing topology",
    input_fields=["graph_source", "permissions_source"],
    output_fields=["candidates"],
    tools_allowed=["read_file", "parse_graph_edges", "check_permission_nodes"],
    deliberation_budget=4000,
    persona="You are a security architect analyzing agentic workflow authorization.",
)

INFRA_SCANNER = AgentContract(
    agent_name="infra_scanner",
    stage="generator",
    description="Detects infrastructure misconfigurations, encryption gaps, logging failures",
    input_fields=["cdk_stacks", "resource_graph"],
    output_fields=["candidates"],
    tools_allowed=["read_cdk", "check_encryption", "check_logging", "check_versioning"],
    deliberation_budget=2000,
    persona="You are a cloud security engineer reviewing AWS CDK infrastructure.",
)

COMPOUND_SCANNER = AgentContract(
    agent_name="compound_scanner",
    stage="generator",
    description="Detects toxic combinations across app + infra boundaries",
    input_fields=["all_stage1_candidates", "iam_graph", "resource_graph"],
    output_fields=["candidates"],
    tools_allowed=["query_all_findings", "check_defense_in_depth"],
    deliberation_budget=6000,
    persona="You are a threat modeling expert looking for defense-in-depth failures.",
)

# ═══════════════════════════════════════════════════════════════
# Stage 2: Verifier Contracts
# ═══════════════════════════════════════════════════════════════

PROSECUTOR = AgentContract(
    agent_name="prosecutor",
    stage="verifier",
    description="Argues that a finding IS a genuine, exploitable vulnerability",
    input_fields=["finding", "source_code", "context"],
    output_fields=["argument", "evidence_cited", "exploit_scenario"],
    tools_allowed=["read_file", "grep_pattern", "check_reachability"],
    deliberation_budget=8000,
    persona=(
        "You are a penetration tester. Your job is to PROVE this vulnerability is real "
        "and exploitable. Cite specific code lines. Describe the exact attack steps. "
        "Be aggressive in your argument — show how each defense fails."
    ),
)

DEFENDER = AgentContract(
    agent_name="defender",
    stage="verifier",
    description="Argues that a finding is NOT exploitable (false positive or mitigated)",
    input_fields=["finding", "source_code", "context", "framework_protections"],
    output_fields=["argument", "mitigations_cited", "why_safe"],
    tools_allowed=["read_file", "grep_pattern", "check_protections"],
    deliberation_budget=8000,
    persona=(
        "You are a defense counsel for the development team. Your job is to argue this "
        "finding is NOT exploitable. Look for: framework protections, environmental "
        "controls, type constraints, authentication gates, compensating controls. "
        "Be thorough — if there's ANY reason this is safe, find it."
    ),
)

JUDGE = AgentContract(
    agent_name="judge",
    stage="verifier",
    description="Evaluates prosecution and defense arguments, renders final verdict",
    input_fields=["finding", "prosecution_case", "defense_case"],
    output_fields=["verdict", "confidence", "reasoning", "severity"],
    tools_allowed=["read_file"],  # Minimal tools — judge reasons, doesn't investigate
    deliberation_budget=16000,
    persona=(
        "You are a senior security architect acting as an impartial judge. "
        "You have heard arguments from both the prosecution (this is exploitable) "
        "and the defense (this is not exploitable). Evaluate BOTH sides fairly. "
        "Consider: quality of evidence cited, logical consistency, whether mitigations "
        "fully prevent exploitation or only partially. "
        "Render verdict: CONFIRMED (with severity) or DISMISSED (with reason). "
        "You must explain which arguments were strongest and why."
    ),
)

# ═══════════════════════════════════════════════════════════════
# Stage 3: Prover Contracts
# ═══════════════════════════════════════════════════════════════

EXPLOIT_GENERATOR = AgentContract(
    agent_name="exploit_generator",
    stage="prover",
    description="Generates proof-of-concept exploit code for verified findings",
    input_fields=["verified_finding", "source_code", "api_info"],
    output_fields=["exploit_code", "expected_outcome", "prerequisites"],
    tools_allowed=["read_file", "generate_code"],
    deliberation_budget=12000,
    persona=(
        "You are an exploit developer. Generate a WORKING proof-of-concept that "
        "demonstrates the vulnerability. Output: executable code (curl commands, "
        "Python script, or test case) with comments explaining each step."
    ),
)

REMEDIATION_GENERATOR = AgentContract(
    agent_name="remediation_generator",
    stage="prover",
    description="Generates minimal code fix for verified findings",
    input_fields=["verified_finding", "source_code", "exploit"],
    output_fields=["fix_diff", "explanation", "breaking_changes"],
    tools_allowed=["read_file", "generate_code"],
    deliberation_budget=8000,
    persona=(
        "You are a senior developer. Generate the MINIMAL code change that fixes "
        "the vulnerability without breaking functionality. Output as a diff. "
        "Explain why this fix works and note any potential side effects."
    ),
)

FIX_VALIDATOR = AgentContract(
    agent_name="fix_validator",
    stage="prover",
    description="Validates that a proposed fix resolves the vulnerability",
    input_fields=["original_code", "fixed_code", "semgrep_rule"],
    output_fields=["passes", "new_issues", "regression_check"],
    tools_allowed=["run_semgrep_on_code"],
    deliberation_budget=4000,
    persona="You validate that security fixes work correctly without introducing regressions.",
)


# ═══════════════════════════════════════════════════════════════
# All contracts registry
# ═══════════════════════════════════════════════════════════════

ALL_CONTRACTS = {
    # Generators
    "cross_tenant_scanner": CROSS_TENANT_SCANNER,
    "iam_escalation_scanner": IAM_ESCALATION_SCANNER,
    "dom_xss_scanner": DOM_XSS_SCANNER,
    "prompt_injection_scanner": PROMPT_INJECTION_SCANNER,
    "graph_topology_scanner": GRAPH_TOPOLOGY_SCANNER,
    "infra_scanner": INFRA_SCANNER,
    "compound_scanner": COMPOUND_SCANNER,
    # Verifiers
    "prosecutor": PROSECUTOR,
    "defender": DEFENDER,
    "judge": JUDGE,
    # Provers
    "exploit_generator": EXPLOIT_GENERATOR,
    "remediation_generator": REMEDIATION_GENERATOR,
    "fix_validator": FIX_VALIDATOR,
}
