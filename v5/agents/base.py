"""
V5 Agent Framework — LLM agents with tool use, extended thinking, and multi-round investigation.

Each agent:
- Receives the full evidence package as context
- Can use tools to read files, query CPG, run Z3 checks
- Has unlimited thinking budget (extended thinking / scratchpad)
- Can run multiple investigation rounds (follow-up on discoveries)
- Produces a structured investigation report

The framework supports both Bedrock API calls and in-session execution
(where Claude Code IS the LLM, processing the agent's prompt directly).
"""
from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass
class ToolCall:
    """A tool invocation by an agent."""
    name: str
    args: dict
    result: str = ""


@dataclass
class InvestigationRound:
    """One round of investigation by an agent."""
    round_number: int
    thinking: str  # Extended thinking / scratchpad
    tool_calls: list[ToolCall] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    next_questions: list[str] = field(default_factory=list)


@dataclass
class InvestigationReport:
    """Complete investigation output from an agent."""
    agent_name: str
    domain: str
    rounds: list[InvestigationRound] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    verified_claims: list[str] = field(default_factory=list)
    unverified_claims: list[str] = field(default_factory=list)
    summary: str = ""
    raw_output: str = ""


@dataclass
class AgentContext:
    """Context provided to each investigation agent."""
    # Source code
    file_contents: dict[str, str]
    handler_files: list[str]

    # V4 evidence
    cpg_summary: str  # CPG statistics + key paths
    semgrep_findings: list[dict]
    evidence_walks: list[str]  # Rendered walk text
    absence_findings: list[dict]
    differential_findings: list[dict]
    attack_chains: list[str]  # Rendered chain text

    # Infrastructure
    infra_graph_summary: str
    z3_proofs: list[dict]
    blast_radii: list[dict]
    lateral_paths: list[dict]

    # CDK source
    cdk_source: str

    def to_prompt_context(self, max_chars: int = 200000) -> str:
        """Render context as a prompt section for the LLM."""
        sections = []

        sections.append("## Source Code (Handler Files)")
        for fpath in self.handler_files[:10]:
            content = self.file_contents.get(fpath, "")
            fname = Path(fpath).name
            if content:
                sections.append(f"\n### {fname}\n```python\n{content[:8000]}\n```")

        sections.append("\n## CPG Analysis")
        sections.append(self.cpg_summary)

        if self.semgrep_findings:
            sections.append("\n## Semgrep Findings")
            for f in self.semgrep_findings[:20]:
                sections.append(f"- [{f.get('severity')}] {f.get('title')} at {Path(f.get('file_path','')).name}:{f.get('line')}")

        if self.evidence_walks:
            sections.append("\n## Evidence Walks")
            for walk in self.evidence_walks[:10]:
                sections.append(f"```\n{walk}\n```")

        if self.absence_findings:
            sections.append("\n## Missing Controls (Absence Detection)")
            for f in self.absence_findings:
                sections.append(f"- [{f.get('severity')}] {f.get('title')}")

        if self.differential_findings:
            sections.append("\n## Inconsistent Security Controls (Differential)")
            for f in self.differential_findings:
                sections.append(f"- [{f.get('severity')}] {f.get('title')}")

        if self.z3_proofs:
            sections.append("\n## Z3 Formal Proofs")
            for p in self.z3_proofs[:10]:
                sections.append(f"- [{p.get('severity')}] {p.get('title')}")
                if p.get('z3_proof'):
                    sections.append(f"  Proof: {p['z3_proof'][:200]}")

        if self.blast_radii:
            sections.append("\n## Zero Trust — Blast Radii")
            for br in self.blast_radii:
                sections.append(
                    f"- {br['role']}: {br['score']}% | {br['status']} | "
                    f"{'INTERNET-FACING' if br['internet_facing'] else 'internal'} | "
                    f"auth={br['auth']}"
                )

        if self.lateral_paths:
            sections.append("\n## Lateral Movement Paths")
            for lp in self.lateral_paths[:15]:
                sections.append(f"- {lp['source']} → {lp['target']} ({lp['mechanism']})")

        if self.attack_chains:
            sections.append("\n## Attack Chains")
            for chain in self.attack_chains[:5]:
                sections.append(chain)

        if self.cdk_source:
            sections.append("\n## CDK Infrastructure Source")
            sections.append(f"```python\n{self.cdk_source[:10000]}\n```")

        full = "\n".join(sections)
        if len(full) > max_chars:
            full = full[:max_chars] + "\n\n... (truncated)"
        return full


class InvestigationAgent(ABC):
    """
    Base class for V5 investigation agents.

    Subclasses implement domain-specific investigation logic.
    The framework handles tool execution, multi-round iteration,
    and report assembly.
    """

    def __init__(self, name: str, domain: str):
        self.name = name
        self.domain = domain
        self._tools: dict[str, Callable] = {}
        self._file_contents: dict[str, str] = {}

    @abstractmethod
    def get_system_prompt(self) -> str:
        """Return the agent's system prompt (persona + mandate)."""
        ...

    @abstractmethod
    def get_investigation_prompt(self, context: AgentContext) -> str:
        """Return the investigation prompt with context."""
        ...

    def register_tool(self, name: str, fn: Callable):
        """Register a tool the agent can use."""
        self._tools[name] = fn

    def investigate(self, context: AgentContext, llm_fn: Callable | None = None) -> InvestigationReport:
        """
        Run the investigation.

        If llm_fn is provided, calls the LLM API.
        If not, produces the prompt for in-session execution by Claude Code.
        """
        report = InvestigationReport(agent_name=self.name, domain=self.domain)

        system = self.get_system_prompt()
        user = self.get_investigation_prompt(context)

        if llm_fn:
            # API mode: call LLM with tools
            response = llm_fn(
                system=system,
                user=user,
                tools=list(self._tools.keys()),
            )
            report.raw_output = response
            report.findings = self._parse_findings(response)
            report.summary = self._extract_summary(response)
        else:
            # In-session mode: output the prompt for Claude Code to process
            report.raw_output = f"## {self.name}\n\n{system}\n\n---\n\n{user}"
            report.summary = "(Awaiting LLM processing)"

        return report

    def generate_prompt_for_session(self, context: AgentContext) -> str:
        """Generate the full prompt for in-session execution."""
        system = self.get_system_prompt()
        user = self.get_investigation_prompt(context)
        return f"{system}\n\n---\n\n{user}"

    def _parse_findings(self, response: str) -> list[dict]:
        """Parse findings from LLM response."""
        findings = []
        try:
            # Try to find JSON blocks in response
            start = response.find("[")
            end = response.rfind("]") + 1
            if start >= 0 and end > start:
                findings = json.loads(response[start:end])
        except (json.JSONDecodeError, ValueError):
            pass
        return findings

    def _extract_summary(self, response: str) -> str:
        """Extract summary section from response."""
        if "## Summary" in response:
            idx = response.index("## Summary")
            return response[idx:idx+500]
        return response[:500]


class LLMClient:
    """
    Client for calling Claude via Bedrock.
    Supports extended thinking and tool use.
    """

    def __init__(self, model_id: str = "us.anthropic.claude-sonnet-4-6-20250514-v1:0",
                 region: str = "us-west-2"):
        self.model_id = model_id
        self.region = region
        self._client = None

    def _get_client(self):
        if self._client is None:
            import boto3
            self._client = boto3.client("bedrock-runtime", region_name=self.region)
        return self._client

    def invoke(self, system: str, user: str, tools: list[str] | None = None,
               max_tokens: int = 16000) -> str:
        """Invoke Claude with the given prompts."""
        client = self._get_client()

        messages = [{"role": "user", "content": [{"type": "text", "text": user}]}]

        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "system": [{"type": "text", "text": system}],
            "messages": messages,
        }

        response = client.invoke_model(
            modelId=self.model_id,
            body=json.dumps(body),
        )

        result = json.loads(response["body"].read())
        text_blocks = [b["text"] for b in result.get("content", []) if b.get("type") == "text"]
        return "\n".join(text_blocks)
