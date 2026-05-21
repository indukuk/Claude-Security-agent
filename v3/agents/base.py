"""
BaseAgent interface — all agents implement this contract.
Enables model-swapping, consistent orchestration, and interoperability.
"""
from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from v3.harness.contracts import AgentContract

logger = logging.getLogger(__name__)


@dataclass
class AgentResult:
    """Standard output from any agent."""
    agent_name: str
    status: str  # completed | failed | partial
    output: dict
    reasoning: str = ""
    tools_used: list[str] = field(default_factory=list)
    tokens_used: int = 0
    duration_ms: int = 0


@dataclass
class CandidateFinding:
    """Output from a generator agent."""
    id: str
    scanner: str
    title: str
    severity: str
    confidence: float
    evidence: str
    file_path: str
    line: int
    cwe: str = ""
    category: str = ""
    context: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scanner": self.scanner,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "file_path": self.file_path,
            "line": self.line,
            "cwe": self.cwe,
            "category": self.category,
        }


@dataclass
class Verdict:
    """Output from the verifier (debate) stage."""
    finding_id: str
    decision: str  # CONFIRMED | DISMISSED
    severity: str
    confidence: float
    prosecution_summary: str
    defense_summary: str
    judge_reasoning: str
    exploit_feasible: bool = False


@dataclass
class Proof:
    """Output from the prover stage."""
    finding_id: str
    exploit_code: str
    exploit_works: bool
    fix_code: str
    fix_validated: bool
    fix_explanation: str


class BaseAgent(ABC):
    """
    All agents implement this interface.
    The harness interacts with agents exclusively through this contract.
    """

    def __init__(self, contract: AgentContract):
        self.contract = contract
        self.name = contract.agent_name
        self.stage = contract.stage

    @abstractmethod
    def execute(self, input_data: dict) -> dict:
        """
        Execute the agent's task.
        Input/output must conform to the contract schema.
        """
        ...

    def validate_input(self, input_data: dict) -> bool:
        """Verify input has required fields."""
        for field_name in self.contract.input_fields:
            if field_name not in input_data:
                logger.warning(f"{self.name}: missing input field '{field_name}'")
                return False
        return True

    def validate_output(self, output: dict) -> bool:
        """Verify output has required fields."""
        for field_name in self.contract.output_fields:
            if field_name not in output:
                logger.warning(f"{self.name}: missing output field '{field_name}'")
                return False
        return True


class ClaudeAgent(BaseAgent):
    """
    Agent that uses Claude (via API or in-session) for reasoning.
    Generates a structured prompt from contract + input, gets response.
    """

    def __init__(self, contract: AgentContract, llm_fn=None):
        super().__init__(contract)
        self.llm_fn = llm_fn  # Function that calls Claude (API or in-session)

    def execute(self, input_data: dict) -> dict:
        """Execute by constructing prompt and calling LLM."""
        if not self.validate_input(input_data):
            return {"error": f"Invalid input for {self.name}"}

        prompt = self._build_prompt(input_data)

        if self.llm_fn:
            response = self.llm_fn(
                system=self.contract.persona,
                user=prompt,
                budget=self.contract.deliberation_budget,
            )
        else:
            # In-session mode: output prompt for Claude to process
            response = self._in_session_execute(prompt)

        output = self._parse_response(response)

        if not self.validate_output(output):
            logger.warning(f"{self.name}: output validation failed, returning raw")

        return output

    def _build_prompt(self, input_data: dict) -> str:
        """Build the prompt from contract + input data."""
        sections = [
            f"## Agent: {self.name}",
            f"## Task: {self.contract.description}",
            "",
            "## Input:",
        ]

        for field_name in self.contract.input_fields:
            value = input_data.get(field_name, "")
            if isinstance(value, str) and len(value) > 2000:
                value = value[:2000] + "\n... (truncated)"
            elif isinstance(value, (list, dict)):
                value = json.dumps(value, indent=2)[:2000]
            sections.append(f"### {field_name}:")
            sections.append(str(value))
            sections.append("")

        sections.append("## Expected Output Fields:")
        for field_name in self.contract.output_fields:
            sections.append(f"- {field_name}")

        sections.append("")
        sections.append("## Instructions:")
        sections.append("Analyze the input and produce the expected output fields.")
        sections.append("Be specific, cite evidence, include line numbers.")

        return "\n".join(sections)

    def _parse_response(self, response: str) -> dict:
        """Parse LLM response into structured output."""
        # Try to extract JSON from response
        try:
            start = response.find("{")
            end = response.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(response[start:end])
        except (json.JSONDecodeError, ValueError):
            pass

        # Fallback: return as text in first output field
        if self.contract.output_fields:
            return {self.contract.output_fields[0]: response}
        return {"raw_response": response}

    def _in_session_execute(self, prompt: str) -> str:
        """For in-session mode: return the prompt (Claude will process it)."""
        return prompt


class DeterministicAgent(BaseAgent):
    """
    Agent that runs deterministic analysis (no LLM).
    Used for Semgrep, infrastructure checks, graph queries.
    """

    def __init__(self, contract: AgentContract, analysis_fn: callable):
        super().__init__(contract)
        self.analysis_fn = analysis_fn

    def execute(self, input_data: dict) -> dict:
        """Execute deterministic analysis."""
        return self.analysis_fn(input_data)
