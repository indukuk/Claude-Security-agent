"""
Base agent class — shared interface for all specialized agents.
"""
from __future__ import annotations


import logging
import time
from abc import ABC, abstractmethod

from src.common.config import ScanConfig
from src.common.findings import Finding, CoverageMetrics
from src.common.checkpoint import AgentState, CheckpointManager
from src.common.llm_client import LLMClient

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """
    All agents implement this interface.
    The orchestrator dispatches to agents via this contract.
    """

    def __init__(self, config: ScanConfig, llm_client: LLMClient):
        self.config = config
        self.llm = llm_client
        self.checkpoint_mgr = CheckpointManager(str(config.checkpoint_path))
        self.state: AgentState | None = None

    @property
    @abstractmethod
    def agent_type(self) -> str:
        """Unique identifier: 'python', 'javascript', 'infrastructure', 'validation'"""
        ...

    @property
    @abstractmethod
    def agent_id(self) -> str:
        """Instance identifier for checkpointing."""
        ...

    def run(self, directories: list[str], budget: float) -> list[Finding]:
        """
        Main entry point. Runs all phases, checkpoints between each.
        Returns candidate findings (pre-validation).
        """
        # Check for existing checkpoint
        if self.checkpoint_mgr.can_resume(self.agent_id):
            logger.info(f"Resuming {self.agent_type} agent from checkpoint")
            self.state = self.checkpoint_mgr.load_latest(self.agent_id)
        else:
            self.state = AgentState(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                status="running",
                cost_budget=budget,
                started_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
            )

        self.state.status = "running"

        try:
            findings = self._execute_phases(directories)
            self.state.status = "complete"
            self.state.candidate_findings = [f.to_dict() for f in findings]
            self.checkpoint_mgr.save(self.state)
            return findings

        except Exception as e:
            logger.error(f"{self.agent_type} agent failed: {e}", exc_info=True)
            self.state.status = "failed"
            self.state.error = str(e)
            self.checkpoint_mgr.save(self.state)
            raise

    @abstractmethod
    def _execute_phases(self, directories: list[str]) -> list[Finding]:
        """Execute all analysis phases. Subclasses implement this."""
        ...

    def _save_checkpoint(self):
        """Save current state as checkpoint."""
        self.state.cost_incurred = self.llm.total_cost
        self.checkpoint_mgr.save(self.state)
