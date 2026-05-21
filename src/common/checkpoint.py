"""
Checkpoint system for scan resumability.
Guarantees: no work lost, no work repeated.
"""
from __future__ import annotations


import json
import os
import time
import glob
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from src.common.findings import Finding, CoverageMetrics, Severity, Confidence

logger = logging.getLogger(__name__)


@dataclass
class AgentState:
    agent_id: str
    agent_type: str
    status: str = "idle"  # idle | running | checkpointed | complete | failed
    phase: int = 0
    chunk_index: int = 0
    graph: dict | None = None
    inferred_specs: dict | None = None
    deterministic_findings: list[dict] = field(default_factory=list)
    candidate_findings: list[dict] = field(default_factory=list)
    validated_findings: list[dict] = field(default_factory=list)
    pending_analysis: list[str] = field(default_factory=list)
    coverage: dict = field(default_factory=dict)
    cost_incurred: float = 0.0
    cost_budget: float = 0.0
    started_at: str = ""
    last_checkpoint: str = ""
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "AgentState":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class CheckpointManager:
    def __init__(self, checkpoint_dir: str):
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

    def save(self, state: AgentState):
        state.last_checkpoint = time.strftime("%Y-%m-%dT%H:%M:%S")

        filename = f"{state.agent_id}_phase{state.phase}_chunk{state.chunk_index}.json"
        checkpoint_path = self.checkpoint_dir / filename
        temp_path = checkpoint_path.with_suffix(".tmp")

        with open(temp_path, "w") as f:
            json.dump(state.to_dict(), f, indent=2, default=str)

        os.rename(temp_path, checkpoint_path)
        self._prune_old(state.agent_id, keep=3)

        logger.info(f"Checkpoint saved: {filename}")

    def load_latest(self, agent_id: str) -> AgentState | None:
        pattern = str(self.checkpoint_dir / f"{agent_id}_*.json")
        checkpoints = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)

        if not checkpoints:
            return None

        with open(checkpoints[0]) as f:
            data = json.load(f)

        logger.info(f"Loaded checkpoint: {checkpoints[0]}")
        return AgentState.from_dict(data)

    def can_resume(self, agent_id: str) -> bool:
        state = self.load_latest(agent_id)
        return state is not None and state.status not in ("complete", "idle")

    def _prune_old(self, agent_id: str, keep: int = 3):
        pattern = str(self.checkpoint_dir / f"{agent_id}_*.json")
        checkpoints = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)

        for old in checkpoints[keep:]:
            os.remove(old)
