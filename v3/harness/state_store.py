"""
Durable state store — external state persistence.
Every agent step is saved. System resumes from last successful step on failure.
"""
from __future__ import annotations

import json
import time
import os
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class AgentStep:
    agent_id: str
    step_name: str
    input_data: dict
    output_data: dict | None = None
    status: str = "pending"  # pending | running | completed | failed
    started_at: str = ""
    completed_at: str | None = None
    retry_count: int = 0
    error: str | None = None
    duration_ms: int = 0


class StateStore:
    """File-backed durable state store."""

    def __init__(self, store_dir: str):
        self.store_dir = Path(store_dir)
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self._state: dict[str, dict[str, AgentStep]] = {}
        self._load()

    def _load(self):
        state_file = self.store_dir / "state.json"
        if state_file.exists():
            raw = json.loads(state_file.read_text())
            for agent_id, steps in raw.items():
                self._state[agent_id] = {}
                for step_name, step_data in steps.items():
                    self._state[agent_id][step_name] = AgentStep(**step_data)

    def _persist(self):
        import threading
        state_file = self.store_dir / "state.json"
        raw = {}
        for agent_id, steps in self._state.items():
            raw[agent_id] = {name: asdict(step) for name, step in steps.items()}
        # Use thread-unique temp file to avoid race condition
        tid = threading.current_thread().ident or 0
        temp = self.store_dir / f"state_{tid}.tmp"
        temp.write_text(json.dumps(raw, indent=2, default=str))
        try:
            os.rename(temp, state_file)
        except OSError:
            # Fallback: direct write if rename fails
            state_file.write_text(json.dumps(raw, indent=2, default=str))
            temp.unlink(missing_ok=True)

    def get(self, agent_id: str, step_name: str) -> AgentStep | None:
        return self._state.get(agent_id, {}).get(step_name)

    def save(self, step: AgentStep):
        if step.agent_id not in self._state:
            self._state[step.agent_id] = {}
        self._state[step.agent_id][step.step_name] = step
        self._persist()

    def get_all_steps(self, agent_id: str) -> list[AgentStep]:
        return list(self._state.get(agent_id, {}).values())

    def get_completed_outputs(self, agent_id: str) -> dict[str, Any]:
        """Get all completed step outputs for an agent."""
        outputs = {}
        for name, step in self._state.get(agent_id, {}).items():
            if step.status == "completed" and step.output_data:
                outputs[name] = step.output_data
        return outputs

    def is_step_complete(self, agent_id: str, step_name: str) -> bool:
        step = self.get(agent_id, step_name)
        return step is not None and step.status == "completed"

    def reset_agent(self, agent_id: str):
        """Reset all steps for an agent (for re-run)."""
        if agent_id in self._state:
            del self._state[agent_id]
            self._persist()

    def get_scan_summary(self) -> dict:
        """Summary of all agent states."""
        summary = {}
        for agent_id, steps in self._state.items():
            completed = sum(1 for s in steps.values() if s.status == "completed")
            failed = sum(1 for s in steps.values() if s.status == "failed")
            total = len(steps)
            summary[agent_id] = {
                "total_steps": total,
                "completed": completed,
                "failed": failed,
                "progress": f"{completed}/{total}",
            }
        return summary
