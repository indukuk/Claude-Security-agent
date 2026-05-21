"""
Durable execution engine.
Runs agent steps with persistence, retry, and idempotent resume.
"""
from __future__ import annotations

import time
import logging
import traceback
from typing import Callable, Any

from v3.harness.state_store import StateStore, AgentStep

logger = logging.getLogger(__name__)


class ExecutionError(Exception):
    pass


class BudgetExhausted(Exception):
    pass


class DurableExecutor:
    """
    Executes agent steps with:
    - Idempotent resume (skip completed steps)
    - Retry on failure (with backoff)
    - External state persistence
    - Circuit breaker (stop after N consecutive failures)
    """

    def __init__(self, state_store: StateStore, max_retries: int = 2,
                 circuit_breaker_threshold: int = 3):
        self.store = state_store
        self.max_retries = max_retries
        self.circuit_breaker_threshold = circuit_breaker_threshold
        self._consecutive_failures = 0

    def execute(self, agent_id: str, step_name: str,
                fn: Callable[[dict], dict], input_data: dict) -> dict:
        """
        Execute a step durably.
        - If already completed: return cached result (idempotent)
        - If failed with retries left: retry
        - If circuit breaker tripped: raise
        """
        # Circuit breaker check
        if self._consecutive_failures >= self.circuit_breaker_threshold:
            raise ExecutionError(
                f"Circuit breaker tripped: {self._consecutive_failures} consecutive failures"
            )

        # Idempotent: skip if already done
        existing = self.store.get(agent_id, step_name)
        if existing and existing.status == "completed":
            logger.debug(f"Step already complete: {agent_id}/{step_name}")
            self._consecutive_failures = 0
            return existing.output_data

        # Create or resume step
        step = existing or AgentStep(
            agent_id=agent_id,
            step_name=step_name,
            input_data=input_data,
        )

        step.status = "running"
        step.started_at = time.strftime("%Y-%m-%dT%H:%M:%S")
        self.store.save(step)

        start_time = time.time()

        try:
            result = fn(input_data)
            elapsed = int((time.time() - start_time) * 1000)

            step.output_data = result
            step.status = "completed"
            step.completed_at = time.strftime("%Y-%m-%dT%H:%M:%S")
            step.duration_ms = elapsed
            self.store.save(step)

            self._consecutive_failures = 0
            logger.info(f"Step complete: {agent_id}/{step_name} ({elapsed}ms)")
            return result

        except Exception as e:
            elapsed = int((time.time() - start_time) * 1000)
            step.duration_ms = elapsed
            step.error = str(e)

            if step.retry_count < self.max_retries:
                step.retry_count += 1
                step.status = "pending"
                self.store.save(step)

                wait = 2 ** step.retry_count
                logger.warning(
                    f"Step failed: {agent_id}/{step_name} "
                    f"(retry {step.retry_count}/{self.max_retries} in {wait}s): {e}"
                )
                time.sleep(wait)
                return self.execute(agent_id, step_name, fn, input_data)
            else:
                step.status = "failed"
                self.store.save(step)
                self._consecutive_failures += 1
                logger.error(f"Step failed permanently: {agent_id}/{step_name}: {e}")
                raise ExecutionError(f"{agent_id}/{step_name} failed: {e}") from e
