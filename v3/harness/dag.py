"""
DAG-based parallel execution.
Runs independent agents concurrently, respects dependencies.
"""
from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Any

from v3.harness.execution import DurableExecutor
from v3.harness.state_store import StateStore

logger = logging.getLogger(__name__)


@dataclass
class DAGNode:
    """A node in the execution DAG."""
    name: str
    fn: Callable[[dict], dict]
    input_data: dict = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    output: dict | None = None
    status: str = "pending"  # pending | running | completed | failed


class DAGExecutor:
    """
    Execute a DAG of agent steps.
    - Independent nodes run in parallel
    - Dependent nodes wait for their prerequisites
    - Uses DurableExecutor for each node (retry, checkpoint)
    """

    def __init__(self, executor: DurableExecutor, max_workers: int = 4):
        self.executor = executor
        self.max_workers = max_workers

    def execute_dag(self, agent_id: str, nodes: list[DAGNode]) -> dict[str, Any]:
        """
        Execute all nodes in the DAG, respecting dependencies.
        Returns: {node_name: output} for all completed nodes.
        """
        results: dict[str, Any] = {}
        node_map = {n.name: n for n in nodes}
        completed = set()
        failed = set()

        while len(completed) + len(failed) < len(nodes):
            # Find ready nodes (all deps satisfied)
            ready = [
                n for n in nodes
                if n.name not in completed
                and n.name not in failed
                and n.status == "pending"
                and all(d in completed for d in n.depends_on)
            ]

            if not ready:
                if len(completed) + len(failed) < len(nodes):
                    # Deadlock or all remaining have failed deps
                    remaining = [n.name for n in nodes if n.name not in completed and n.name not in failed]
                    logger.warning(f"Cannot make progress. Remaining: {remaining}")
                    break
                break

            # Execute ready nodes (parallel if multiple)
            if len(ready) == 1:
                node = ready[0]
                self._execute_node(agent_id, node, results)
                if node.status == "completed":
                    completed.add(node.name)
                    results[node.name] = node.output
                else:
                    failed.add(node.name)
            else:
                # Parallel execution
                with ThreadPoolExecutor(max_workers=min(self.max_workers, len(ready))) as pool:
                    futures = {
                        pool.submit(self._execute_node, agent_id, node, results): node
                        for node in ready
                    }
                    for future in as_completed(futures):
                        node = futures[future]
                        try:
                            future.result()
                            if node.status == "completed":
                                completed.add(node.name)
                                results[node.name] = node.output
                            else:
                                failed.add(node.name)
                        except Exception as e:
                            node.status = "failed"
                            failed.add(node.name)
                            logger.error(f"Node {node.name} failed: {e}")

        logger.info(
            f"DAG execution complete: {len(completed)} completed, "
            f"{len(failed)} failed, {len(nodes) - len(completed) - len(failed)} skipped"
        )
        return results

    def _execute_node(self, agent_id: str, node: DAGNode, prior_results: dict):
        """Execute a single DAG node via durable executor."""
        # Inject dependency outputs into input
        enriched_input = dict(node.input_data)
        for dep_name in node.depends_on:
            if dep_name in prior_results:
                enriched_input[f"from_{dep_name}"] = prior_results[dep_name]

        node.status = "running"
        try:
            result = self.executor.execute(
                agent_id=agent_id,
                step_name=node.name,
                fn=node.fn,
                input_data=enriched_input,
            )
            node.output = result
            node.status = "completed"
        except Exception as e:
            node.status = "failed"
            logger.error(f"DAG node {node.name} failed: {e}")
            raise
