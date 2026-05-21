"""
Token budget management and chunk creation.
Groups taint paths into LLM-friendly chunks respecting token limits.
"""
from __future__ import annotations


import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class TaintPath:
    source: str
    sink: str
    path_nodes: list[str]
    risk_score: float = 0.0
    estimated_tokens: int = 0
    cwe: str = ""
    category: str = ""

    @property
    def length(self) -> int:
        return len(self.path_nodes)


@dataclass
class AnalysisChunk:
    paths: list[TaintPath] = field(default_factory=list)
    total_tokens: int = 0
    chunk_id: int = 0

    def add_path(self, path: TaintPath):
        self.paths.append(path)
        self.total_tokens += path.estimated_tokens

    def shared_nodes(self, path: TaintPath) -> float:
        """Fraction of path's nodes already in this chunk."""
        if not self.paths:
            return 0.0
        existing_nodes = set()
        for p in self.paths:
            existing_nodes.update(p.path_nodes)
        overlap = len(set(path.path_nodes) & existing_nodes)
        return overlap / max(len(path.path_nodes), 1)


def prioritize_paths(paths: list[TaintPath], budget: int) -> list[TaintPath]:
    """
    Knapsack-like prioritization: maximize risk coverage within token budget.
    Greedy approximation: sort by risk_score/token_cost ratio.
    """
    for path in paths:
        if path.estimated_tokens == 0:
            path.estimated_tokens = max(len(path.path_nodes) * 100, 500)

    scored = sorted(
        paths,
        key=lambda p: p.risk_score / max(p.estimated_tokens, 1),
        reverse=True,
    )

    selected = []
    total = 0
    for path in scored:
        if total + path.estimated_tokens <= budget:
            selected.append(path)
            total += path.estimated_tokens

    logger.info(
        f"Prioritized {len(selected)}/{len(paths)} paths within {budget} token budget "
        f"(risk coverage: {sum(p.risk_score for p in selected):.1f}/"
        f"{sum(p.risk_score for p in paths):.1f})"
    )
    return selected


def create_chunks(
    paths: list[TaintPath], tokens_per_chunk: int = 20000
) -> list[AnalysisChunk]:
    """
    Group paths into chunks that fit within per-chunk token budget.
    Paths sharing nodes are grouped together for efficiency.
    """
    chunks = []
    current = AnalysisChunk(chunk_id=0)

    for path in paths:
        overlap = current.shared_nodes(path)
        effective_cost = int(path.estimated_tokens * (1 - 0.5 * overlap))

        if current.total_tokens + effective_cost > tokens_per_chunk and current.paths:
            chunks.append(current)
            current = AnalysisChunk(chunk_id=len(chunks))

        current.add_path(path)

    if current.paths:
        chunks.append(current)

    logger.info(f"Created {len(chunks)} chunks from {len(paths)} paths")
    return chunks


def estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 characters per token for code."""
    return len(text) // 4
