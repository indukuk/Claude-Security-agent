"""
Scan configuration.
"""
from __future__ import annotations


from dataclasses import dataclass, field
from pathlib import Path

from src.common.findings import Severity


@dataclass
class ScanConfig:
    repo_path: str
    total_budget: float = 5.00
    validation_budget: float = 1.00

    enable_python: bool = True
    enable_javascript: bool = False
    enable_infrastructure: bool = True

    min_severity: Severity = Severity.LOW
    fail_threshold: Severity = Severity.HIGH

    reasoning_model: str = "us.anthropic.claude-sonnet-4-6-20250514-v1:0"
    fast_model: str = "us.anthropic.claude-sonnet-4-6-20250514-v1:0"
    temperature: float = 0.1
    max_retries: int = 2

    max_taint_paths: int = 100
    max_path_length: int = 15
    cpg_slice_budget: int = 20000

    checkpoint_dir: str = ".security-agent/checkpoints"
    resume_from: str | None = None

    output_format: str = "json"
    output_path: str = "security-report"

    @property
    def checkpoint_path(self) -> Path:
        return Path(self.repo_path) / self.checkpoint_dir

    @property
    def knowledge_path(self) -> Path:
        return Path(__file__).parent.parent / "knowledge"

    @property
    def skills_path(self) -> Path:
        return Path(__file__).parent.parent / "skills"
