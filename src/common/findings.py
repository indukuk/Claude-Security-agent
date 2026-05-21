"""
Finding data structures shared across all agents.
"""
from __future__ import annotations


from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1

    def __lt__(self, other):
        return self.value < other.value


class Confidence(Enum):
    HIGH = 3
    MEDIUM = 2
    LOW = 1


class ValidationVerdict(Enum):
    CONFIRMED = "confirmed"
    DISMISSED = "dismissed"
    UNCERTAIN = "uncertain"


@dataclass
class Location:
    file_path: str
    start_line: int = 0
    end_line: int = 0
    resource_id: str | None = None

    def __str__(self):
        if self.resource_id:
            return f"{self.file_path}:{self.start_line} ({self.resource_id})"
        return f"{self.file_path}:{self.start_line}"


@dataclass
class Evidence:
    snippet: str
    graph_context: str = ""
    reasoning: str = ""


@dataclass
class Remediation:
    fix_diff: str
    explanation: str
    validated: bool = False
    validation_result: str | None = None


@dataclass
class Finding:
    id: str
    agent: str
    category: str
    cwe: str | None
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    evidence: Evidence
    location: Location
    attack_path: list[str] = field(default_factory=list)
    blast_radius: list[str] = field(default_factory=list)
    remediation: Remediation | None = None
    related_findings: list[str] = field(default_factory=list)
    validation_verdict: ValidationVerdict | None = None
    compliance_impact: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "agent": self.agent,
            "category": self.category,
            "cwe": self.cwe,
            "severity": self.severity.name,
            "confidence": self.confidence.name,
            "title": self.title,
            "description": self.description,
            "evidence": {
                "snippet": self.evidence.snippet,
                "graph_context": self.evidence.graph_context,
                "reasoning": self.evidence.reasoning,
            },
            "location": str(self.location),
            "attack_path": self.attack_path,
            "blast_radius": self.blast_radius,
            "remediation": {
                "fix_diff": self.remediation.fix_diff,
                "explanation": self.remediation.explanation,
                "validated": self.remediation.validated,
            } if self.remediation else None,
            "related_findings": self.related_findings,
            "validation_verdict": self.validation_verdict.value if self.validation_verdict else None,
            "compliance_impact": self.compliance_impact,
        }


@dataclass
class CoverageMetrics:
    total_files: int = 0
    files_analyzed: int = 0
    total_paths: int = 0
    paths_analyzed: int = 0
    risk_weighted_coverage: float = 0.0
    skipped_files: list[str] = field(default_factory=list)
    skipped_reason: dict[str, str] = field(default_factory=dict)

    @property
    def file_coverage(self) -> float:
        if self.total_files == 0:
            return 0.0
        return self.files_analyzed / self.total_files

    @property
    def path_coverage(self) -> float:
        if self.total_paths == 0:
            return 0.0
        return self.paths_analyzed / self.total_paths
