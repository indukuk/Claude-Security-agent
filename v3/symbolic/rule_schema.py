"""
Rule schema for the Symbolic Property Engine.
Defines the data model for declarative security rules.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RuleCondition:
    """A deterministic predicate evaluated against InfraGraph."""
    type: str  # "graph_query" | "z3_sat" | "edge_query" | "composite"

    # For graph_query: filter nodes, check properties
    node_filter: dict = field(default_factory=dict)
    property_check: str = ""

    # For edge_query: filter IAM edges
    edge_filter: dict = field(default_factory=dict)

    # For z3_sat: delegate to Z3 property checker
    z3_checker: str = ""

    # For composite: combine multiple conditions
    all_of: list[dict] = field(default_factory=list)
    any_of: list[dict] = field(default_factory=list)
    none_of: list[dict] = field(default_factory=list)


@dataclass
class SymbolicRule:
    """A single declarative security rule."""
    id: str
    category: str
    severity: str
    title_template: str
    description_template: str
    condition: RuleCondition

    cwe: str = ""
    context_needed: bool = False
    context_questions: list[str] = field(default_factory=list)
    remediation_template: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "SymbolicRule":
        cond_data = data.get("condition", {})
        condition = RuleCondition(
            type=cond_data.get("type", "graph_query"),
            node_filter=cond_data.get("node_filter", {}),
            property_check=cond_data.get("property_check", ""),
            edge_filter=cond_data.get("edge_filter", {}),
            z3_checker=cond_data.get("z3_checker", ""),
            all_of=cond_data.get("all_of", []),
            any_of=cond_data.get("any_of", []),
            none_of=cond_data.get("none_of", []),
        )
        return cls(
            id=data["id"],
            category=data.get("category", ""),
            severity=data.get("severity", "MEDIUM"),
            title_template=data.get("title_template", ""),
            description_template=data.get("description_template", ""),
            condition=condition,
            cwe=data.get("cwe", ""),
            context_needed=data.get("context_needed", False),
            context_questions=data.get("context_questions", []),
            remediation_template=data.get("remediation_template", ""),
        )


@dataclass
class SymbolicCandidate:
    """Output from a symbolic rule evaluation — either a final finding or a candidate for Layer 2."""
    rule_id: str
    resource_id: str
    severity: str
    title: str
    description: str
    category: str
    cwe: str
    evidence: dict
    context_needed: bool
    context_questions: list[str] = field(default_factory=list)
    remediation: str = ""
