from __future__ import annotations

"""
Knowledge Base Schema
======================
Defines the structure for all knowledge base entries.
Every entry follows this schema for consistent RAG injection.
"""

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class VulnerabilityEntry:
    id: str                              # e.g., "WEB-SQLI-001"
    cwe: str                             # e.g., "CWE-89"
    owasp: str | None                    # e.g., "A03:2021 Injection"
    name: str                            # Short title
    severity: Severity
    description: str                     # What the vulnerability IS
    how_it_works: str                    # Technical explanation of exploitation
    preconditions: list[str]             # What must be true for this to be exploitable
    impact: list[str]                    # What an attacker gains
    affected_components: list[str]       # AWS services, frameworks, patterns affected
    detection_guidance: str              # How to find this in code/config
    exploit_payloads: list[str]          # Concrete attack strings/steps
    vulnerable_code: str                 # Before (vulnerable) code example
    safe_code: str                       # After (fixed) code example
    remediation: list[str]              # Steps to fix
    references: list[str]               # URLs, CVEs, papers
    tags: list[str]                     # For filtering: ["python", "dynamodb", "multi-tenant"]


@dataclass
class BreachCase:
    id: str
    name: str                            # e.g., "Capital One 2019"
    date: str
    root_cause: str                      # Primary vulnerability exploited
    cwes: list[str]                      # CWEs involved
    attack_chain: list[str]             # Step-by-step how the attack progressed
    impact: str                          # What was stolen/damaged
    lessons: list[str]                  # What should have prevented this
    relevance_to_compliance: str        # Why this matters for our codebase


@dataclass
class ExploitPayload:
    id: str
    category: str                        # "sqli", "nosql", "ssrf", "jwt", "prompt_injection"
    payload: str                         # The actual attack string
    purpose: str                         # What this payload achieves
    target: str                          # What it targets (e.g., "MySQL WHERE clause")
    bypass_technique: str | None         # What sanitizer it bypasses
    detection_hint: str                  # How a scanner would spot this is needed
