"""
Grounded Debate Engine — AEGIS-style debate anchored in verifiable evidence.

Key innovation: all arguments must cite evidence items from the EvidenceBundle.
The judge discards any claim not backed by a citation. This prevents hallucinated
evidence and reduces false positives by 54.4% (AEGIS, Mar 2026).

Protocol:
1. Extract EvidenceBundle from CPG/InfraGraph for the finding
2. Prosecution argues exploitability citing ONLY bundle items
3. Defense argues safety citing ONLY bundle items
4. Judge evaluates citation quality, renders CONFIRMED/DISMISSED
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.common.graph import InfraGraph, CodePropertyGraph
from v3.agents.verifiers.evidence_bundle import EvidenceBundle, EvidenceItem

logger = logging.getLogger(__name__)


@dataclass
class Argument:
    """A debate argument with cited evidence."""
    role: str  # "prosecution" | "defense"
    position: str  # The argument text
    cited_evidence_ids: list[int] = field(default_factory=list)
    confidence: float = 0.5


@dataclass
class Verdict:
    """Judge's final decision."""
    decision: str  # "CONFIRMED" | "DISMISSED"
    severity: str  # Final severity (may be adjusted from original)
    confidence: float
    reasoning: str
    strongest_prosecution_point: str = ""
    strongest_defense_point: str = ""
    cited_evidence_ids: list[int] = field(default_factory=list)


@dataclass
class CandidateFinding:
    """Input finding to debate."""
    id: str
    title: str
    severity: str
    category: str
    file_path: str = ""
    line: int = 0
    evidence_text: str = ""
    cwe: str = ""


class GroundedDebateEngine:
    """
    AEGIS-style grounded debate over verified evidence.

    For in-session execution: generates structured debate prompts
    that Claude processes with citation requirements.

    For API execution: would call Claude API with structured messages.
    """

    def __init__(self, cpg: CodePropertyGraph | None = None,
                 infra_graph: InfraGraph | None = None):
        self.cpg = cpg
        self.infra_graph = infra_graph

    def build_evidence_bundle(self, candidate: CandidateFinding) -> EvidenceBundle:
        """
        Construct the immutable evidence bundle for a finding.
        Gathers code context, IAM permissions, network paths, and Z3 results.
        """
        bundle = EvidenceBundle(
            finding_id=candidate.id,
            finding_title=candidate.title,
        )

        # Code evidence from CPG
        if self.cpg and candidate.file_path:
            self._add_cpg_evidence(bundle, candidate)

        # Negative evidence for business logic findings (what's missing)
        if candidate.category in ("missing_authorization", "business_logic") or "IDOR" in candidate.title:
            self._add_missing_pattern_evidence(bundle, candidate)

        # Infrastructure evidence
        if self.infra_graph:
            self._add_infra_evidence(bundle, candidate)

        # If no CPG/infra, add raw evidence text
        if not bundle.items and candidate.evidence_text:
            bundle.add_item(
                category="raw_evidence",
                file_path=candidate.file_path or "unknown",
                line=candidate.line,
                text=candidate.evidence_text,
            )

        return bundle

    def generate_debate_prompts(self, candidate: CandidateFinding,
                                 bundle: EvidenceBundle) -> dict:
        """
        Generate structured debate prompts with citation requirements.

        Returns dict with keys: prosecution_prompt, defense_prompt, judge_prompt
        """
        evidence_text = bundle.render_for_debate()

        prosecution_prompt = self._build_prosecution_prompt(candidate, evidence_text)
        defense_prompt = self._build_defense_prompt(candidate, evidence_text)
        judge_prompt = self._build_judge_prompt(candidate, evidence_text)

        return {
            "evidence_bundle": evidence_text,
            "prosecution_prompt": prosecution_prompt,
            "defense_prompt": defense_prompt,
            "judge_prompt": judge_prompt,
        }

    def debate(self, candidate: CandidateFinding) -> tuple[EvidenceBundle, Verdict]:
        """
        Run the full debate pipeline.

        In-session mode: generates prompts for Claude to process sequentially.
        Returns the evidence bundle and a placeholder verdict (Claude fills in).
        """
        bundle = self.build_evidence_bundle(candidate)
        prompts = self.generate_debate_prompts(candidate, bundle)

        # In-session execution: return prompts for sequential processing
        # In API mode: would call Claude API for each role
        placeholder_verdict = Verdict(
            decision="PENDING",
            severity=candidate.severity,
            confidence=0.0,
            reasoning="Awaiting debate execution",
        )

        return bundle, placeholder_verdict

    def _add_cpg_evidence(self, bundle: EvidenceBundle, candidate: CandidateFinding):
        """
        Extract CPG-based evidence: full taint path slices with numbered steps.
        Each path node becomes a separately-citable evidence item.
        """
        if not self.cpg:
            return

        # Find taint paths relevant to this finding's file
        relevant_paths = self._find_relevant_paths(candidate)

        if relevant_paths:
            self._add_path_evidence(bundle, candidate, relevant_paths)
        else:
            # Fallback: add isolated source/sink nodes if no full path found
            self._add_isolated_node_evidence(bundle, candidate)

    def _find_relevant_paths(self, candidate: CandidateFinding) -> list[tuple[str, str, list[str]]]:
        """Find taint paths that pass through the candidate's file."""
        all_paths = self.cpg.find_taint_paths()
        relevant = []

        for source_id, sink_id, path_nodes in all_paths:
            # Check if any path node is in the candidate's file
            for node_id in path_nodes:
                file_path, _ = self.cpg.get_file_line(node_id)
                if file_path and (
                    candidate.file_path in file_path or
                    Path(file_path).name == Path(candidate.file_path).name
                ):
                    relevant.append((source_id, sink_id, path_nodes))
                    break

        return relevant

    def _add_path_evidence(self, bundle: EvidenceBundle, candidate: CandidateFinding,
                           paths: list[tuple[str, str, list[str]]]):
        """Add full taint path as numbered, citable evidence items."""
        for path_index, (source_id, sink_id, path_nodes) in enumerate(paths[:3]):  # Max 3 paths
            # Extract CPG slice for context (includes branch conditions)
            cpg_slice = self.cpg.extract_slice(source_id, sink_id)

            # Add each path step as a separately-citable evidence item
            for step_num, node_id in enumerate(path_nodes, 1):
                file_path, line = self.cpg.get_file_line(node_id)
                text = self.cpg.get_text(node_id)
                if not text:
                    continue

                role = self.cpg.get_role(node_id)

                # Determine edge type to next node
                edge_to_next = ""
                if step_num < len(path_nodes):
                    next_node = path_nodes[step_num]
                    edge_data = self.cpg.graph.edges.get((node_id, next_node), {})
                    edge_to_next = edge_data.get("edge_type", "dfg")

                bundle.add_item(
                    category="path_node",
                    file_path=file_path or candidate.file_path,
                    line=line,
                    text=text,
                    role=role,
                    path_index=path_index,
                    step=step_num,
                    edge_to_next=edge_to_next,
                )

                # Track structured summaries
                if role == "source":
                    bundle.source_node = {"file": file_path, "line": line, "text": text}
                elif role == "sink":
                    bundle.sink_node = {"file": file_path, "line": line, "text": text}
                elif role == "sanitizer":
                    bundle.sanitizers_on_path.append({"file": file_path, "line": line, "text": text})

            # Add taint path summary
            bundle.taint_path.append({
                "source": source_id,
                "sink": sink_id,
                "length": len(path_nodes),
                "sanitized": any(
                    self.cpg.get_role(n) == "sanitizer" for n in path_nodes
                ),
            })

            # Add branch conditions from the slice that gate the path
            for node_id in cpg_slice.nodes:
                node_type = self.cpg.graph.nodes.get(node_id, {}).get("node_type", "")
                if node_type == "if_statement" and node_id not in set(path_nodes):
                    file_path, line = self.cpg.get_file_line(node_id)
                    text = self.cpg.get_text(node_id)
                    if text:
                        bundle.add_item(
                            category="branch_condition",
                            file_path=file_path or candidate.file_path,
                            line=line,
                            text=text,
                            role="gate",
                            path_index=path_index,
                        )
                        bundle.branch_conditions.append({
                            "file": file_path, "line": line, "text": text
                        })

    def _add_isolated_node_evidence(self, bundle: EvidenceBundle, candidate: CandidateFinding):
        """Fallback: add source/sink nodes without full path when no DFG path exists."""
        for source_id in self.cpg.sources:
            file_path, line = self.cpg.get_file_line(source_id)
            if file_path and (candidate.file_path in file_path or
                            Path(file_path).name == Path(candidate.file_path).name):
                text = self.cpg.get_text(source_id)
                if text:
                    bundle.add_item(
                        category="source",
                        file_path=file_path,
                        line=line,
                        text=text,
                        role="source",
                    )
                    bundle.source_node = {"file": file_path, "line": line, "text": text}

        for sink_id in self.cpg.sinks:
            file_path, line = self.cpg.get_file_line(sink_id)
            if file_path and (candidate.file_path in file_path or
                            Path(file_path).name == Path(candidate.file_path).name):
                text = self.cpg.get_text(sink_id)
                if text:
                    bundle.add_item(
                        category="sink",
                        file_path=file_path,
                        line=line,
                        text=text,
                        role="sink",
                    )
                    bundle.sink_node = {"file": file_path, "line": line, "text": text}

        for san_id in self.cpg.sanitizers:
            file_path, line = self.cpg.get_file_line(san_id)
            if file_path and candidate.file_path in file_path:
                text = self.cpg.get_text(san_id)
                if text:
                    bundle.add_item(
                        category="sanitizer",
                        file_path=file_path,
                        line=line,
                        text=text,
                        role="sanitizer",
                    )
                    bundle.sanitizers_on_path.append({"file": file_path, "line": line, "text": text})

    def _add_missing_pattern_evidence(self, bundle: EvidenceBundle, candidate: CandidateFinding):
        """
        Add negative evidence for business logic findings — what SHOULD be present but isn't.
        Reads the source file and identifies the absence of authorization checks.
        """
        import re

        file_path = candidate.file_path
        if not file_path or not Path(file_path).exists():
            return

        try:
            content = Path(file_path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return

        lines = content.split("\n")

        # Find what user-controlled input flows in (what IS there)
        body_patterns = re.finditer(
            r'body\.get\(["\'](\w+)["\']\)|body\[["\'](\w+)["\']\]', content
        )
        for match in body_patterns:
            field = match.group(1) or match.group(2)
            line_num = content[:match.start()].count("\n") + 1
            bundle.add_item(
                category="missing_check",
                file_path=file_path,
                line=line_num,
                text=f"User input: body['{field}'] used WITHOUT authorization comparison",
                role="source",
                absence_type="input_without_auth",
            )

        # Find what SHOULD be there: authorizer context access
        has_authorizer = "requestContext" in content and "authorizer" in content
        has_tenant_comparison = bool(re.search(
            r'tenant_id.*==|==.*tenant_id|customer_id.*==.*tenant|tenant.*==.*customer',
            content
        ))

        if not has_authorizer:
            bundle.add_item(
                category="missing_check",
                file_path=file_path,
                line=0,
                text="MISSING: No access to event['requestContext']['authorizer'] — caller identity never checked",
                role="gate",
                absence_type="no_authorizer_access",
            )
        elif not has_tenant_comparison:
            bundle.add_item(
                category="missing_check",
                file_path=file_path,
                line=0,
                text="MISSING: Authorizer accessed but no comparison between body ID and authenticated tenant_id",
                role="gate",
                absence_type="no_tenant_comparison",
            )

        # Find data write operations (what the input reaches)
        sink_patterns = re.finditer(
            r'(table\.\w+|cognito\w*\.\w+|s3\w*\.\w+|lambda\w*\.invoke)\(', content
        )
        for match in sink_patterns:
            line_num = content[:match.start()].count("\n") + 1
            bundle.add_item(
                category="missing_check",
                file_path=file_path,
                line=line_num,
                text=f"Sensitive operation: {match.group(0)} reachable without tenant validation",
                role="sink",
                absence_type="unguarded_operation",
            )

    def _add_infra_evidence(self, bundle: EvidenceBundle, candidate: CandidateFinding):
        """Extract infrastructure evidence for the finding."""
        if not self.infra_graph:
            return

        # Add relevant IAM permissions
        for source, target, data in self.infra_graph.iam.edges(data=True):
            if data.get("relationship") == "can_assume":
                continue
            actions = data.get("actions", [])
            conditions = data.get("conditions", {})

            # Include if related to the finding's resource or principal
            if (candidate.id and (source in candidate.id or target in candidate.id)) or \
               (candidate.category in ("multi_tenant_isolation", "overpermissive_iam")):
                bundle.add_item(
                    category="iam",
                    file_path="infra/",
                    line=data.get("line", 0),
                    text=f"{source} → {target}: {actions} [conditions={conditions or 'none'}]",
                    principal=source,
                    resource=target,
                    actions=actions,
                    conditions=conditions,
                )
                bundle.iam_permissions.append({
                    "principal": source, "resource": target,
                    "actions": actions, "conditions": conditions,
                })

        # Network paths
        publicly_reachable = self.infra_graph.get_publicly_reachable()
        if publicly_reachable:
            for resource in publicly_reachable[:5]:
                bundle.add_item(
                    category="network",
                    file_path="infra/",
                    line=0,
                    text=f"INTERNET → {resource} (publicly reachable)",
                )
            bundle.network_path = ["INTERNET"] + publicly_reachable[:5]

    def _build_prosecution_prompt(self, candidate: CandidateFinding,
                                   evidence_text: str) -> str:
        return f"""You are a PENETRATION TESTER. Your job is to PROVE this vulnerability is real and exploitable.

## FINDING
Title: {candidate.title}
Severity: {candidate.severity}
Category: {candidate.category}
CWE: {candidate.cwe}

## EVIDENCE (you may ONLY cite items from this bundle)
{evidence_text}

## YOUR TASK
Argue why this finding IS a genuine, exploitable vulnerability.

RULES:
1. You MUST cite specific evidence items using [E1], [E2], etc.
2. You MUST NOT claim evidence that doesn't appear in the bundle above
3. Describe the exact attack steps an adversary would take
4. Explain why each cited evidence item proves the vulnerability exists
5. Address: What is the source of attacker-controlled data? What sensitive operation is reached? What defenses are absent?

## OUTPUT FORMAT
**Position:** This IS exploitable because...
**Attack Steps:**
1. [step] (citing [EX])
2. [step] (citing [EX])
**Key Evidence:** [list the 3 strongest evidence items]
**Confidence:** HIGH | MEDIUM | LOW
"""

    def _build_defense_prompt(self, candidate: CandidateFinding,
                               evidence_text: str) -> str:
        return f"""You are DEFENSE COUNSEL for the development team. Your job is to argue this finding is NOT exploitable.

## FINDING
Title: {candidate.title}
Severity: {candidate.severity}
Category: {candidate.category}
CWE: {candidate.cwe}

## EVIDENCE (you may ONLY cite items from this bundle)
{evidence_text}

## YOUR TASK
Argue why this finding is NOT exploitable or is a false positive.

RULES:
1. You MUST cite specific evidence items using [E1], [E2], etc.
2. You MUST NOT invent protections that don't appear in the evidence
3. Look for: sanitizers on path, framework protections, authentication gates, IAM conditions, environmental controls
4. If you find NO mitigating evidence in the bundle, you MUST state "No mitigating evidence found"

## CONSIDER
- Are there sanitizers [E?] that neutralize the taint?
- Do IAM conditions [E?] restrict access scope?
- Does authentication reduce the attacker pool?
- Are there environmental controls (VPC, WAF) that prevent exploitation?

## OUTPUT FORMAT
**Position:** This is NOT exploitable because...
**Mitigations Found:**
1. [mitigation] (citing [EX])
**Mitigations Absent:** [list what SHOULD exist but doesn't]
**Confidence:** HIGH | MEDIUM | LOW
"""

    def _build_judge_prompt(self, candidate: CandidateFinding,
                             evidence_text: str) -> str:
        return f"""You are a SENIOR SECURITY ARCHITECT acting as impartial judge.

## FINDING
Title: {candidate.title}
Severity: {candidate.severity}
Category: {candidate.category}

## EVIDENCE BUNDLE
{evidence_text}

## PROSECUTION ARGUMENT
{{prosecution_argument}}

## DEFENSE ARGUMENT
{{defense_argument}}

## YOUR TASK
Evaluate BOTH arguments. Render a final verdict.

RULES:
1. DISCARD any claim not backed by a cited evidence item [EX]
2. A citation is valid ONLY if the referenced [EX] actually supports the claim
3. Weight evidence quality: Z3 proofs > code citations > architectural claims
4. If prosecution cites concrete taint paths and defense finds no sanitizers → CONFIRMED
5. If defense cites valid sanitizers/conditions that break the attack → DISMISSED

## OUTPUT FORMAT
**Verdict:** CONFIRMED | DISMISSED
**Severity:** CRITICAL | HIGH | MEDIUM | LOW (may adjust from original)
**Confidence:** 0.0-1.0
**Reasoning:** [2-3 sentences explaining which arguments won and why]
**Strongest Prosecution Point:** [cite evidence]
**Strongest Defense Point:** [cite evidence or "none found"]
"""
