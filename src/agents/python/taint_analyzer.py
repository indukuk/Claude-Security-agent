"""
LLM-powered taint analysis using Think & Verify CoT.
Analyzes CPG slices for security vulnerabilities.
"""
from __future__ import annotations


import json
import logging

from src.common.findings import Finding, Severity, Confidence, Evidence, Location
from src.common.graph import CodePropertyGraph
from src.common.chunker import AnalysisChunk
from src.common.llm_client import LLMClient
from src.skills.python_taint_skills import TAINT_COT_TEMPLATE
from src.skills.cwe_knowledge import CWE_DEFINITIONS

logger = logging.getLogger(__name__)


class TaintAnalyzer:
    SYSTEM_PROMPT = (
        "You are a senior application security engineer specializing in Python taint "
        "analysis and vulnerability detection. You are performing a security audit of "
        "production code for a multi-tenant compliance platform. You reason step-by-step "
        "about data flow, never jumping to conclusions without tracing the actual path."
    )

    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client
        self._finding_counter = 0

    def analyze_chunk(self, chunk: AnalysisChunk, cpg: CodePropertyGraph) -> list[Finding]:
        """Analyze a chunk of taint paths using LLM reasoning."""
        findings = []

        for path in chunk.paths:
            finding = self._analyze_path(path, cpg)
            if finding:
                findings.append(finding)

        return findings

    def _analyze_path(self, path, cpg: CodePropertyGraph) -> Finding | None:
        """Analyze a single taint path with Think & Verify CoT."""
        # Extract CPG slice
        cpg_slice = cpg.extract_slice(path.source, path.sink)
        if cpg_slice.node_count == 0:
            return None

        # Get CWE context for RAG
        cwe_id = path.cwe or "CWE-639"
        cwe_def = CWE_DEFINITIONS.get(cwe_id, {})
        cwe_context = (
            f"CWE: {cwe_id} — {cwe_def.get('name', 'Unknown')}\n"
            f"{cwe_def.get('description', '')}\n"
            f"Detection in this platform: {cwe_def.get('detection_in_compliance_platform', '')}"
        )

        # Render CPG slice for LLM (source at beginning, sink at end)
        slice_code = cpg.render_for_llm(cpg_slice.nodes)

        # Build prompt
        prompt = TAINT_COT_TEMPLATE.format(
            cwe_id=cwe_id,
            cwe_name=cwe_def.get("name", "Unknown Vulnerability"),
            cwe_definition=cwe_context,
            cpg_slice_code=slice_code,
            cpg_slice_graph=self._render_graph_edges(cpg_slice.nodes, cpg),
        )

        # LLM call
        try:
            response = self.llm.analyze(
                system_prompt=self.SYSTEM_PROMPT,
                user_prompt=prompt,
                task_type="reasoning",
            )
        except Exception as e:
            logger.warning(f"LLM call failed for path {path.source}→{path.sink}: {e}")
            return None

        # Parse verdict
        return self._parse_verdict(response, path, cpg, slice_code)

    def _parse_verdict(self, response: str, path, cpg: CodePropertyGraph,
                       slice_code: str) -> Finding | None:
        """Parse LLM response into a Finding (or None if SAFE)."""
        response_lower = response.lower()

        # Determine verdict
        if "verdict:" in response_lower:
            verdict_section = response_lower.split("verdict:")[-1][:200]
        else:
            verdict_section = response_lower[-500:]

        if "vulnerable" in verdict_section:
            severity = self._extract_severity(response)
            confidence = self._extract_confidence(response)
        elif "uncertain" in verdict_section:
            severity = Severity.MEDIUM
            confidence = Confidence.LOW
        else:
            return None  # SAFE — no finding

        # Extract description from response
        description = self._extract_description(response)

        self._finding_counter += 1
        source_file, source_line = cpg.get_file_line(path.source)
        sink_file, sink_line = cpg.get_file_line(path.sink)

        return Finding(
            id=f"TAINT-{self._finding_counter:03d}",
            agent="python",
            category=path.category or "taint_flow",
            cwe=path.cwe or "CWE-639",
            severity=severity,
            confidence=confidence,
            title=f"Tainted data flows from {self._short_name(path.source)} to {self._short_name(path.sink)}",
            description=description,
            evidence=Evidence(
                snippet=slice_code[:1000],
                reasoning=response[:2000],
            ),
            location=Location(
                file_path=source_file or sink_file,
                start_line=source_line,
                end_line=sink_line,
            ),
            attack_path=[path.source, "...", path.sink],
        )

    def _extract_severity(self, response: str) -> Severity:
        """Extract severity from LLM response."""
        lower = response.lower()
        if "critical" in lower:
            return Severity.CRITICAL
        if "high" in lower:
            return Severity.HIGH
        if "medium" in lower:
            return Severity.MEDIUM
        return Severity.LOW

    def _extract_confidence(self, response: str) -> Confidence:
        """Extract confidence from LLM response."""
        lower = response.lower()
        if "confidence: high" in lower or "confidence:high" in lower:
            return Confidence.HIGH
        if "confidence: low" in lower or "confidence:low" in lower:
            return Confidence.LOW
        return Confidence.MEDIUM

    def _extract_description(self, response: str) -> str:
        """Extract a concise description from the LLM reasoning."""
        # Look for the CONCLUDE or VERDICT section
        sections = ["step 4", "conclude", "verdict", "vulnerable"]
        for section in sections:
            if section in response.lower():
                idx = response.lower().index(section)
                chunk = response[idx:idx + 500]
                # Take first 2 sentences
                sentences = chunk.split(". ")[:2]
                return ". ".join(sentences).strip()

        # Fallback: last 200 chars
        return response[-200:].strip()

    def _render_graph_edges(self, nodes: set[str], cpg: CodePropertyGraph) -> str:
        """Render the edges between slice nodes as text."""
        lines = []
        for node in nodes:
            for succ in cpg.successors(node):
                if succ in nodes:
                    edge_data = cpg.graph.edges.get((node, succ), {})
                    edge_type = edge_data.get("edge_type", "unknown")
                    var = edge_data.get("variable", "")
                    lines.append(f"  {self._short_name(node)} →({edge_type}{': ' + var if var else ''})→ {self._short_name(succ)}")
        return "\n".join(lines[:20])  # Limit for token budget

    def _short_name(self, node_id: str) -> str:
        """Shorten node ID for display."""
        parts = node_id.split(":")
        if len(parts) >= 2:
            file_name = parts[0].split("/")[-1]
            line = parts[1]
            return f"{file_name}:{line}"
        return node_id[:30]
