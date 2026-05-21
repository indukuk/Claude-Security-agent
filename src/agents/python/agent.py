"""
Python Application Security Agent.
Performs taint analysis via CPG construction and LLM reasoning.
"""
from __future__ import annotations


import json
import logging
from pathlib import Path

from src.agents.base import BaseAgent
from src.agents.python.cpg_builder import PythonCPGBuilder
from src.agents.python.taint_analyzer import TaintAnalyzer
from src.agents.python.spec_inference import SpecInference
from src.common.config import ScanConfig
from src.common.findings import Finding, Severity, Confidence, Evidence, Location
from src.common.graph import CodePropertyGraph
from src.common.chunker import TaintPath, prioritize_paths, create_chunks
from src.common.llm_client import LLMClient

logger = logging.getLogger(__name__)


class PythonSecurityAgent(BaseAgent):
    @property
    def agent_type(self) -> str:
        return "python"

    @property
    def agent_id(self) -> str:
        return "python-app-agent"

    def __init__(self, config: ScanConfig, llm_client: LLMClient):
        super().__init__(config, llm_client)
        self.cpg_builder = PythonCPGBuilder()
        self.taint_analyzer = TaintAnalyzer(llm_client)
        self.spec_inference = SpecInference(llm_client)

    def _execute_phases(self, directories: list[str]) -> list[Finding]:
        findings = []

        # Phase 0: Specification Inference
        if self.state.phase <= 0:
            logger.info("Phase 0: Inferring sources/sinks/sanitizers from codebase")
            python_files = self._find_python_files(directories)
            inferred_specs = self.spec_inference.infer(python_files)
            self.state.inferred_specs = inferred_specs
            self.state.phase = 1
            self._save_checkpoint()

        # Phase 2: CPG Construction
        if self.state.phase <= 1:
            logger.info("Phase 2: Building Code Property Graph")
            python_files = self._find_python_files(directories)
            cpg = self.cpg_builder.build(python_files, self.state.inferred_specs or {})
            self.state.graph = cpg.serialize()
            logger.info(f"CPG built: {cpg.node_count()} nodes, {cpg.edge_count()} edges")

            # Find taint paths
            taint_paths = cpg.find_taint_paths(max_depth=self.config.max_taint_paths)
            logger.info(f"Found {len(taint_paths)} potential taint paths")

            # Convert to TaintPath objects with risk scoring
            scored_paths = self._score_paths(taint_paths, cpg)

            # Prioritize within budget
            token_budget = int(self.config.cpg_slice_budget * 10)  # Total across all chunks
            prioritized = prioritize_paths(scored_paths, token_budget)

            self.state.pending_analysis = [
                f"{p.source}→{p.sink}" for p in prioritized
            ]
            self.state.phase = 2
            self._save_checkpoint()

        # Phase 3: LLM Taint Reasoning (chunked)
        if self.state.phase <= 2:
            logger.info("Phase 3: LLM taint analysis")
            cpg = CodePropertyGraph.deserialize(self.state.graph)
            scored_paths = self._rebuild_paths(self.state.pending_analysis, cpg)
            chunks = create_chunks(scored_paths, self.config.cpg_slice_budget)

            for i, chunk in enumerate(chunks[self.state.chunk_index:], self.state.chunk_index):
                logger.info(f"Analyzing chunk {i + 1}/{len(chunks)} ({len(chunk.paths)} paths)")
                chunk_findings = self.taint_analyzer.analyze_chunk(chunk, cpg)
                findings.extend(chunk_findings)

                self.state.chunk_index = i + 1
                self.state.candidate_findings.extend([f.to_dict() for f in chunk_findings])
                self._save_checkpoint()

            self.state.phase = 3

        # Also add deterministic findings (no LLM needed)
        deterministic = self._run_deterministic_checks(directories)
        findings.extend(deterministic)
        self.state.deterministic_findings = [f.to_dict() for f in deterministic]

        logger.info(
            f"Python agent complete: {len(findings)} findings "
            f"(${self.llm.total_cost:.3f} spent)"
        )
        return findings

    def _find_python_files(self, directories: list[str]) -> list[str]:
        """Find all .py files in the given directories."""
        files = []
        for directory in directories:
            path = Path(self.config.repo_path) / directory
            if path.exists():
                files.extend(str(f) for f in path.rglob("*.py") if "test" not in str(f).lower())
        return files

    def _score_paths(
        self, raw_paths: list[tuple[str, str, list[str]]], cpg: CodePropertyGraph
    ) -> list[TaintPath]:
        """Score taint paths by risk (for prioritization)."""
        scored = []
        for source, sink, path_nodes in raw_paths:
            source_text = cpg.get_text(source)
            sink_text = cpg.get_text(sink)

            # Risk scoring based on source exposure and sink severity
            exposure = self._score_exposure(source_text)
            severity = self._score_sink_severity(sink_text)
            risk = exposure * severity

            # Estimate tokens for this path's CPG slice
            tokens = max(len(path_nodes) * 150, 500)

            scored.append(TaintPath(
                source=source,
                sink=sink,
                path_nodes=path_nodes,
                risk_score=risk,
                estimated_tokens=tokens,
                cwe=self._infer_cwe(sink_text),
                category=self._infer_category(sink_text),
            ))

        return sorted(scored, key=lambda p: p.risk_score, reverse=True)

    def _score_exposure(self, source_text: str) -> float:
        """How exposed is this source to attackers?"""
        if "event['body']" in source_text or "event.get('body')" in source_text:
            return 1.0  # Direct HTTP input
        if "state['messages']" in source_text:
            return 0.9  # User messages (prompt injection surface)
        if "requestContext" in source_text:
            return 0.3  # Auth context (validated)
        if "os.environ" in source_text:
            return 0.1  # Environment (deploy-time)
        return 0.5  # Unknown

    def _score_sink_severity(self, sink_text: str) -> float:
        """How dangerous is this sink if reached by tainted data?"""
        critical_patterns = ["exec(", "eval(", "admin_create_user", "put_item", "update_item"]
        high_patterns = ["generate_presigned_url", "invoke_model", "query("]
        medium_patterns = ["logger", "print("]

        for p in critical_patterns:
            if p in sink_text:
                return 1.0
        for p in high_patterns:
            if p in sink_text:
                return 0.7
        for p in medium_patterns:
            if p in sink_text:
                return 0.3
        return 0.5

    def _infer_cwe(self, sink_text: str) -> str:
        if "execute" in sink_text or "query" in sink_text:
            return "CWE-943"
        if "exec(" in sink_text or "eval(" in sink_text:
            return "CWE-94"
        if "generate_presigned_url" in sink_text:
            return "CWE-22"
        if "admin_create_user" in sink_text:
            return "CWE-284"
        if "invoke_model" in sink_text:
            return "CWE-77"
        return "CWE-639"

    def _infer_category(self, sink_text: str) -> str:
        if "put_item" in sink_text or "query" in sink_text:
            return "cross_tenant_access"
        if "generate_presigned_url" in sink_text:
            return "path_traversal"
        if "exec(" in sink_text or "eval(" in sink_text:
            return "code_injection"
        if "admin_create_user" in sink_text:
            return "privilege_escalation"
        return "taint_flow"

    def _rebuild_paths(self, path_strs: list[str], cpg: CodePropertyGraph) -> list[TaintPath]:
        """Rebuild TaintPath objects from checkpoint string representation."""
        paths = []
        for ps in path_strs:
            parts = ps.split("→")
            if len(parts) == 2:
                source, sink = parts[0].strip(), parts[1].strip()
                paths.append(TaintPath(
                    source=source,
                    sink=sink,
                    path_nodes=[source, sink],
                    risk_score=0.5,
                    estimated_tokens=800,
                ))
        return paths

    def _run_deterministic_checks(self, directories: list[str]) -> list[Finding]:
        """Quick pattern-based checks that don't need LLM."""
        findings = []
        python_files = self._find_python_files(directories)

        for file_path in python_files:
            try:
                content = Path(file_path).read_text()
            except Exception:
                continue

            # Check: eval/exec usage
            for i, line in enumerate(content.split("\n"), 1):
                if "eval(" in line and "literal_eval" not in line:
                    findings.append(Finding(
                        id=f"DET-EVAL-{len(findings)}",
                        agent="python",
                        category="code_injection",
                        cwe="CWE-94",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        title="eval() usage detected",
                        description="eval() executes arbitrary Python expressions. If user input reaches it, full code execution is possible.",
                        evidence=Evidence(snippet=line.strip()),
                        location=Location(file_path=file_path, start_line=i),
                    ))

                if "pickle.loads" in line or "pickle.load(" in line:
                    findings.append(Finding(
                        id=f"DET-PICKLE-{len(findings)}",
                        agent="python",
                        category="deserialization",
                        cwe="CWE-502",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        title="Unsafe pickle deserialization",
                        description="pickle.loads() executes arbitrary code during deserialization.",
                        evidence=Evidence(snippet=line.strip()),
                        location=Location(file_path=file_path, start_line=i),
                    ))

        return findings
