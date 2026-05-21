"""
Infrastructure Security Agent.
Analyzes CDK/CloudFormation for misconfigurations, IAM escalation, and toxic combinations.
"""
from __future__ import annotations


import json
import logging
from pathlib import Path

from src.agents.base import BaseAgent
from src.agents.infrastructure.cfn_parser import CloudFormationParser
from src.agents.infrastructure.deterministic_checks import DeterministicChecker
from src.agents.infrastructure.iam_analyzer import IAMAnalyzer
from src.agents.infrastructure.toxic_combos import ToxicCombinationDetector
from src.common.config import ScanConfig
from src.common.findings import Finding, Severity, Confidence, Evidence, Location
from src.common.graph import InfraGraph
from src.common.llm_client import LLMClient

logger = logging.getLogger(__name__)


class InfraSecurityAgent(BaseAgent):
    @property
    def agent_type(self) -> str:
        return "infrastructure"

    @property
    def agent_id(self) -> str:
        return "infra-security-agent"

    def __init__(self, config: ScanConfig, llm_client: LLMClient):
        super().__init__(config, llm_client)
        self.cfn_parser = CloudFormationParser()
        self.deterministic_checker = DeterministicChecker()
        self.iam_analyzer = IAMAnalyzer()
        self.toxic_detector = ToxicCombinationDetector()

    def _execute_phases(self, directories: list[str]) -> list[Finding]:
        findings = []

        # Phase 1: Parse templates and build graphs
        if self.state.phase <= 0:
            logger.info("Infra Phase 1: Parsing templates and building graphs")
            template = self._load_template(directories)
            if not template:
                logger.warning("No CloudFormation template found")
                self.state.phase = 5
                self._save_checkpoint()
                return []

            infra_graph = self.cfn_parser.parse(template)
            self.state.graph = infra_graph.serialize()
            self.state.phase = 1
            self._save_checkpoint()

        # Phase 2: Deterministic checks
        if self.state.phase <= 1:
            logger.info("Infra Phase 2: Running deterministic checks")
            infra_graph = InfraGraph.deserialize(self.state.graph)
            det_findings = self.deterministic_checker.check(infra_graph)
            findings.extend(det_findings)
            self.state.deterministic_findings = [f.to_dict() for f in det_findings]
            self.state.phase = 2
            self._save_checkpoint()
            logger.info(f"Deterministic checks: {len(det_findings)} findings")

        # Phase 3: IAM analysis
        if self.state.phase <= 2:
            logger.info("Infra Phase 3: IAM permission analysis")
            infra_graph = InfraGraph.deserialize(self.state.graph)
            iam_findings = self.iam_analyzer.analyze(infra_graph)
            findings.extend(iam_findings)
            self.state.phase = 3
            self._save_checkpoint()
            logger.info(f"IAM analysis: {len(iam_findings)} findings")

        # Phase 3b: Z3 formal IAM verification
        if self.state.phase <= 2:
            logger.info("Infra Phase 3b: Z3 formal IAM verification")
            infra_graph = InfraGraph.deserialize(self.state.graph)
            try:
                from src.agents.infrastructure.z3_iam_analyzer import Z3IAMAnalyzer
                z3_analyzer = Z3IAMAnalyzer()
                z3_findings = z3_analyzer.analyze(infra_graph)
                findings.extend(z3_findings)
                logger.info(f"Z3 IAM analysis: {len(z3_findings)} findings")
            except ImportError:
                logger.warning("z3-solver not installed, skipping formal IAM analysis")
            except Exception as e:
                logger.warning(f"Z3 IAM analysis failed: {e}")

        # Phase 4: Toxic combination detection
        if self.state.phase <= 3:
            logger.info("Infra Phase 4: Toxic combination detection")
            infra_graph = InfraGraph.deserialize(self.state.graph)
            existing_findings = [
                Finding(**f) if isinstance(f, dict) else f
                for f in self.state.deterministic_findings
            ] if self.state.deterministic_findings else findings

            toxic_findings = self.toxic_detector.detect(infra_graph, existing_findings)
            findings.extend(toxic_findings)
            self.state.phase = 4
            self._save_checkpoint()
            logger.info(f"Toxic combinations: {len(toxic_findings)} findings")

        # Phase 5: LLM contextual analysis (for findings needing judgment)
        if self.state.phase <= 4:
            logger.info("Infra Phase 5: LLM contextual analysis")
            needs_judgment = [f for f in findings if f.confidence == Confidence.LOW]
            for finding in needs_judgment[:10]:  # Limit LLM calls
                self._enrich_with_llm(finding)
            self.state.phase = 5
            self._save_checkpoint()

        logger.info(
            f"Infrastructure agent complete: {len(findings)} findings "
            f"(${self.llm.total_cost:.3f} spent)"
        )
        return findings

    def _load_template(self, directories: list[str]) -> dict | None:
        """Load CloudFormation template from cdk.out or specified path."""
        repo = Path(self.config.repo_path)

        # Try cdk.out first
        cdk_out = repo / "cdk.out"
        if cdk_out.exists():
            for template_file in cdk_out.glob("*.template.json"):
                try:
                    return json.loads(template_file.read_text())
                except Exception:
                    continue

        # Try synthesizing
        for directory in directories:
            dir_path = repo / directory
            for json_file in dir_path.rglob("*.template.json"):
                try:
                    return json.loads(json_file.read_text())
                except Exception:
                    continue

        # Try reading CDK source directly (parse Python CDK code)
        for directory in directories:
            dir_path = repo / directory
            for py_file in dir_path.rglob("*.py"):
                if "stack" in py_file.name.lower():
                    # We'll do CDK source analysis instead
                    return self._parse_cdk_source(py_file)

        return None

    def _parse_cdk_source(self, stack_file: Path) -> dict | None:
        """
        Parse CDK Python source to extract resource definitions.
        Fallback when cdk synth output isn't available.
        """
        try:
            content = stack_file.read_text()
            # Extract resource patterns from CDK code
            resources = {}
            lines = content.split("\n")

            for i, line in enumerate(lines):
                # Detect resource creation patterns
                if "lambda_.Function(" in line or "lambda_.DockerImageFunction(" in line:
                    resources[f"Lambda_{len(resources)}"] = {
                        "Type": "AWS::Lambda::Function",
                        "Properties": {"SourceLine": i + 1},
                        "SourceFile": str(stack_file),
                    }
                elif "dynamodb.Table(" in line:
                    resources[f"DynamoDB_{len(resources)}"] = {
                        "Type": "AWS::DynamoDB::Table",
                        "Properties": {"SourceLine": i + 1},
                        "SourceFile": str(stack_file),
                    }
                elif "s3.Bucket(" in line:
                    resources[f"S3_{len(resources)}"] = {
                        "Type": "AWS::S3::Bucket",
                        "Properties": {"SourceLine": i + 1},
                        "SourceFile": str(stack_file),
                    }
                elif "cognito.UserPool(" in line:
                    resources[f"Cognito_{len(resources)}"] = {
                        "Type": "AWS::Cognito::UserPool",
                        "Properties": {"SourceLine": i + 1},
                        "SourceFile": str(stack_file),
                    }
                elif "apigateway.RestApi(" in line:
                    resources[f"ApiGw_{len(resources)}"] = {
                        "Type": "AWS::ApiGateway::RestApi",
                        "Properties": {"SourceLine": i + 1},
                        "SourceFile": str(stack_file),
                    }

            if resources:
                return {"Resources": resources, "SourceFile": str(stack_file), "RawContent": content}

        except Exception as e:
            logger.warning(f"Failed to parse CDK source {stack_file}: {e}")

        return None

    def _enrich_with_llm(self, finding: Finding):
        """Use LLM to add context and adjust confidence for ambiguous findings."""
        from src.skills.infra_security_skills import INFRA_COT_TEMPLATE

        prompt = f"""Analyze this infrastructure finding:

FINDING: {finding.title}
SEVERITY: {finding.severity.name}
EVIDENCE: {finding.evidence.snippet[:500]}

Is this finding genuinely exploitable in a production multi-tenant compliance platform?
Consider: compensating controls, AWS service limitations, practical exploitability.

Respond with:
- CONFIRMED (genuinely dangerous) or DISMISSED (false positive or acceptable risk)
- Brief explanation (2-3 sentences)"""

        try:
            response = self.llm.analyze(
                system_prompt="You are a senior cloud security architect reviewing infrastructure findings.",
                user_prompt=prompt,
                task_type="validation",
            )

            if "confirmed" in response.lower():
                finding.confidence = Confidence.HIGH
            elif "dismissed" in response.lower():
                finding.confidence = Confidence.LOW
                finding.severity = Severity.LOW

        except Exception as e:
            logger.warning(f"LLM enrichment failed: {e}")
