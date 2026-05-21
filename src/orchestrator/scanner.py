"""
Orchestrator — coordinates the full security scan.
Dispatches specialized agents, validates findings, correlates across boundaries.
"""
from __future__ import annotations


import json
import logging
import time
from pathlib import Path

from src.common.config import ScanConfig
from src.common.findings import Finding, Severity, ValidationVerdict
from src.common.llm_client import LLMClient
from src.agents.python.agent import PythonSecurityAgent
from src.agents.infrastructure.agent import InfraSecurityAgent
from src.agents.validation.agent import ValidationAgent

logger = logging.getLogger(__name__)


class SecurityScanner:
    """
    Main orchestrator. Coordinates:
    1. Repo scanning (technology detection)
    2. Agent dispatch (parallel where possible)
    3. Validation (adversarial FP filtering)
    4. Cross-boundary correlation
    5. Report generation
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.llm = LLMClient(config)

    def scan(self) -> dict:
        """Run the full security scan. Returns structured report."""
        start_time = time.time()
        logger.info(f"Starting security scan of {self.config.repo_path}")

        # Phase 1: Discovery
        manifest = self._discover_technologies()
        logger.info(f"Technologies detected: {list(manifest.keys())}")

        # Phase 2-4: Agent dispatch
        all_findings: list[Finding] = []

        if "python" in manifest and self.config.enable_python:
            logger.info("Dispatching Python application agent")
            python_agent = PythonSecurityAgent(self.config, self.llm)
            python_findings = python_agent.run(
                directories=manifest["python"]["directories"],
                budget=self.config.total_budget * 0.4,
            )
            all_findings.extend(python_findings)

        if "infrastructure" in manifest and self.config.enable_infrastructure:
            logger.info("Dispatching Infrastructure agent")
            infra_agent = InfraSecurityAgent(self.config, self.llm)
            infra_findings = infra_agent.run(
                directories=manifest["infrastructure"]["directories"],
                budget=self.config.total_budget * 0.3,
            )
            all_findings.extend(infra_findings)

        logger.info(f"Raw findings: {len(all_findings)}")

        # Phase 3.5: Validation (adversarial FP filtering)
        logger.info("Dispatching Validation agent")
        validation_agent = ValidationAgent(self.llm)
        validated_findings = validation_agent.validate_batch(all_findings)

        # Phase 5: Cross-boundary correlation
        compound_findings = self._correlate_cross_boundary(validated_findings)
        validated_findings.extend(compound_findings)

        # Phase 6: Report
        elapsed = time.time() - start_time
        report = self._generate_report(validated_findings, elapsed)

        logger.info(
            f"Scan complete: {len(validated_findings)} findings, "
            f"${self.llm.total_cost:.2f} spent, {elapsed:.1f}s elapsed"
        )

        return report

    def _discover_technologies(self) -> dict:
        """Scan repository to identify technologies present."""
        repo = Path(self.config.repo_path)
        manifest = {}

        # Python detection
        python_files = list(repo.rglob("*.py"))
        if python_files:
            # Find directories containing Python source (exclude tests, venv)
            py_dirs = set()
            for f in python_files:
                rel = f.relative_to(repo)
                parts = rel.parts
                if not any(skip in parts for skip in ("test", "tests", "venv", ".venv", "node_modules", "cdk.out")):
                    if len(parts) > 1:
                        py_dirs.add(parts[0])
                    else:
                        py_dirs.add(".")

            manifest["python"] = {
                "directories": list(py_dirs),
                "file_count": len(python_files),
            }

        # Infrastructure detection (CDK)
        if (repo / "cdk.json").exists() or list(repo.rglob("*stack*.py")):
            infra_dirs = []
            if (repo / "infra").exists():
                infra_dirs.append("infra")
            if (repo / "cdk.out").exists():
                infra_dirs.append("cdk.out")
            if not infra_dirs:
                infra_dirs.append(".")

            manifest["infrastructure"] = {
                "directories": infra_dirs,
                "type": "cdk",
            }

        # Terraform detection
        tf_files = list(repo.rglob("*.tf"))
        if tf_files:
            manifest["infrastructure"] = {
                "directories": list(set(str(f.parent.relative_to(repo)) for f in tf_files)),
                "type": "terraform",
            }

        # Frontend detection
        if (repo / "frontend").exists() or list(repo.rglob("*.html")):
            manifest["frontend"] = {
                "directories": ["frontend"],
            }

        return manifest

    def _correlate_cross_boundary(self, findings: list[Finding]) -> list[Finding]:
        """Find compound vulnerabilities spanning app + infra boundaries."""
        app_findings = [f for f in findings if f.agent in ("python", "javascript")]
        infra_findings = [f for f in findings if f.agent == "infrastructure"]

        if not app_findings or not infra_findings:
            return []

        # Check known correlation patterns
        compound = []

        # Pattern: overpermissive IAM + unsafe input handling
        has_overperm = any("overpermissive" in f.category or "blast_radius" in f.category
                         for f in infra_findings)
        has_taint = any("taint" in f.category or "cross_tenant" in f.category
                       for f in app_findings)

        if has_overperm and has_taint:
            compound.append(Finding(
                id="COMPOUND-001",
                agent="orchestrator",
                category="compound_risk",
                cwe=None,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                title="Overpermissive IAM + unsafe input handling = amplified blast radius",
                description=(
                    "Application-level vulnerability (taint flow reaching DynamoDB/S3) "
                    "combined with overpermissive IAM means exploitation gives attacker "
                    "access to ALL tenant data, not just the expected scope."
                ),
                evidence=Evidence(
                    snippet="App finding + Infra finding combined",
                    reasoning="Individual app vuln is HIGH. Individual IAM issue is MEDIUM. "
                             "Combined: CRITICAL because blast radius covers all tenants.",
                ),
                location=Location(file_path="cross-boundary"),
                related_findings=[f.id for f in app_findings[:3]] + [f.id for f in infra_findings[:3]],
            ))

        return compound

    def _generate_report(self, findings: list[Finding], elapsed: float) -> dict:
        """Generate the final scan report."""
        by_severity = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
        }
        for f in findings:
            by_severity[f.severity.name].append(f.to_dict())

        return {
            "summary": {
                "total_findings": len(findings),
                "critical": len(by_severity["CRITICAL"]),
                "high": len(by_severity["HIGH"]),
                "medium": len(by_severity["MEDIUM"]),
                "low": len(by_severity["LOW"]),
                "scan_duration_seconds": round(elapsed, 1),
                "cost_usd": round(self.llm.total_cost, 3),
                "repo_path": self.config.repo_path,
            },
            "findings": by_severity,
            "metadata": {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "agents_used": ["python", "infrastructure", "validation"],
                "budget_remaining": round(self.llm.remaining_budget, 3),
            },
        }
