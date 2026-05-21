"""
V4 Security Agent — Deep Analysis Pipeline.

Orchestrates: Enhanced CPG → Evidence Walks → Absence Detection →
Differential Analysis → Chain Synthesis → Report Generation.

Optimizes for analyst-actionable depth over speed.
"""
from __future__ import annotations

import sys
import json
import time
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from v4.cpg.enhanced_builder import EnhancedCPGBuilder
from v4.analysis.evidence_walker import EvidenceWalker
from v4.analysis.absence_detector import AbsenceDetector
from v4.analysis.differential_analyzer import DifferentialAnalyzer
from v4.analysis.chain_synthesizer import ChainSynthesizer
from v4.report.generator import ReportGenerator, V4Report


logger = logging.getLogger(__name__)

# Auth context from CDK analysis — which handlers have API Gateway authorizers
INFRA_AUTH_MAP = {
    "lambda_handler": "authorizer",  # agent handlers behind auth
    "handler": "authorizer",  # auth-api handlers behind token authorizer
}

# Handlers known to be unauthenticated from infra analysis
UNAUTH_HANDLERS = {
    "handler_v2.py": "none",
    "handler_v3.py": "none",
    "observer/handler.py": "none",
}


def run_v4(repo_path: str) -> V4Report:
    """Run the full V4 deep analysis pipeline."""
    start_time = time.time()
    repo = Path(repo_path)

    print("═" * 60)
    print("  Security Agent V4 — Deep Analysis Pipeline")
    print("═" * 60)
    print(f"  Target: {repo_path}")
    print()

    # ════════════════════════════════════════════════════════════
    # STAGE 1: Build Enhanced CPG
    # ════════════════════════════════════════════════════════════
    print("  [1/6] Building Enhanced CPG...")
    py_files = [
        str(f) for f in repo.rglob("*.py")
        if "__pycache__" not in str(f) and ".venv" not in str(f)
        and "cdk.out" not in str(f) and "node_modules" not in str(f)
        and "test" not in str(f).lower()
    ]
    py_files = [f for f in py_files if "/src/" in f or "/infra/" in f]

    builder = EnhancedCPGBuilder()
    cpg = builder.build(py_files, infra_auth_map=INFRA_AUTH_MAP)
    print(f"        CPG: {cpg.node_count()} nodes, {cpg.edge_count()} edges")
    print(f"        {len(cpg.sources)} sources, {len(cpg.sinks)} sinks, "
          f"{len(builder.functions)} functions")

    # ════════════════════════════════════════════════════════════
    # STAGE 2: Run Semgrep (V2 rules) + Generate Evidence Walks
    # ════════════════════════════════════════════════════════════
    print("  [2/6] Running Semgrep + generating evidence walks...")
    semgrep_findings = _run_semgrep(repo)
    walker = EvidenceWalker(cpg, builder)

    evidence_walks = []
    for finding in semgrep_findings:
        walk = walker.generate_walk(finding)
        if walk:
            evidence_walks.append((finding, walk))

    print(f"        {len(semgrep_findings)} semgrep findings, "
          f"{len(evidence_walks)} with evidence walks")

    # ════════════════════════════════════════════════════════════
    # STAGE 2b: Z3 Formal IAM Verification (Zelkova)
    # ════════════════════════════════════════════════════════════
    print("  [2b/6] Running Z3 formal IAM verification...")
    z3_findings = _run_z3_iam(repo)
    print(f"         {len(z3_findings)} formally proven IAM findings")

    # Z3 findings are infra-level, passed directly to report generator

    # ════════════════════════════════════════════════════════════
    # STAGE 3: Absence Detection
    # ════════════════════════════════════════════════════════════
    print("  [3/6] Running absence detection...")
    absence_detector = AbsenceDetector(cpg, builder)
    absence_findings = absence_detector.detect()
    print(f"        {len(absence_findings)} missing-control findings")

    # ════════════════════════════════════════════════════════════
    # STAGE 4: Differential Analysis
    # ════════════════════════════════════════════════════════════
    print("  [4/6] Running differential path analysis...")
    diff_analyzer = DifferentialAnalyzer(cpg, builder)
    differential_findings = diff_analyzer.analyze()
    print(f"        {len(differential_findings)} inconsistency findings")

    # ════════════════════════════════════════════════════════════
    # STAGE 5: Attack Chain Synthesis
    # ════════════════════════════════════════════════════════════
    print("  [5/6] Synthesizing attack chains...")
    # Combine all findings for chain analysis
    all_findings_for_chains = []

    for finding, walk in evidence_walks:
        all_findings_for_chains.append(finding)

    for af in absence_findings:
        all_findings_for_chains.append({
            "id": af.id,
            "title": af.title,
            "severity": af.severity,
            "category": af.category,
            "file_path": af.file_path,
        })

    for df in differential_findings:
        all_findings_for_chains.append({
            "id": df.id,
            "title": df.title,
            "severity": df.severity,
            "category": df.category,
            "file_path": df.weaker_path.entry_file,
        })

    # Add synthetic findings for known issues detected via infra analysis
    all_findings_for_chains.extend(_synthetic_infra_findings(repo))

    chain_synth = ChainSynthesizer()
    attack_chains = chain_synth.synthesize(all_findings_for_chains)
    critical_chains = [c for c in attack_chains if c.composite_severity == "CRITICAL"]
    print(f"        {len(attack_chains)} chains ({len(critical_chains)} critical)")

    # ════════════════════════════════════════════════════════════
    # STAGE 6: Report Generation
    # ════════════════════════════════════════════════════════════
    print("  [6/6] Generating report...")
    # Add synthetic infra findings directly to the report
    synthetic = _synthetic_infra_findings(repo)
    # Convert to absence-style findings for the report
    from v4.analysis.absence_detector import AbsenceFinding
    for sf in synthetic:
        absence_findings.append(AbsenceFinding(
            id=sf["id"], title=sf["title"], description=sf.get("title", ""),
            severity=sf["severity"], confidence=0.9,
            file_path=sf.get("file_path", ""), line=0,
            handler_name="", sink_text="", missing_guard=sf["category"],
            category=sf["category"],
        ))

    report_gen = ReportGenerator(repo_path)
    report = report_gen.generate(
        evidence_walks=evidence_walks,
        absence_findings=absence_findings,
        differential_findings=differential_findings,
        attack_chains=attack_chains,
        z3_findings=z3_findings,
    )

    elapsed = time.time() - start_time

    # Save outputs
    output_dir = repo / ".security-agent" / "v4-state"
    output_dir.mkdir(parents=True, exist_ok=True)

    report_md = report.render_markdown()
    (output_dir / "v4_report.md").write_text(report_md)
    (output_dir / "v4_report.json").write_text(report.render_json())

    print()
    print("═" * 60)
    print("  V4 PIPELINE COMPLETE")
    print("═" * 60)
    print()
    print(f"  Findings: {report.summary['total_findings']}")
    print(f"    Critical: {report.summary['severity_distribution'].get('CRITICAL', 0)}")
    print(f"    High:     {report.summary['severity_distribution'].get('HIGH', 0)}")
    print(f"    Medium:   {report.summary['severity_distribution'].get('MEDIUM', 0)}")
    print(f"  Attack Chains: {len(attack_chains)} ({len(critical_chains)} critical)")
    print(f"  Duration: {elapsed:.1f}s")
    print()
    print(f"  Outputs:")
    print(f"    Report (MD):   {output_dir / 'v4_report.md'}")
    print(f"    Report (JSON): {output_dir / 'v4_report.json'}")
    print()
    print("═" * 60)

    return report


def _run_semgrep(repo: Path) -> list[dict]:
    """Run V2 semgrep rules and return findings."""
    import subprocess

    rules_dir = Path(__file__).parent.parent / "v2"
    findings = []

    rule_files = [
        ("semgrep_rules.yaml", "src"),
        ("semgrep_rules_gaps.yaml", "src"),
        ("semgrep_rules_frontend.yaml", "frontend"),
    ]

    for rule_file, target_subdir in rule_files:
        rule_path = rules_dir / rule_file
        target_path = repo / target_subdir

        if not rule_path.exists() or not target_path.exists():
            continue

        try:
            result = subprocess.run(
                ["semgrep", "--config", str(rule_path), str(target_path),
                 "--json", "--quiet", "--no-git-ignore"],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode in (0, 1):  # 1 = findings found
                data = json.loads(result.stdout) if result.stdout else {}
                for r in data.get("results", []):
                    severity_map = {"ERROR": "CRITICAL", "WARNING": "HIGH", "INFO": "MEDIUM"}
                    findings.append({
                        "id": f"semgrep-{len(findings)}",
                        "title": r.get("check_id", "").split(".")[-1],
                        "severity": severity_map.get(
                            r.get("extra", {}).get("severity", ""), "MEDIUM"
                        ),
                        "confidence": 0.8,
                        "file_path": r.get("path", ""),
                        "line": r.get("start", {}).get("line", 0),
                        "cwe": str(r.get("extra", {}).get("metadata", {}).get("cwe", "")),
                        "category": r.get("extra", {}).get("metadata", {}).get("category", ""),
                    })
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning(f"Semgrep failed for {rule_file}: {e}")

    # Also run V4 crypto/auth rules
    v4_rules = Path(__file__).parent / "rules" / "crypto_auth.yaml"
    if v4_rules.exists():
        try:
            result = subprocess.run(
                ["semgrep", "--config", str(v4_rules), str(repo / "src"),
                 "--json", "--quiet", "--no-git-ignore"],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode in (0, 1):
                data = json.loads(result.stdout) if result.stdout else {}
                for r in data.get("results", []):
                    findings.append({
                        "id": f"semgrep-crypto-{len(findings)}",
                        "title": r.get("check_id", "").split(".")[-1],
                        "severity": "HIGH",
                        "confidence": 0.9,
                        "file_path": r.get("path", ""),
                        "line": r.get("start", {}).get("line", 0),
                        "cwe": str(r.get("extra", {}).get("metadata", {}).get("cwe", "")),
                        "category": r.get("extra", {}).get("metadata", {}).get("category", ""),
                    })
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass

    return findings


def _run_z3_iam(repo: Path) -> list[dict]:
    """Run Z3 formal IAM verification against infrastructure."""
    findings = []
    try:
        from src.agents.infrastructure.cfn_parser import CloudFormationParser
        from src.agents.infrastructure.z3_iam_analyzer import Z3IAMAnalyzer
        from src.agents.infrastructure.deterministic_checks import DeterministicChecker
        from src.agents.infrastructure.iam_analyzer import IAMAnalyzer

        # Parse CDK stacks into InfraGraph
        all_resources = {}
        all_content = ""
        stack_dir = repo / "infra" / "stacks"
        if not stack_dir.exists():
            return findings

        for stack_file in stack_dir.glob("*.py"):
            content = stack_file.read_text()
            all_content += content + "\n"
            lines = content.split("\n")
            for i, line in enumerate(lines):
                if "lambda_.Function(" in line or "lambda_.DockerImageFunction(" in line:
                    all_resources[f"Lambda_{stack_file.stem}_{len(all_resources)}"] = {
                        "Type": "AWS::Lambda::Function",
                        "Properties": {"SourceLine": i + 1},
                        "SourceFile": str(stack_file),
                    }
                elif "dynamodb.Table(" in line:
                    all_resources[f"DynamoDB_{stack_file.stem}_{len(all_resources)}"] = {
                        "Type": "AWS::DynamoDB::Table",
                        "Properties": {"SourceLine": i + 1},
                        "SourceFile": str(stack_file),
                    }
                elif "s3.Bucket(" in line:
                    all_resources[f"S3_{stack_file.stem}_{len(all_resources)}"] = {
                        "Type": "AWS::S3::Bucket",
                        "Properties": {"SourceLine": i + 1},
                        "SourceFile": str(stack_file),
                    }

        template = {"Resources": all_resources, "RawContent": all_content}
        parser = CloudFormationParser()
        graph = parser.parse(template)

        # Run Z3 analyzer
        z3_analyzer = Z3IAMAnalyzer()
        z3_results = z3_analyzer.analyze(graph)

        for f in z3_results:
            findings.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity.name,
                "category": f.category,
                "file_path": "infra/stacks/",
                "line": f.location.start_line if f.location else 0,
                "cwe": f.cwe or "",
                "description": f.description,
                "evidence": f.evidence.snippet if f.evidence else "",
                "z3_proof": f.evidence.reasoning if f.evidence else "",
            })

        # Also run deterministic IAM checks
        iam_analyzer = IAMAnalyzer()
        iam_results = iam_analyzer.analyze(graph)
        for f in iam_results:
            findings.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity.name,
                "category": f.category,
                "file_path": "infra/stacks/",
                "line": f.location.start_line if f.location else 0,
                "cwe": f.cwe or "",
            })

    except ImportError as e:
        logger.warning(f"Z3 not available: {e}. Install with: pip install z3-solver")
    except Exception as e:
        logger.warning(f"Z3 IAM analysis failed: {e}")

    return findings


def _synthetic_infra_findings(repo: Path) -> list[dict]:
    """
    Generate synthetic findings from infrastructure analysis.
    These represent issues detectable from CDK code that enhance chain synthesis.
    """
    findings = []

    # Check for unauthenticated endpoints in CDK
    infra_dir = repo / "infra" / "stacks"
    if infra_dir.exists():
        for stack_file in infra_dir.glob("*.py"):
            content = stack_file.read_text()

            # Detect API routes without authorizer
            if "LambdaIntegration" in content and "authorizer" not in content.lower():
                findings.append({
                    "id": "infra-no-auth-route",
                    "title": "API Gateway route without authorizer",
                    "severity": "MEDIUM",
                    "category": "missing_auth",
                    "file_path": str(stack_file),
                })

            # Detect self-signup with auto-admin
            if "self_sign_up_enabled" in content and "admin" in content:
                findings.append({
                    "id": "infra-signup-admin",
                    "title": "Self-signup auto-assigns admin role",
                    "severity": "HIGH",
                    "category": "self_signup_admin",
                    "file_path": str(stack_file),
                })

            # Detect wildcard CORS
            if "Access-Control-Allow-Origin" in content and "*" in content:
                findings.append({
                    "id": "infra-cors-wildcard",
                    "title": "Wildcard CORS on API endpoints",
                    "severity": "LOW",
                    "category": "cors_wildcard",
                    "file_path": str(stack_file),
                })

    # Check for exposed API keys in frontend
    frontend_dir = repo / "frontend"
    if frontend_dir.exists():
        for js_file in frontend_dir.rglob("*.js"):
            try:
                content = js_file.read_text()
                if "x-api-key" in content and "'" in content:
                    findings.append({
                        "id": "frontend-apikey",
                        "title": "API key hardcoded in client JavaScript",
                        "severity": "MEDIUM",
                        "category": "api_key_exposed",
                        "file_path": str(js_file),
                    })
                    break
            except (OSError, UnicodeDecodeError):
                pass

    # Secret rotation check
    if infra_dir.exists():
        for stack_file in infra_dir.glob("*.py"):
            try:
                content = stack_file.read_text()
                if ("secret" in content.lower() or "credentials" in content.lower()):
                    if "rotation" not in content.lower() or "rotation not configured" in content.lower():
                        findings.append({
                            "id": "infra-no-rotation",
                            "title": "No rotation policy for database credentials and API keys",
                            "severity": "MEDIUM",
                            "category": "missing_secret_rotation",
                            "file_path": str(stack_file),
                        })
                        break
            except (OSError, UnicodeDecodeError):
                pass

    # Custom crypto detection
    src_dir = repo / "src"
    if src_dir.exists():
        for py_file in src_dir.rglob("*.py"):
            try:
                content = py_file.read_text()
                if "pow(" in content and "int.from_bytes" in content and ("signature" in content or "RSA" in content.lower()):
                    findings.append({
                        "id": "custom-crypto",
                        "title": "Custom RSA signature verification instead of established library",
                        "severity": "MEDIUM",
                        "category": "custom_crypto",
                        "file_path": str(py_file),
                    })
                    break
            except (OSError, UnicodeDecodeError):
                pass

    return findings


def main():
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "/Users/indukuk/compliance"

    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    run_v4(repo_path)


if __name__ == "__main__":
    main()
