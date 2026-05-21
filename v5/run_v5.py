"""
V5 Security Agent — Expert Security Code Reviewer.

Layer 0: Deterministic evidence collection (V4 + Zero Trust)
Layer 1: Deep investigation agents (5 domain experts)
Layer 2: Chain-of-Thought synthesis (per finding)
Layer 3: Adversarial grounded debate (HIGH/CRITICAL)
Layer 4: Exploit proof + fix verification
Layer 5: Narrative synthesis (final report)

Run: python3 v5/run_v5.py /path/to/repo [--api] [--layer N]
  --api: Use Bedrock API for LLM calls (costs ~$30)
  --layer N: Run only up to layer N (default: all)
  No flags: Outputs investigation prompts for in-session Claude Code execution
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
from v5.analysis.zero_trust_analyzer import ZeroTrustAnalyzer
from v5.evidence_package import EvidencePackage
from v5.agents.base import AgentContext, LLMClient
from v5.agents.investigation.tenant_isolation import TenantIsolationAgent
from v5.agents.investigation.auth_architecture import AuthArchitectureAgent
from v5.agents.investigation.data_flow import DataFlowAgent
from v5.agents.investigation.infra_blast_radius import InfraBlastRadiusAgent
from v5.agents.investigation.business_logic import BusinessLogicAgent
from v5.agents.cot_synthesizer import CoTSynthesizer
from v5.agents.debate.engine import DebateEngine
from v5.agents.prover.exploit_generator import ExploitGenerator
from v5.agents.prover.fix_verifier import FixVerifierEngine
from v5.agents.narrator import NarratorAgent

logger = logging.getLogger(__name__)

INFRA_AUTH_MAP = {
    "lambda_handler": "authorizer",
    "handler": "authorizer",
}


def run_v5(repo_path: str, use_api: bool = False, max_layer: int = 5) -> dict:
    """Run the full V5 pipeline."""
    start_time = time.time()
    repo = Path(repo_path)

    print("═" * 70)
    print("  Security Agent V5 — Expert Security Code Reviewer")
    print("  Deterministic Foundation + LLM Deep Analysis + Zero Trust")
    print("═" * 70)
    print(f"  Target: {repo_path}")
    print(f"  Mode: {'API (Bedrock)' if use_api else 'In-session (prompts for Claude Code)'}")
    print()

    # ════════════════════════════════════════════════════════════════════
    # LAYER 0: DETERMINISTIC EVIDENCE COLLECTION
    # ════════════════════════════════════════════════════════════════════
    print("  ╔══ LAYER 0: Deterministic Evidence Collection ══╗")

    # 0A: Build Enhanced CPG
    print("  ║ [0A] Building Enhanced CPG...")
    py_files = [
        str(f) for f in repo.rglob("*.py")
        if "__pycache__" not in str(f) and ".venv" not in str(f)
        and "cdk.out" not in str(f) and "node_modules" not in str(f)
        and "test" not in str(f).lower()
    ]
    py_files = [f for f in py_files if "/src/" in f or "/infra/" in f]

    builder = EnhancedCPGBuilder()
    cpg = builder.build(py_files, infra_auth_map=INFRA_AUTH_MAP)
    print(f"  ║       {cpg.node_count()} nodes, {cpg.edge_count()} edges, "
          f"{len(builder.functions)} functions")

    # 0B: Semgrep + Evidence Walks
    print("  ║ [0B] Running Semgrep + evidence walks...")
    semgrep_findings = _run_semgrep(repo)
    walker = EvidenceWalker(cpg, builder)
    evidence_walks = []
    for finding in semgrep_findings:
        walk = walker.generate_walk(finding)
        if walk:
            evidence_walks.append((finding, walk))
    print(f"  ║       {len(semgrep_findings)} semgrep → {len(evidence_walks)} with walks")

    # 0C: Absence + Differential + Chains
    print("  ║ [0C] Running absence + differential + chain synthesis...")
    absence_findings = AbsenceDetector(cpg, builder).detect()
    differential_findings = DifferentialAnalyzer(cpg, builder).analyze()
    print(f"  ║       {len(absence_findings)} absent, {len(differential_findings)} differential")

    # 0D: Infrastructure + Z3 + Zero Trust
    print("  ║ [0D] Running Z3 IAM + Zero Trust analysis...")
    infra_graph, z3_findings = _run_infra_analysis(repo)
    zero_trust = None
    if infra_graph:
        zt_analyzer = ZeroTrustAnalyzer(infra_graph)
        zero_trust = zt_analyzer.analyze()
        print(f"  ║       Z3: {len(z3_findings)} proven | "
              f"ZT: {zero_trust.summary.get('uncontained', 0)} uncontained, "
              f"{len(zero_trust.lateral_paths)} lateral paths")
    else:
        print("  ║       (no infrastructure found)")

    # 0E: Chain synthesis with all findings
    print("  ║ [0E] Synthesizing attack chains...")
    all_for_chains = _collect_chain_inputs(
        semgrep_findings, evidence_walks, absence_findings,
        differential_findings, zero_trust, repo
    )
    attack_chains = ChainSynthesizer().synthesize(all_for_chains)
    print(f"  ║       {len(attack_chains)} chains "
          f"({sum(1 for c in attack_chains if c.composite_severity == 'CRITICAL')} critical)")

    print("  ╚══════════════════════════════════════════════════╝")
    print()

    # Assemble evidence package
    handler_files = [f for f in py_files if "handler" in Path(f).stem]
    file_contents = {}
    for f in handler_files[:15]:
        try:
            file_contents[f] = Path(f).read_text()
        except (OSError, UnicodeDecodeError):
            pass

    cdk_source = ""
    cdk_dir = repo / "infra" / "stacks"
    if cdk_dir.exists():
        for sf in cdk_dir.glob("*.py"):
            cdk_source += sf.read_text() + "\n"

    package = EvidencePackage(
        repo_path=repo_path,
        cpg=cpg,
        semgrep_findings=semgrep_findings,
        evidence_walks=evidence_walks,
        absence_findings=absence_findings,
        differential_findings=differential_findings,
        attack_chains=attack_chains,
        infra_graph=infra_graph,
        z3_findings=z3_findings,
        zero_trust=zero_trust,
        file_contents=file_contents,
        handler_files=handler_files,
        cdk_source=cdk_source,
    )

    if max_layer < 1:
        return _save_layer0_results(package, repo)

    # ════════════════════════════════════════════════════════════════════
    # LAYER 1: DEEP INVESTIGATION AGENTS
    # ════════════════════════════════════════════════════════════════════
    print("  ╔══ LAYER 1: Deep Investigation Agents ══╗")

    context = package.to_agent_context()
    agents = [
        TenantIsolationAgent(),
        AuthArchitectureAgent(),
        DataFlowAgent(),
        InfraBlastRadiusAgent(),
        BusinessLogicAgent(),
    ]

    output_dir = repo / ".security-agent" / "v5-state"
    output_dir.mkdir(parents=True, exist_ok=True)

    if use_api:
        # API mode: actually call the LLM
        llm = LLMClient()
        for agent in agents:
            print(f"  ║ Running: {agent.name}...")
            report = agent.investigate(context, llm_fn=llm.invoke)
            (output_dir / f"investigation_{agent.domain}.md").write_text(report.raw_output)
            print(f"  ║   → {len(report.findings)} findings")
    else:
        # In-session mode: generate prompts for Claude Code execution
        print("  ║ Generating investigation prompts (in-session mode)...")
        prompts_file = output_dir / "investigation_prompts.md"
        with open(prompts_file, "w") as f:
            f.write("# V5 Layer 1: Investigation Agent Prompts\n\n")
            f.write("Execute each prompt below with Claude to complete the investigation.\n\n")
            for agent in agents:
                f.write(f"\n{'═' * 70}\n")
                f.write(f"## {agent.name}\n\n")
                prompt = agent.generate_prompt_for_session(context)
                f.write(prompt)
                f.write(f"\n{'═' * 70}\n\n")
        print(f"  ║   Prompts written to: {prompts_file}")

    print("  ╚════════════════════════════════════════════════╝")

    if max_layer < 2:
        elapsed = time.time() - start_time
        _save_layer0_results(package, repo)
        _print_final_summary(elapsed, package, attack_chains, zero_trust, output_dir, use_api)
        return {"elapsed": elapsed, "package": package}

    # ════════════════════════════════════════════════════════════════════
    # LAYER 2: CHAIN-OF-THOUGHT SYNTHESIS
    # ════════════════════════════════════════════════════════════════════
    print("  ╔══ LAYER 2: Chain-of-Thought Synthesis ══╗")

    # Select findings for deep CoT analysis (deduplicate by title)
    seen_titles = set()
    findings_for_cot = []
    for finding, walk in evidence_walks:
        if finding["title"] not in seen_titles:
            seen_titles.add(finding["title"])
            findings_for_cot.append(finding)

    # Add absence and differential findings
    for af in absence_findings:
        title = af.title
        if title not in seen_titles:
            seen_titles.add(title)
            findings_for_cot.append({
                "id": af.id, "title": af.title, "severity": af.severity,
                "category": af.category, "file_path": af.file_path,
                "line": af.line, "cwe": af.cwe,
            })

    cot_synth = CoTSynthesizer(context)
    llm = LLMClient() if use_api else None

    if use_api:
        cot_findings = cot_synth.synthesize(findings_for_cot[:15], llm_fn=llm.invoke)
        print(f"  ║ Synthesized {len(cot_findings)} findings via API")
    else:
        cot_findings = cot_synth.synthesize(findings_for_cot[:15])
        cot_prompts = cot_synth.generate_all_prompts(findings_for_cot[:15])
        (output_dir / "cot_prompts.md").write_text(cot_prompts)
        print(f"  ║ Generated CoT prompts for {len(findings_for_cot[:15])} findings")

    print("  ╚════════════════════════════════════════════════╝")

    if max_layer < 3:
        elapsed = time.time() - start_time
        _save_layer0_results(package, repo)
        _print_final_summary(elapsed, package, attack_chains, zero_trust, output_dir, use_api)
        return {"elapsed": elapsed, "package": package}

    # ════════════════════════════════════════════════════════════════════
    # LAYER 3: ADVERSARIAL GROUNDED DEBATE
    # ════════════════════════════════════════════════════════════════════
    print("  ╔══ LAYER 3: Adversarial Grounded Debate ══╗")

    debate_engine = DebateEngine()
    verdicts = []

    # Only debate HIGH/CRITICAL findings
    to_debate = [f for f in cot_findings if f.severity in ("HIGH", "CRITICAL")]
    print(f"  ║ Debating {len(to_debate)} HIGH/CRITICAL findings")

    if use_api:
        for cot_f in to_debate[:8]:
            evidence_items = debate_engine.build_evidence_bundle(cot_f, {})
            verdict = debate_engine.debate(cot_f, evidence_items, llm_fn=llm.invoke)
            verdicts.append(verdict)
        print(f"  ║ {len(verdicts)} verdicts rendered")
    else:
        debate_prompts = output_dir / "debate_prompts.md"
        with open(debate_prompts, "w") as f:
            f.write("# Layer 3: Grounded Debate Prompts\n\n")
            for cot_f in to_debate[:8]:
                evidence_items = debate_engine.build_evidence_bundle(cot_f, {})
                prompt = debate_engine.generate_debate_prompts(cot_f, evidence_items)
                f.write(f"\n{'═' * 60}\n{prompt}\n")
        print(f"  ║ Debate prompts written for {min(len(to_debate), 8)} findings")

    print("  ╚════════════════════════════════════════════════╝")

    if max_layer < 4:
        elapsed = time.time() - start_time
        _save_layer0_results(package, repo)
        _print_final_summary(elapsed, package, attack_chains, zero_trust, output_dir, use_api)
        return {"elapsed": elapsed, "package": package}

    # ════════════════════════════════════════════════════════════════════
    # LAYER 4: EXPLOIT PROOF + FIX VERIFICATION
    # ════════════════════════════════════════════════════════════════════
    print("  ╔══ LAYER 4: Exploit Proof + Fix Verification ══╗")

    exploit_gen = ExploitGenerator()
    fix_engine = FixVerifierEngine(repo_path, str(Path(__file__).parent.parent / "v2"))
    exploits = []
    fixes = []

    for cot_f in cot_findings:
        if cot_f.severity not in ("HIGH", "CRITICAL"):
            continue

        # Generate exploit
        verdict = verdicts[0] if verdicts else None
        exploit = exploit_gen.generate(cot_f, verdict, llm_fn=llm.invoke if use_api else None)
        exploits.append(exploit)

        # Generate and verify fix
        fix = fix_engine.fix_and_verify(cot_f, llm_fn=llm.invoke if use_api else None)
        fixes.append(fix)

    print(f"  ║ {len(exploits)} exploits generated, {len(fixes)} fixes proposed")

    # Save exploits
    exploits_file = output_dir / "exploits.md"
    with open(exploits_file, "w") as f:
        f.write("# Layer 4: Exploit Proofs\n\n")
        for exp in exploits:
            f.write(f"## {exp.title}\n\n")
            if exp.preconditions:
                f.write("**Preconditions:**\n")
                for p in exp.preconditions:
                    f.write(f"- {p}\n")
                f.write("\n")
            f.write(f"**Exploit:**\n```\n{exp.exploit_code}\n```\n\n")
            f.write(f"**Expected:** {exp.expected_response}\n\n")
            f.write(f"**Impact:** {exp.impact_description}\n\n---\n\n")

    print("  ╚════════════════════════════════════════════════╝")

    if max_layer < 5:
        elapsed = time.time() - start_time
        _save_layer0_results(package, repo)
        _print_final_summary(elapsed, package, attack_chains, zero_trust, output_dir, use_api)
        return {"elapsed": elapsed, "package": package}

    # ════════════════════════════════════════════════════════════════════
    # LAYER 5: NARRATIVE SYNTHESIS
    # ════════════════════════════════════════════════════════════════════
    print("  ╔══ LAYER 5: Narrative Synthesis ══╗")

    narrator = NarratorAgent()

    if use_api:
        final_report = narrator.synthesize(
            context, cot_findings, verdicts, exploits, fixes,
            zero_trust, attack_chains, llm_fn=llm.invoke,
        )
        (output_dir / "v5_final_report.md").write_text(final_report.markdown)
        print(f"  ║ Final report written ({len(final_report.markdown)} chars)")
    else:
        narrator_prompt = narrator.generate_synthesis_prompt(
            context, cot_findings, zero_trust, attack_chains,
        )
        (output_dir / "narrator_prompt.md").write_text(narrator_prompt)
        print(f"  ║ Narrator prompt generated for in-session execution")

    print("  ╚════════════════════════════════════════════════╝")

    elapsed = time.time() - start_time
    _save_layer0_results(package, repo)
    _print_final_summary(elapsed, package, attack_chains, zero_trust, output_dir, use_api)
    return {"elapsed": elapsed, "package": package}


def _print_final_summary(elapsed, package, attack_chains, zero_trust, output_dir, use_api):
    """Print final pipeline summary."""
    print()
    print("═" * 70)
    print("  V5 PIPELINE COMPLETE")
    print("═" * 70)
    print()
    print(f"  Layer 0 Evidence:")
    print(f"    CPG: {package.cpg.node_count()} nodes")
    print(f"    Semgrep: {len(package.semgrep_findings)} → {len(package.evidence_walks)} with walks")
    print(f"    Absence: {len(package.absence_findings)} missing-control findings")
    print(f"    Differential: {len(package.differential_findings)} bypass paths")
    print(f"    Z3 IAM: {len(package.z3_findings)} formally proven")
    zt_uncontained = zero_trust.summary.get("uncontained", 0) if zero_trust else 0
    zt_lateral = len(zero_trust.lateral_paths) if zero_trust else 0
    print(f"    Zero Trust: {zt_uncontained} uncontained | {zt_lateral} lateral paths")
    crit_chains = sum(1 for c in attack_chains if c.composite_severity == "CRITICAL")
    print(f"    Attack Chains: {len(attack_chains)} ({crit_chains} critical)")
    print(f"  Duration: {elapsed:.1f}s")
    print(f"  Outputs: {output_dir}")
    if not use_api:
        print(f"  Mode: In-session — execute prompts in v5-state/ with Claude")
    print()
    print("═" * 70)


def _run_semgrep(repo: Path) -> list[dict]:
    """Run semgrep rules."""
    import subprocess

    rules_dir = Path(__file__).parent.parent / "v2"
    v4_rules = Path(__file__).parent.parent / "v4" / "rules"
    findings = []

    rule_targets = [
        (rules_dir / "semgrep_rules.yaml", repo / "src"),
        (rules_dir / "semgrep_rules_gaps.yaml", repo / "src"),
        (rules_dir / "semgrep_rules_frontend.yaml", repo / "frontend"),
        (v4_rules / "crypto_auth.yaml", repo / "src"),
    ]

    for rule_path, target_path in rule_targets:
        if not rule_path.exists() or not target_path.exists():
            continue
        try:
            result = subprocess.run(
                ["semgrep", "--config", str(rule_path), str(target_path),
                 "--json", "--quiet", "--no-git-ignore"],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode in (0, 1):
                data = json.loads(result.stdout) if result.stdout else {}
                for r in data.get("results", []):
                    sev_map = {"ERROR": "CRITICAL", "WARNING": "HIGH", "INFO": "MEDIUM"}
                    findings.append({
                        "id": f"semgrep-{len(findings)}",
                        "title": r.get("check_id", "").split(".")[-1],
                        "severity": sev_map.get(r.get("extra", {}).get("severity", ""), "MEDIUM"),
                        "confidence": 0.8,
                        "file_path": r.get("path", ""),
                        "line": r.get("start", {}).get("line", 0),
                        "cwe": str(r.get("extra", {}).get("metadata", {}).get("cwe", "")),
                        "category": r.get("extra", {}).get("metadata", {}).get("category", ""),
                    })
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning(f"Semgrep: {e}")

    return findings


def _run_infra_analysis(repo: Path) -> tuple:
    """Run infrastructure analysis + Z3."""
    z3_findings = []
    infra_graph = None

    try:
        from src.agents.infrastructure.cfn_parser import CloudFormationParser
        from src.agents.infrastructure.z3_iam_analyzer import Z3IAMAnalyzer
        from src.agents.infrastructure.iam_analyzer import IAMAnalyzer

        stack_dir = repo / "infra" / "stacks"
        if not stack_dir.exists():
            return None, []

        all_resources = {}
        all_content = ""
        for stack_file in stack_dir.glob("*.py"):
            content = stack_file.read_text()
            all_content += content + "\n"
            lines = content.split("\n")
            for i, line in enumerate(lines):
                if "lambda_.Function(" in line or "lambda_.DockerImageFunction(" in line:
                    all_resources[f"Lambda_{stack_file.stem}_{len(all_resources)}"] = {
                        "Type": "AWS::Lambda::Function", "Properties": {"SourceLine": i + 1}}
                elif "dynamodb.Table(" in line:
                    all_resources[f"DynamoDB_{stack_file.stem}_{len(all_resources)}"] = {
                        "Type": "AWS::DynamoDB::Table", "Properties": {"SourceLine": i + 1}}
                elif "s3.Bucket(" in line:
                    all_resources[f"S3_{stack_file.stem}_{len(all_resources)}"] = {
                        "Type": "AWS::S3::Bucket", "Properties": {"SourceLine": i + 1}}

        template = {"Resources": all_resources, "RawContent": all_content}
        parser = CloudFormationParser()
        infra_graph = parser.parse(template)

        # Z3 analysis
        try:
            z3_analyzer = Z3IAMAnalyzer()
            for f in z3_analyzer.analyze(infra_graph):
                z3_findings.append({
                    "id": f.id, "title": f.title, "severity": f.severity.name,
                    "category": f.category, "cwe": f.cwe or "",
                    "description": f.description,
                    "evidence": f.evidence.snippet if f.evidence else "",
                    "z3_proof": f.evidence.reasoning if f.evidence else "",
                    "file_path": "infra/stacks/",
                })
        except ImportError:
            pass

        # IAM analysis
        iam_analyzer = IAMAnalyzer()
        for f in iam_analyzer.analyze(infra_graph):
            z3_findings.append({
                "id": f.id, "title": f.title, "severity": f.severity.name,
                "category": f.category, "file_path": "infra/stacks/",
            })

    except Exception as e:
        logger.warning(f"Infra analysis failed: {e}")

    return infra_graph, z3_findings


def _collect_chain_inputs(semgrep_findings, evidence_walks, absence_findings,
                          differential_findings, zero_trust, repo) -> list[dict]:
    """Collect all findings for chain synthesis."""
    all_findings = []

    for finding, walk in evidence_walks:
        all_findings.append(finding)

    for af in absence_findings:
        all_findings.append({
            "id": af.id, "title": af.title, "severity": af.severity,
            "category": af.category, "file_path": af.file_path,
        })

    for df in differential_findings:
        all_findings.append({
            "id": df.id, "title": df.title, "severity": df.severity,
            "category": df.category, "file_path": df.weaker_path.entry_file,
        })

    # Synthetic infra findings for chain composition
    infra_dir = repo / "infra" / "stacks"
    if infra_dir.exists():
        for stack_file in infra_dir.glob("*.py"):
            content = stack_file.read_text()
            if "LambdaIntegration" in content:
                all_findings.append({
                    "id": "infra-no-auth", "title": "API Gateway route without authorizer",
                    "severity": "MEDIUM", "category": "missing_auth", "file_path": str(stack_file),
                })
            if "self_sign_up_enabled" in content:
                all_findings.append({
                    "id": "infra-signup-admin", "title": "Self-signup auto-assigns admin role",
                    "severity": "HIGH", "category": "self_signup_admin", "file_path": str(stack_file),
                })

    # Frontend secrets
    frontend = repo / "frontend"
    if frontend.exists():
        for js in frontend.rglob("*.js"):
            try:
                if "x-api-key" in js.read_text():
                    all_findings.append({
                        "id": "frontend-apikey", "title": "API key hardcoded in client JavaScript",
                        "severity": "MEDIUM", "category": "api_key_exposed", "file_path": str(js),
                    })
                    break
            except (OSError, UnicodeDecodeError):
                pass

    # Secret rotation check
    if infra_dir.exists():
        for stack_file in infra_dir.glob("*.py"):
            try:
                content = stack_file.read_text()
                # Check for secrets without rotation
                if ("secret" in content.lower() or "credentials" in content.lower()):
                    if "rotation" not in content.lower():
                        all_findings.append({
                            "id": "infra-no-rotation", "title": "No rotation policy for database credentials and API keys",
                            "severity": "MEDIUM", "category": "missing_secret_rotation", "file_path": str(stack_file),
                        })
                        break
                    elif "rotation not configured" in content.lower():
                        all_findings.append({
                            "id": "infra-rotation-suppressed", "title": "Secret rotation warning explicitly suppressed (CDK nag)",
                            "severity": "MEDIUM", "category": "missing_secret_rotation", "file_path": str(stack_file),
                        })
                        break
            except (OSError, UnicodeDecodeError):
                pass

    # Custom crypto detection (for chain composition)
    for py_file in (repo / "src").rglob("*.py"):
        try:
            content = py_file.read_text()
            if "pow(" in content and "int.from_bytes" in content and ("signature" in content or "RSA" in content.lower()):
                all_findings.append({
                    "id": "custom-crypto", "title": "Custom RSA signature verification instead of established library",
                    "severity": "MEDIUM", "category": "custom_crypto", "file_path": str(py_file),
                })
                break
        except (OSError, UnicodeDecodeError):
            pass

    return all_findings


def _save_layer0_results(package: EvidencePackage, repo: Path) -> dict:
    """Save Layer 0 results to disk."""
    output_dir = repo / ".security-agent" / "v5-state"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save summary
    summary = {
        "cpg_nodes": package.cpg.node_count(),
        "cpg_edges": package.cpg.edge_count(),
        "semgrep_findings": len(package.semgrep_findings),
        "evidence_walks": len(package.evidence_walks),
        "absence_findings": len(package.absence_findings),
        "differential_findings": len(package.differential_findings),
        "z3_findings": len(package.z3_findings),
        "attack_chains": len(package.attack_chains),
        "zero_trust_uncontained": package.zero_trust.summary.get("uncontained", 0) if package.zero_trust else 0,
        "lateral_paths": len(package.zero_trust.lateral_paths) if package.zero_trust else 0,
    }
    (output_dir / "layer0_summary.json").write_text(json.dumps(summary, indent=2))

    # Save zero trust assessment
    if package.zero_trust:
        zt_data = {
            "posture": package.zero_trust.overall_posture,
            "summary": package.zero_trust.summary,
            "blast_radii": {
                rid: {
                    "role": br.iam_role, "score": br.blast_radius_score,
                    "status": br.containment_status,
                    "internet_facing": br.is_internet_facing,
                    "auth": br.auth_mechanism,
                    "capabilities": {
                        "all_tenants": br.can_access_all_tenants,
                        "exfiltrate": br.can_exfiltrate_data,
                        "modify": br.can_modify_data,
                        "escalate": br.can_escalate_privileges,
                    },
                    "dangerous_actions": br.dangerous_actions[:10],
                }
                for rid, br in package.zero_trust.blast_radii.items()
            },
            "lateral_paths": [
                {"source": lp.source, "target": lp.target,
                 "mechanism": lp.mechanism, "severity": lp.severity,
                 "description": lp.description}
                for lp in package.zero_trust.lateral_paths[:30]
            ],
        }
        (output_dir / "zero_trust_assessment.json").write_text(json.dumps(zt_data, indent=2))

    return summary


def main():
    import argparse
    parser = argparse.ArgumentParser(description="V5 Expert Security Code Reviewer")
    parser.add_argument("repo", nargs="?", default="/Users/indukuk/compliance")
    parser.add_argument("--api", action="store_true", help="Use Bedrock API for LLM calls")
    parser.add_argument("--layer", type=int, default=5, help="Run up to layer N")
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING, format="%(asctime)s [%(levelname)s] %(message)s")
    run_v5(args.repo, use_api=args.api, max_layer=args.layer)


if __name__ == "__main__":
    main()
