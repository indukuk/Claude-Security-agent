"""
V6 Security Agent — Hybrid Zero-Day Discovery Pipeline.

Layer 0: Deterministic foundation (parallel: code ‖ infra+ZT ‖ frontend)
Layer 1: LLM discovery (parallel: novel patterns ‖ zero-day ‖ investigation)
Layer 2: CoT synthesis (parallel per finding)
Layer 3: Validation (parallel: debate ‖ ZT cross-ref ‖ zero-day validation)
Layer 4: Proof (parallel: exploit ‖ fix+verify ‖ regression tests)
Layer 5: Narrative synthesis (sequential)
Layer 6: Learning feedback loop (sequential)

Usage:
  python3 v6/run_v6.py /path/to/repo                    # Layer 0 only (free, 26s)
  python3 v6/run_v6.py /path/to/repo --layer 1          # + LLM discovery
  python3 v6/run_v6.py /path/to/repo --full             # All layers (~$15-20, ~15min)
  python3 v6/run_v6.py /path/to/repo --full --api       # With Bedrock API calls
"""
from __future__ import annotations

import sys
import time
import json
import logging
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, str(Path(__file__).parent.parent))

from v6.layer0.code_analyzer import run_code_analysis
from v6.layer0.infra_analyzer import run_infra_analysis
from v6.layer0.chain_synthesizer import ChainSynthesizer
from v6.evidence_package import EvidencePackage
from v6.report.pdf_generator import generate_pdf_report

logger = logging.getLogger(__name__)


def run_v6(repo_path: str, max_layer: int = 0, use_api: bool = False) -> EvidencePackage:
    """Run the V6 pipeline up to the specified layer."""
    start_time = time.time()
    repo = Path(repo_path)

    print("═" * 70)
    print("  V6 Security Agent — Hybrid Zero-Day Discovery Pipeline")
    print("═" * 70)
    print(f"  Target: {repo_path}")
    print(f"  Mode: {'API (Bedrock)' if use_api else 'In-session / Layer 0 only'}")
    print(f"  Layers: 0{' → ' + str(max_layer) if max_layer > 0 else ' (deterministic only)'}")
    print()

    # ════════════════════════════════════════════════════════════════════
    # LAYER 0: DETERMINISTIC FOUNDATION (parallel tracks)
    # ════════════════════════════════════════════════════════════════════
    print("  ╔══ LAYER 0: Deterministic Foundation (parallel) ══╗")

    layer0_start = time.time()

    # Run three tracks in parallel
    with ThreadPoolExecutor(max_workers=3) as executor:
        future_code = executor.submit(run_code_analysis, repo_path)
        future_infra = executor.submit(run_infra_analysis, repo_path)
        # Frontend is handled within code analysis semgrep rules

        code_result = future_code.result()
        infra_result = future_infra.result()

    layer0_time = time.time() - layer0_start

    print(f"  ║  Code:  CPG {code_result.cpg.node_count()} nodes | "
          f"Semgrep {len(code_result.semgrep_findings)} | "
          f"Walks {len(code_result.evidence_walks)} | "
          f"Absence {len(code_result.absence_findings)} | "
          f"Diff {len(code_result.differential_findings)}")
    print(f"  ║  Infra: Z3 {len(infra_result.z3_findings)} | "
          f"ZT {'posture=' + infra_result.zero_trust.overall_posture if infra_result.zero_trust else 'N/A'} | "
          f"Lateral {len(infra_result.zero_trust.lateral_paths) if infra_result.zero_trust else 0}")

    # Chain synthesis (needs both code + infra results)
    all_for_chains = _collect_chain_inputs(code_result, infra_result)
    attack_chains = ChainSynthesizer().synthesize(all_for_chains)
    crit_chains = sum(1 for c in attack_chains if c.composite_severity == "CRITICAL")
    print(f"  ║  Chains: {len(attack_chains)} ({crit_chains} critical)")
    print(f"  ║  Time: {layer0_time:.1f}s")
    print("  ╚═══════════════════════════════════════════════════╝")

    # Assemble evidence package
    package = EvidencePackage(
        repo_path=repo_path,
        cpg=code_result.cpg,
        semgrep_findings=code_result.semgrep_findings,
        evidence_walks=code_result.evidence_walks,
        absence_findings=code_result.absence_findings,
        differential_findings=code_result.differential_findings,
        infra_graph=infra_result.infra_graph,
        z3_findings=infra_result.z3_findings,
        iam_findings=infra_result.iam_findings,
        zero_trust=infra_result.zero_trust,
        synthetic_findings=infra_result.synthetic_findings,
        attack_chains=attack_chains,
        file_contents=code_result.file_contents,
        handler_files=code_result.handler_files,
        cdk_source=infra_result.cdk_source,
    )
    package.total_findings_layer0 = (
        len(code_result.semgrep_findings) +
        len(code_result.absence_findings) +
        len(code_result.differential_findings) +
        len(infra_result.z3_findings) +
        len(infra_result.synthetic_findings)
    )

    # Save Layer 0 outputs to scanner's own reports directory (not in target repo)
    repo_name = repo.name
    output_dir = Path(__file__).parent / "reports" / repo_name
    package.save(output_dir)

    # Generate PDF report
    pdf_data = _build_pdf_data(package, attack_chains)
    pdf_path = str(output_dir / "security-report.pdf")
    generate_pdf_report(pdf_data, pdf_path, title=f"Security Analysis Report — {repo_name}")
    print(f"  ║  Report: {pdf_path}")

    if max_layer >= 1:
        # ════════════════════════════════════════════════════════════════
        # LAYER 1: LLM DISCOVERY (3 parallel tracks)
        # ════════════════════════════════════════════════════════════════
        print()
        print("  ╔══ LAYER 1: LLM Discovery (3 parallel tracks) ══╗")
        _run_layer1(package, output_dir, use_api)
        print("  ╚═══════════════════════════════════════════════════════╝")

    if max_layer >= 2:
        print()
        print("  ╔══ LAYER 2: CoT Synthesis ══╗")
        print("  ║  (pending prompt engineering — Task #31)")
        print("  ╚═════════════════════════════╝")

    if max_layer >= 3:
        print()
        print("  ╔══ LAYER 3: Validation ══╗")
        print("  ║  (pending prompt engineering — Task #29)")
        print("  ╚═════════════════════════╝")

    if max_layer >= 4:
        print()
        print("  ╔══ LAYER 4: Proof ══╗")
        print("  ║  (pending implementation — Tasks #20, #13)")
        print("  ╚════════════════════╝")

    if max_layer >= 5:
        print()
        print("  ╔══ LAYER 5: Narrative Synthesis ══╗")
        print("  ║  (pending prompt engineering — Task #32)")
        print("  ╚═════════════════════════════════════╝")

    if max_layer >= 6:
        print()
        print("  ╔══ LAYER 6: Learning Feedback Loop ══╗")
        print("  ║  (pending implementation — Task #24)")
        print("  ╚══════════════════════════════════════╝")

    elapsed = time.time() - start_time

    print()
    print("═" * 70)
    print("  V6 PIPELINE COMPLETE")
    print("═" * 70)
    print(f"  {json.dumps(package.summary(), indent=4)}")
    print(f"  Duration: {elapsed:.1f}s")
    print(f"  Outputs: {output_dir}")
    print("═" * 70)

    return package


def _build_pdf_data(package: EvidencePackage, attack_chains) -> dict:
    """Build the data structure needed for PDF generation."""
    findings = []
    seen_titles = set()

    # Semgrep findings with evidence walks
    for finding_dict, walk in package.evidence_walks:
        if finding_dict["title"] in seen_titles:
            continue
        seen_titles.add(finding_dict["title"])
        findings.append({
            "title": finding_dict.get("title", ""),
            "severity": finding_dict.get("severity", "MEDIUM"),
            "confidence": "HIGH",
            "risk_type": finding_dict.get("category", ""),
            "cwe": finding_dict.get("cwe", ""),
            "description": f"Vulnerability at {Path(finding_dict.get('file_path','')).name}:{finding_dict.get('line', 0)}",
            "evidence": walk.render() if walk else "",
            "code_locations": [f"{finding_dict.get('file_path','')}:{finding_dict.get('line', 0)}"],
        })

    # Absence findings
    for af in package.absence_findings:
        findings.append({
            "title": af.title, "severity": af.severity, "confidence": "HIGH",
            "risk_type": af.category, "cwe": af.cwe, "description": af.description,
            "evidence": af.evidence,
            "code_locations": [f"{af.file_path}:{af.line}"],
            "verified": [af.evidence],
            "could_not_verify": ["Whether compensating controls exist at infrastructure level"],
        })

    # Differential findings
    for df in package.differential_findings:
        findings.append({
            "title": df.title, "severity": df.severity, "confidence": "HIGH",
            "risk_type": df.category, "cwe": df.cwe, "description": df.description,
            "verified": [f"Missing guards: {df.missing_guards}"],
            "code_locations": [f"{df.weaker_path.entry_file}:{df.weaker_path.sink_line}"],
        })

    # Z3 findings (deduplicated)
    for zf in package.z3_findings:
        if zf["title"] in seen_titles:
            continue
        seen_titles.add(zf["title"])
        findings.append({
            "title": zf.get("title", ""), "severity": zf.get("severity", "HIGH"),
            "confidence": "HIGH", "risk_type": zf.get("category", ""),
            "cwe": zf.get("cwe", ""), "description": zf.get("description", ""),
            "evidence": zf.get("evidence", ""),
            "verified": [zf.get("z3_proof", "Formally proven via Z3 SMT solver")],
            "code_locations": [zf.get("file_path", "infra/")],
        })

    # Synthetic findings
    for sf in package.synthetic_findings:
        if sf["title"] in seen_titles:
            continue
        seen_titles.add(sf["title"])
        findings.append({
            "title": sf.get("title", ""), "severity": sf.get("severity", "MEDIUM"),
            "confidence": "HIGH", "risk_type": sf.get("category", ""),
            "description": sf.get("title", ""),
            "code_locations": [sf.get("file_path", "")],
        })

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: sev_order.get(f.get("severity", ""), 4))

    sev_dist = {}
    for f in findings:
        s = f.get("severity", "MEDIUM")
        sev_dist[s] = sev_dist.get(s, 0) + 1

    zt_data = {}
    if package.zero_trust:
        zt_data = {
            "posture": package.zero_trust.overall_posture,
            "summary": package.zero_trust.summary,
            "blast_radii": {
                rid: {"role": br.iam_role, "status": br.containment_status,
                      "internet_facing": br.is_internet_facing, "auth": br.auth_mechanism,
                      "capabilities": {"all_tenants": br.can_access_all_tenants,
                                       "exfiltrate": br.can_exfiltrate_data,
                                       "modify": br.can_modify_data}}
                for rid, br in package.zero_trust.blast_radii.items()
            },
            "lateral_paths": [{"source": lp.source, "target": lp.target, "mechanism": lp.mechanism}
                             for lp in package.zero_trust.lateral_paths[:20]],
        }

    chains_data = [
        {"title": c.title, "composite_severity": c.composite_severity,
         "steps": [{"title": s.title, "severity": s.severity} for s in c.steps],
         "narrative": c.narrative}
        for c in attack_chains
    ]

    return {
        "summary": {
            "repo": package.repo_path, "total_findings": len(findings),
            "severity_distribution": sev_dist, "z3_findings": len(package.z3_findings),
            "zero_trust_uncontained": package.zero_trust.summary.get("uncontained", 0) if package.zero_trust else 0,
            "lateral_paths": len(package.zero_trust.lateral_paths) if package.zero_trust else 0,
            "attack_chains": len(chains_data),
        },
        "findings": findings,
        "attack_chains": chains_data,
        "zero_trust": zt_data,
    }


def _run_layer1(package: EvidencePackage, output_dir: Path, use_api: bool):
    """Run Layer 1 LLM discovery tracks."""
    evidence_text = package.render_for_llm()
    known_findings = package.get_known_finding_titles()

    if use_api:
        # TODO: implement API calls to discovery agents
        print("  ║  Track A (Novel Patterns): pending prompt selection")
        print("  ║  Track B (Zero-Day): pending prompt selection")
        print("  ║  Track C (Investigation): pending prompt selection")
    else:
        # Generate prompts for in-session execution
        prompts_dir = output_dir / "layer1_prompts"
        prompts_dir.mkdir(parents=True, exist_ok=True)

        # Track A prompt
        track_a_prompt = _build_track_a_prompt(evidence_text, known_findings)
        (prompts_dir / "track_a_novel_patterns.md").write_text(track_a_prompt)

        # Track B prompt
        track_b_prompt = _build_track_b_prompt(evidence_text, known_findings, package)
        (prompts_dir / "track_b_zero_day.md").write_text(track_b_prompt)

        # Track C prompts (5 agents)
        track_c_prompts = _build_track_c_prompts(evidence_text)
        (prompts_dir / "track_c_investigation.md").write_text(track_c_prompts)

        total_size = sum(f.stat().st_size for f in prompts_dir.glob("*.md"))
        print(f"  ║  Prompts generated: {prompts_dir}")
        print(f"  ║  Total: {total_size/1024:.0f} KB across 3 tracks")


def _build_track_a_prompt(evidence: str, known: list[str]) -> str:
    """Build Track A: Novel Pattern Discovery prompt."""
    exclusion = "\n".join(f"- {t}" for t in known[:30])
    return f"""# Track A: Novel Pattern Discovery

## System
You are a security researcher finding vulnerabilities that automated tools MISSED.
Phase 0 already found the findings listed below — DO NOT re-report them.
Find ONLY things not in this list.

## Already Found (DO NOT RE-REPORT):
{exclusion}

## Strategies to Apply:
1. DECLARED-BUT-UNENFORCED: Find security metadata/comments that aren't enforced in code
2. SENSITIVE DATA TO EXTERNAL SERVICES: Trace tokens/PII flowing to third-party services
3. IMPLICIT CONTRACT VIOLATIONS: Find the 20% of code paths that don't do what 80% do
4. ATTACK SURFACE EXPANSION: Find code reachable beyond design intent
5. TEMPORAL/STATE ISSUES: TOCTOU, stale sessions, token reuse

## Evidence Package:
{evidence}

## Output Format:
For each novel finding:
```json
{{
  "title": "specific title with impact",
  "severity": "CRITICAL|HIGH|MEDIUM",
  "category": "which strategy found this",
  "description": "what's wrong and why rules missed it",
  "evidence": "file:line citations",
  "exploit": "how to demonstrate",
  "rule_suggestion": "how to catch this deterministically next time"
}}
```
"""


def _build_track_b_prompt(evidence: str, known: list[str], package: EvidencePackage) -> str:
    """Build Track B: Zero-Day Discovery prompt."""
    # Load CVE seeds if available
    cve_seeds = ""
    seeds_dir = Path(__file__).parent / "knowledge" / "cve_seeds"
    if seeds_dir.exists():
        for f in sorted(seeds_dir.glob("*.md"))[:3]:
            cve_seeds += f.read_text() + "\n\n"

    return f"""# Track B: Zero-Day Discovery (Opus)

## System
You are an elite vulnerability researcher hunting for GENUINELY NOVEL bugs —
vulnerability classes that don't exist in any CVE database yet. You think like
Google Project Zero's Big Sleep: question assumptions, infer specifications,
prove violations.

## Strategies:

### 1. CVE Variant Analysis
Look for code structurally similar to known vulnerabilities but not an exact match.
{cve_seeds if cve_seeds else "(No CVE seeds loaded — analyze based on structural patterns)"}

### 2. Specification Inference + Violation Proof
Infer what MUST be true for security to hold. Then find where it ISN'T true.
Example: "tenant_id must come from verified authorizer context" — find where it doesn't.

### 3. Anomaly-Driven Exploration
Which code is STRUCTURALLY UNUSUAL compared to its neighbors?
Different error handling? Different trust assumptions? Different data flow shape?

### 4. AI/LLM-Specific Attack Vectors
- Bedrock memory sharing (cross-tenant context leakage)
- Prompt injection via stored evaluation data
- Agent routing control via adversarial input
- Tool use escalation (trick AI into calling dangerous tools)

### 5. Cross-Language Pattern Transfer
Python vulnerability → equivalent in JavaScript/CDK?

### 6. Commit-Diff Seeding
(If git history available) What was recently fixed? Find unfixed siblings.

## Evidence Package:
{evidence}

## Already Known (DO NOT RE-REPORT):
{chr(10).join(f'- {t}' for t in known[:20])}

## Output: Only genuinely novel findings. For each:
```json
{{
  "title": "novel vulnerability title",
  "severity": "CRITICAL|HIGH|MEDIUM",
  "novelty": "why this isn't in any CVE database",
  "strategy": "which strategy discovered this",
  "evidence": "file:line + reasoning",
  "inferred_spec": "what security property SHOULD hold",
  "violation_proof": "how the spec is violated",
  "exploit_scenario": "concrete attack description",
  "rule_suggestion": "how to detect this deterministically"
}}
```
"""


def _build_track_c_prompts(evidence: str) -> str:
    """Build Track C: Investigation Agent prompts."""
    agents = [
        ("Tenant Isolation Expert",
         "Trace every path tenant_id takes. Find all cross-tenant access vectors."),
        ("Auth Architecture Expert",
         "Map complete auth/authz architecture. Find bypass paths and JWT weaknesses."),
        ("Data Flow Expert",
         "Trace user input to sensitive sinks. Construct concrete exploits."),
        ("Infrastructure & Blast Radius Expert",
         "Assume breach per resource. Map blast radius and lateral movement."),
        ("Business Logic Expert",
         "Identify design flaws — insecure defaults, missing controls, compliance irony."),
    ]

    output = "# Track C: Domain Investigation Agents\n\n"
    for name, mandate in agents:
        output += f"## {name}\n\n"
        output += f"**Mandate:** {mandate}\n\n"
        output += f"**Evidence:**\n{evidence[:30000]}\n\n"
        output += "---\n\n"

    return output


def _collect_chain_inputs(code_result, infra_result) -> list[dict]:
    """Merge findings from code + infra for chain synthesis."""
    all_findings = []

    for finding, walk in code_result.evidence_walks:
        all_findings.append(finding)

    for af in code_result.absence_findings:
        all_findings.append({
            "id": af.id, "title": af.title, "severity": af.severity,
            "category": af.category, "file_path": af.file_path,
        })

    for df in code_result.differential_findings:
        all_findings.append({
            "id": df.id, "title": df.title, "severity": df.severity,
            "category": df.category, "file_path": df.weaker_path.entry_file,
        })

    for sf in infra_result.synthetic_findings:
        all_findings.append(sf)

    return all_findings


def main():
    parser = argparse.ArgumentParser(description="V6 Hybrid Security Scanner")
    parser.add_argument("repo", nargs="?", default="/Users/indukuk/compliance")
    parser.add_argument("--layer", type=int, default=0, help="Run up to layer N")
    parser.add_argument("--full", action="store_true", help="Run all layers")
    parser.add_argument("--api", action="store_true", help="Use Bedrock API")
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING, format="%(asctime)s [%(levelname)s] %(message)s")

    max_layer = 6 if args.full else args.layer
    run_v6(args.repo, max_layer=max_layer, use_api=args.api)


if __name__ == "__main__":
    main()
