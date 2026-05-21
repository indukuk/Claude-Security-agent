"""
Security scan runner that uses Claude Code's session for LLM reasoning.

Runs all deterministic phases in Python, then outputs findings and
prompts that Claude can reason about directly in the conversation.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.agents.python.cpg_builder import PythonCPGBuilder
from src.agents.infrastructure.cfn_parser import CloudFormationParser
from src.agents.infrastructure.deterministic_checks import DeterministicChecker
from src.agents.infrastructure.iam_analyzer import IAMAnalyzer
from src.agents.infrastructure.toxic_combos import ToxicCombinationDetector
from src.common.graph import InfraGraph


def run_deterministic_scan(repo_path: str):
    """Run all phases that don't need LLM, output results for Claude reasoning."""
    repo = Path(repo_path)
    results = {
        "python_cpg": {},
        "infra_findings": [],
        "taint_paths_for_llm": [],
        "summary": {},
    }

    # =========================================================================
    # PYTHON APPLICATION ANALYSIS
    # =========================================================================
    print("=" * 60)
    print("PHASE 1: Python Code Property Graph Construction")
    print("=" * 60)

    builder = PythonCPGBuilder()
    py_files = [
        str(f) for f in repo.rglob("*.py")
        if "test" not in str(f).lower()
        and "cdk.out" not in str(f)
        and "venv" not in str(f)
        and "node_modules" not in str(f)
    ]
    # Focus on src/ directory
    py_files = [f for f in py_files if "/src/" in f or "/infra/" in f]

    print(f"Scanning {len(py_files)} Python files...")
    cpg = builder.build(py_files, {})

    print(f"\nCPG Statistics:")
    print(f"  Nodes: {cpg.node_count()}")
    print(f"  Edges: {cpg.edge_count()}")
    print(f"  Sources detected: {len(cpg.sources)}")
    print(f"  Sinks detected: {len(cpg.sinks)}")
    print(f"  Sanitizers detected: {len(cpg.sanitizers)}")

    # Collect sources and sinks with context for LLM analysis
    print(f"\n--- SOURCES (user input entry points) ---")
    source_details = []
    for s in cpg.sources:
        file_path, line = cpg.get_file_line(s)
        text = cpg.get_text(s)
        if text and len(text) > 10:
            detail = f"{Path(file_path).name}:{line}: {text[:120]}"
            source_details.append(detail)
            print(f"  {detail}")
    results["python_cpg"]["sources"] = source_details[:30]

    print(f"\n--- SINKS (security-sensitive operations) ---")
    sink_details = []
    for s in cpg.sinks:
        file_path, line = cpg.get_file_line(s)
        text = cpg.get_text(s)
        if text and len(text) > 10:
            detail = f"{Path(file_path).name}:{line}: {text[:120]}"
            sink_details.append(detail)
            print(f"  {detail}")
    results["python_cpg"]["sinks"] = sink_details[:20]

    print(f"\n--- SANITIZERS (validation/escaping) ---")
    sanitizer_details = []
    for s in cpg.sanitizers:
        file_path, line = cpg.get_file_line(s)
        text = cpg.get_text(s)
        if text and len(text) > 10:
            detail = f"{Path(file_path).name}:{line}: {text[:120]}"
            sanitizer_details.append(detail)
    results["python_cpg"]["sanitizers"] = sanitizer_details[:15]
    for d in sanitizer_details[:10]:
        print(f"  {d}")

    # Find taint paths (source → sink via DFG)
    print(f"\n--- TAINT PATHS (source → sink without sanitizer) ---")
    paths = cpg.find_taint_paths(max_depth=12)
    print(f"Direct taint paths found: {len(paths)}")

    # Also do manual cross-file analysis: which sinks could receive from which sources?
    # (compensates for weak DFG in regex mode)
    print(f"\n--- POTENTIAL TAINT PAIRS (for LLM analysis) ---")
    taint_pairs = []
    for src_id in cpg.sources[:20]:
        src_file, src_line = cpg.get_file_line(src_id)
        src_text = cpg.get_text(src_id)
        for sink_id in cpg.sinks[:15]:
            sink_file, sink_line = cpg.get_file_line(sink_id)
            sink_text = cpg.get_text(sink_id)
            # Same file = higher chance of connection
            if src_file == sink_file:
                pair = {
                    "source": f"{Path(src_file).name}:{src_line}: {src_text[:100]}",
                    "sink": f"{Path(sink_file).name}:{sink_line}: {sink_text[:100]}",
                    "same_file": True,
                    "source_file": src_file,
                }
                taint_pairs.append(pair)

    # Deduplicate and limit
    seen = set()
    unique_pairs = []
    for p in taint_pairs:
        key = (p["source"][:50], p["sink"][:50])
        if key not in seen:
            seen.add(key)
            unique_pairs.append(p)
    taint_pairs = unique_pairs[:15]

    for pair in taint_pairs:
        print(f"  SOURCE: {pair['source']}")
        print(f"  SINK:   {pair['sink']}")
        print()
    results["taint_paths_for_llm"] = taint_pairs

    # =========================================================================
    # INFRASTRUCTURE ANALYSIS
    # =========================================================================
    print("\n" + "=" * 60)
    print("PHASE 2: Infrastructure Security Analysis")
    print("=" * 60)

    # Parse all CDK stacks
    all_resources = {}
    all_content = ""
    stack_files = list((repo / "infra" / "stacks").glob("*.py"))
    print(f"Parsing {len(stack_files)} CDK stack files...")

    for stack_file in stack_files:
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
            elif "cognito.UserPool(" in line:
                all_resources[f"Cognito_{stack_file.stem}_{len(all_resources)}"] = {
                    "Type": "AWS::Cognito::UserPool",
                    "Properties": {"SourceLine": i + 1},
                    "SourceFile": str(stack_file),
                }
            elif "apigateway.RestApi(" in line or "apigw.RestApi(" in line:
                all_resources[f"ApiGw_{stack_file.stem}_{len(all_resources)}"] = {
                    "Type": "AWS::ApiGateway::RestApi",
                    "Properties": {"SourceLine": i + 1},
                    "SourceFile": str(stack_file),
                }

    template = {"Resources": all_resources, "RawContent": all_content}
    print(f"Resources found: {len(all_resources)}")
    for rid, r in all_resources.items():
        print(f"  {rid}: {r['Type']}")

    # Build graph
    parser = CloudFormationParser()
    graph = parser.parse(template)
    print(f"\nInfra graph: {graph.network.number_of_nodes()} nodes, {graph.network.number_of_edges()} edges")
    print(f"IAM permissions: {graph.iam.number_of_edges()} edges")

    # IAM analysis
    print(f"\n--- IAM PERMISSIONS ---")
    for s, t, d in graph.iam.edges(data=True):
        actions = d.get("actions", [])
        source_info = d.get("source", "")
        wildcards = [a for a in actions if "*" in a]
        marker = " ⚠️  WILDCARD" if wildcards else ""
        print(f"  {s} → {t}: {actions}{marker}")
        if wildcards:
            results["infra_findings"].append({
                "severity": "HIGH",
                "title": f"Wildcard action in {s}: {wildcards}",
                "resource": t,
            })

    # Deterministic checks
    print(f"\n--- DETERMINISTIC SECURITY CHECKS ---")
    checker = DeterministicChecker()
    det_findings = checker.check(graph)
    for f in det_findings:
        print(f"  [{f.severity.name}] {f.title}")
        results["infra_findings"].append({
            "severity": f.severity.name,
            "title": f.title,
            "description": f.description,
        })

    # IAM escalation
    print(f"\n--- IAM ESCALATION ANALYSIS ---")
    iam_analyzer = IAMAnalyzer()
    iam_findings = iam_analyzer.analyze(graph)
    for f in iam_findings:
        print(f"  [{f.severity.name}] {f.title}")
        results["infra_findings"].append({
            "severity": f.severity.name,
            "title": f.title,
            "description": f.description,
        })

    # Z3 formal IAM analysis
    print(f"\n--- Z3 FORMAL IAM VERIFICATION (Zelkova approach) ---")
    z3_findings = []
    try:
        from src.agents.infrastructure.z3_iam_analyzer import Z3IAMAnalyzer
        z3_analyzer = Z3IAMAnalyzer()
        z3_findings = z3_analyzer.analyze(graph)
        for f in z3_findings:
            print(f"  [{f.severity.name}] {f.title}")
            results["infra_findings"].append({
                "severity": f.severity.name,
                "title": f.title,
                "description": f.description,
            })
        if not z3_findings:
            print("  (no findings — all policies formally verified)")
    except ImportError:
        print("  z3-solver not installed — run: pip install z3-solver")
    except Exception as e:
        print(f"  Z3 analysis failed: {e}")

    # Toxic combinations
    print(f"\n--- TOXIC COMBINATIONS ---")
    all_findings = det_findings + iam_findings + z3_findings
    toxic_detector = ToxicCombinationDetector()
    toxic_findings = toxic_detector.detect(graph, all_findings)
    for f in toxic_findings:
        print(f"  [{f.severity.name}] {f.title}")
        print(f"    {f.description[:150]}")
        results["infra_findings"].append({
            "severity": f.severity.name,
            "title": f.title,
            "description": f.description,
        })

    # =========================================================================
    # SUMMARY
    # =========================================================================
    total_findings = len(det_findings) + len(iam_findings) + len(z3_findings) + len(toxic_findings)
    print("\n" + "=" * 60)
    print("SCAN SUMMARY (Deterministic — No LLM)")
    print("=" * 60)
    print(f"Python CPG: {cpg.node_count()} nodes, {len(cpg.sources)} sources, {len(cpg.sinks)} sinks")
    print(f"Taint pairs for LLM analysis: {len(taint_pairs)}")
    print(f"Infrastructure findings: {total_findings}")
    print(f"  - Deterministic checks: {len(det_findings)}")
    print(f"  - IAM escalation: {len(iam_findings)}")
    print(f"  - Z3 formal verification: {len(z3_findings)}")
    print(f"  - Toxic combinations: {len(toxic_findings)}")

    results["summary"] = {
        "cpg_nodes": cpg.node_count(),
        "cpg_edges": cpg.edge_count(),
        "sources": len(cpg.sources),
        "sinks": len(cpg.sinks),
        "sanitizers": len(cpg.sanitizers),
        "taint_pairs_for_llm": len(taint_pairs),
        "infra_findings": total_findings,
    }

    # Save results for Claude to analyze
    output_path = Path(__file__).parent / "scan_results.json"
    output_path.write_text(json.dumps(results, indent=2))
    print(f"\nResults saved to: {output_path}")
    print("\n⏭️  Next: Claude will analyze the taint pairs and infra findings using LLM reasoning.")

    return results


if __name__ == "__main__":
    repo = sys.argv[1] if len(sys.argv) > 1 else "/Users/indukuk/compliance"
    run_deterministic_scan(repo)
