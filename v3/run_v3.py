"""
V3 Security Agent — Entry Point
Generator → Verifier → Prover pipeline.
"""
from __future__ import annotations

import sys
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from v3.orchestrator import V3Orchestrator


def main():
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "/Users/indukuk/compliance"

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    print("═" * 60)
    print("  Security Agent V3 — Generator → Verifier → Prover")
    print("═" * 60)
    print(f"  Target: {repo_path}")
    print()

    orchestrator = V3Orchestrator(repo_path)
    report = orchestrator.run()

    print()
    print("═" * 60)
    print("  V3 PIPELINE COMPLETE")
    print("═" * 60)
    print()
    print(f"  Stage 1 (Generator): {report['summary']['candidates_detected']} candidates")
    print(f"  Stage 2 (Verifier):  {report['summary']['verified_after_debate']} verified")
    print(f"  Stage 3 (Prover):    {report['summary']['proven_with_exploits']} proven")
    print(f"  Duration:            {report['summary']['elapsed_seconds']}s")
    print()
    print(f"  Outputs:")
    state_dir = Path(repo_path) / ".security-agent" / "v3-state"
    print(f"    Report:    {state_dir / 'v3_report.json'}")
    print(f"    Debates:   {state_dir / 'debate_prompts.md'}")
    print(f"    Proofs:    {state_dir / 'proofs.json'}")
    print(f"    State:     {state_dir / 'state.json'}")
    print()
    print("═" * 60)


if __name__ == "__main__":
    main()
