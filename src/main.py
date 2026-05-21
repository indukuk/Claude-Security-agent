"""
Security Agent CLI — entry point.

Usage:
    python -m src.main /path/to/repo [--budget 5.0] [--output report.json]
"""
from __future__ import annotations


import argparse
import json
import logging
import sys
from pathlib import Path

from src.common.config import ScanConfig
from src.orchestrator.scanner import SecurityScanner


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def main():
    parser = argparse.ArgumentParser(
        description="Security Agent — graph-based vulnerability scanner with LLM reasoning"
    )
    parser.add_argument("repo_path", help="Path to repository to scan")
    parser.add_argument("--budget", type=float, default=5.0, help="LLM budget in USD (default: $5)")
    parser.add_argument("--output", default="security-report.json", help="Output file path")
    parser.add_argument("--format", choices=["json", "markdown"], default="json", help="Output format")
    parser.add_argument("--no-python", action="store_true", help="Disable Python agent")
    parser.add_argument("--no-infra", action="store_true", help="Disable infrastructure agent")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    parser.add_argument("--resume", action="store_true", help="Resume from last checkpoint")

    args = parser.parse_args()

    setup_logging(args.verbose)
    logger = logging.getLogger("security-agent")

    # Validate repo path
    repo = Path(args.repo_path)
    if not repo.exists():
        logger.error(f"Repository path does not exist: {repo}")
        sys.exit(1)

    # Build configuration
    config = ScanConfig(
        repo_path=str(repo.resolve()),
        total_budget=args.budget,
        enable_python=not args.no_python,
        enable_infrastructure=not args.no_infra,
        output_format=args.format,
        output_path=args.output,
    )

    if args.resume:
        config.resume_from = str(config.checkpoint_path)

    # Run scan
    logger.info(f"Scanning: {config.repo_path}")
    logger.info(f"Budget: ${config.total_budget:.2f}")
    logger.info(f"Agents: python={'enabled' if config.enable_python else 'disabled'}, "
               f"infra={'enabled' if config.enable_infrastructure else 'disabled'}")

    scanner = SecurityScanner(config)

    try:
        report = scanner.scan()
    except KeyboardInterrupt:
        logger.info("Scan interrupted — progress saved to checkpoint")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        sys.exit(1)

    # Output report
    output_path = Path(args.output)
    if args.format == "json":
        output_path.write_text(json.dumps(report, indent=2))
    elif args.format == "markdown":
        output_path.write_text(_format_markdown(report))

    # Print summary
    summary = report["summary"]
    print(f"\n{'=' * 60}")
    print(f"Security Scan Complete")
    print(f"{'=' * 60}")
    print(f"Repository: {summary['repo_path']}")
    print(f"Duration:   {summary['scan_duration_seconds']}s")
    print(f"Cost:       ${summary['cost_usd']}")
    print(f"")
    print(f"Findings:")
    print(f"  CRITICAL: {summary['critical']}")
    print(f"  HIGH:     {summary['high']}")
    print(f"  MEDIUM:   {summary['medium']}")
    print(f"  LOW:      {summary['low']}")
    print(f"  Total:    {summary['total_findings']}")
    print(f"")
    print(f"Report: {output_path}")
    print(f"{'=' * 60}")

    # Exit code based on findings
    if summary["critical"] > 0:
        sys.exit(2)
    elif summary["high"] > 0:
        sys.exit(1)
    sys.exit(0)


def _format_markdown(report: dict) -> str:
    """Format report as markdown."""
    lines = [
        "# Security Scan Report",
        "",
        f"**Repository:** {report['summary']['repo_path']}",
        f"**Date:** {report['metadata']['timestamp']}",
        f"**Cost:** ${report['summary']['cost_usd']}",
        "",
        "## Summary",
        "",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| CRITICAL | {report['summary']['critical']} |",
        f"| HIGH | {report['summary']['high']} |",
        f"| MEDIUM | {report['summary']['medium']} |",
        f"| LOW | {report['summary']['low']} |",
        "",
    ]

    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        findings = report["findings"].get(severity, [])
        if findings:
            lines.append(f"## {severity} Findings")
            lines.append("")
            for f in findings:
                lines.append(f"### {f['title']}")
                lines.append(f"- **CWE:** {f.get('cwe', 'N/A')}")
                lines.append(f"- **Location:** {f.get('location', 'N/A')}")
                lines.append(f"- **Description:** {f.get('description', '')[:200]}")
                if f.get("remediation"):
                    lines.append(f"- **Fix:** {f['remediation'].get('explanation', '')}")
                lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    main()
