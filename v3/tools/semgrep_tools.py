"""
Semgrep tools — run scans and query results.
"""
from __future__ import annotations

import json
import subprocess
import os
from pathlib import Path


SEMGREP_BIN = str(Path.home() / "Library/Python/3.9/bin/pysemgrep")


def run_semgrep(rules_path: str, target_path: str) -> list[dict]:
    """Run Semgrep with given rules and return findings."""
    env = os.environ.copy()
    env["PATH"] = f"{Path.home()}/Library/Python/3.9/bin:" + env.get("PATH", "")

    try:
        result = subprocess.run(
            [SEMGREP_BIN, "scan", "--config", rules_path, target_path, "--json", "--quiet"],
            capture_output=True, text=True, env=env, timeout=120,
        )
        # Semgrep returns exit code 1 for findings, 0 for none
        output = result.stdout or result.stderr
        if not output:
            return []

        data = json.loads(output)
        return data.get("results", [])
    except subprocess.TimeoutExpired:
        return [{"error": "Semgrep timeout"}]
    except json.JSONDecodeError:
        return []
    except FileNotFoundError:
        return [{"error": "Semgrep not installed"}]


def query_findings(findings: list[dict], rule_id: str = None,
                   file_pattern: str = None, severity: str = None) -> list[dict]:
    """Query/filter Semgrep findings."""
    results = findings

    if rule_id:
        results = [f for f in results if rule_id in f.get("check_id", "")]

    if file_pattern:
        results = [f for f in results if file_pattern in f.get("path", "")]

    if severity:
        results = [f for f in results if f.get("extra", {}).get("severity", "") == severity]

    return results


def run_semgrep_on_file(rules_path: str, file_path: str, rule_id: str | None = None) -> list[dict]:
    """
    Run Semgrep on a single file for targeted re-verification.
    Optionally filter to a specific rule_id.
    Returns findings list (empty = file is clean).
    """
    env = os.environ.copy()
    env["PATH"] = f"{Path.home()}/Library/Python/3.9/bin:" + env.get("PATH", "")

    try:
        result = subprocess.run(
            [SEMGREP_BIN, "scan", "--config", rules_path, file_path, "--json", "--quiet"],
            capture_output=True, text=True, env=env, timeout=60,
        )
        output = result.stdout or result.stderr
        if not output:
            return []

        data = json.loads(output)
        findings = data.get("results", [])

        if rule_id:
            findings = [f for f in findings if rule_id in f.get("check_id", "")]

        return findings
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        return []


def format_finding(finding: dict) -> str:
    """Format a single finding for display."""
    rule = finding.get("check_id", "unknown").split(".")[-1]
    file_path = finding.get("path", "").split("/compliance/")[-1] if "/compliance/" in finding.get("path", "") else finding.get("path", "")
    line = finding.get("start", {}).get("line", 0)
    severity = finding.get("extra", {}).get("severity", "?")
    message = finding.get("extra", {}).get("message", "")[:150]
    code = finding.get("extra", {}).get("lines", "").strip()[:200]
    meta = finding.get("extra", {}).get("metadata", {})

    return (
        f"[{severity}] {rule}\n"
        f"  File: {file_path}:{line}\n"
        f"  CWE: {meta.get('cwe', 'N/A')} | Category: {meta.get('category', 'N/A')}\n"
        f"  Message: {message}\n"
        f"  Code: {code}"
    )
