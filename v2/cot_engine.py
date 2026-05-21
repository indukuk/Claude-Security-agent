"""
V2 Chain-of-Thought Engine
============================
Coordinates Semgrep detection with structured CoT reasoning.
Each finding from Semgrep goes through 6-step Think & Verify.

This script runs the full pipeline:
1. Semgrep detects taint paths (already done — reads results)
2. For each finding, gathers context via Python tools
3. Outputs structured prompts for Claude to reason about
4. Claude (in-session) performs the CoT reasoning
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TaintFinding:
    rule_id: str
    severity: str
    file: str
    line: int
    end_line: int
    cwe: str
    category: str
    code: str
    dataflow_trace: dict


@dataclass
class AnalysisContext:
    """Context gathered by Python tools for CoT reasoning."""
    finding: TaintFinding
    source_code: str
    function_body: str
    auth_context_usage: list
    sanitizers_on_path: list
    iam_permissions: dict
    authorizer_coverage: dict
    related_findings: list


def load_semgrep_results(path: str) -> list[TaintFinding]:
    """Load Semgrep JSON results."""
    with open(path) as f:
        data = json.load(f)

    findings = []
    for r in data:
        meta = r.get("extra", {}).get("metadata", {})
        findings.append(TaintFinding(
            rule_id=r.get("check_id", "").split(".")[-1],
            severity=r.get("extra", {}).get("severity", "UNKNOWN"),
            file=r.get("path", ""),
            line=r.get("start", {}).get("line", 0),
            end_line=r.get("end", {}).get("line", 0),
            cwe=meta.get("cwe", ""),
            category=meta.get("category", ""),
            code=r.get("extra", {}).get("lines", ""),
            dataflow_trace=r.get("extra", {}).get("dataflow_trace", {}),
        ))
    return findings


def gather_context(finding: TaintFinding, repo_path: str) -> AnalysisContext:
    """Gather all context needed for CoT reasoning (Python tools)."""
    file_path = finding.file

    # Read source code around the finding
    source_code = _read_context(file_path, finding.line, context_lines=10)

    # Read the full function containing this line
    function_body = _read_enclosing_function(file_path, finding.line)

    # Check: does this file access auth context?
    auth_usage = _find_auth_context_usage(file_path)

    # Check: are there sanitizers between source and nearby sinks?
    sanitizers = _find_sanitizers_in_function(file_path, finding.line)

    # Check IAM for the Lambda that runs this code
    iam = _check_iam_for_file(file_path, repo_path)

    # Check authorizer coverage
    authorizer = _check_authorizer(file_path, repo_path)

    # Find related findings in the same file
    related = _find_related_in_file(finding.file, finding.line)

    return AnalysisContext(
        finding=finding,
        source_code=source_code,
        function_body=function_body,
        auth_context_usage=auth_usage,
        sanitizers_on_path=sanitizers,
        iam_permissions=iam,
        authorizer_coverage=authorizer,
        related_findings=related,
    )


def generate_cot_prompt(ctx: AnalysisContext) -> str:
    """Generate the full CoT prompt for Claude to reason about."""

    cwe_knowledge = _get_cwe_context(ctx.finding.cwe)

    prompt = f"""═══════════════════════════════════════════════════════════════════
CHAIN-OF-THOUGHT SECURITY ANALYSIS
Finding: {ctx.finding.rule_id} [{ctx.finding.severity}]
File: {ctx.finding.file}:{ctx.finding.line}
CWE: {ctx.finding.cwe} — {cwe_knowledge['name']}
═══════════════════════════════════════════════════════════════════

CWE CONTEXT:
{cwe_knowledge['description']}

CODEBASE CONTEXT:
Multi-tenant serverless compliance platform. Tenant isolation relies on
DynamoDB partition keys (TENANT#{{tenant_id}}). S3 keys prefixed with tenant_id.
Authentication via Cognito JWT → Lambda authorizer injects tenant_id to
event['requestContext']['authorizer']['tenant_id'].

SEMGREP DETECTION:
Rule: {ctx.finding.rule_id}
Taint source → sink path CONFIRMED by static analysis.
Semgrep has PROVEN data flows from source to sink.

═══════════════════════════════════════════════════════════════════
SOURCE CODE (around finding):
═══════════════════════════════════════════════════════════════════
{ctx.source_code}

═══════════════════════════════════════════════════════════════════
ENCLOSING FUNCTION:
═══════════════════════════════════════════════════════════════════
{ctx.function_body[:2000]}

═══════════════════════════════════════════════════════════════════
TOOL RESULTS (Python analysis):
═══════════════════════════════════════════════════════════════════

AUTH CONTEXT USAGE IN THIS FILE:
{json.dumps(ctx.auth_context_usage, indent=2) if ctx.auth_context_usage else "[] (NONE — auth context never accessed)"}

SANITIZERS FOUND IN FUNCTION:
{json.dumps(ctx.sanitizers_on_path, indent=2) if ctx.sanitizers_on_path else "[] (NONE — no validation between source and sink)"}

IAM PERMISSIONS FOR THIS LAMBDA:
{json.dumps(ctx.iam_permissions, indent=2)}

AUTHORIZER COVERAGE:
{json.dumps(ctx.authorizer_coverage, indent=2)}

═══════════════════════════════════════════════════════════════════
PERFORM CHAIN-OF-THOUGHT ANALYSIS (6 Steps):
═══════════════════════════════════════════════════════════════════

STEP 1 — IDENTIFY:
What untrusted input enters? Where from? What does attacker control?

STEP 2 — TRACE:
The taint path is CONFIRMED by Semgrep. For each step:
(a) variable carrying taint, (b) operation, (c) taint preserved/removed

STEP 3 — ASSESS:
Given the tool results above — is there ANY sanitizer on this path?
Is the auth context (JWT tenant_id) consulted before the sink?

STEP 4 — CONCLUDE:
Is this exploitable? What is the concrete attack? What is blast radius?

STEP 5 — VERIFY:
Challenge your reasoning. Consider:
- Does the authorizer prevent this? (check tool result above)
- Is there a sanitizer you missed? (check tool result above)
- Is this finding only exploitable by an authenticated user? (reduce severity?)
- Could DynamoDB key structure inherently prevent cross-tenant access?

STEP 6 — VERDICT:
{{ VULNERABLE | SAFE | UNCERTAIN }}
Severity: {{ CRITICAL | HIGH | MEDIUM | LOW }}
Confidence: {{ HIGH | MEDIUM | LOW }}
Concrete exploit (curl command or steps).
Remediation (exact code change).
"""
    return prompt


# ═══════════════════════════════════════════════════════════════════
# PYTHON TOOLS (context gathering)
# ═══════════════════════════════════════════════════════════════════

def _read_context(file_path: str, line: int, context_lines: int = 10) -> str:
    """Read source code around a specific line."""
    try:
        lines = Path(file_path).read_text().split("\n")
        start = max(0, line - context_lines - 1)
        end = min(len(lines), line + context_lines)
        numbered = [f"{i+1:4d}│ {lines[i]}" for i in range(start, end)]
        # Mark the finding line
        finding_idx = line - start - 1
        if 0 <= finding_idx < len(numbered):
            numbered[finding_idx] = numbered[finding_idx].replace("│", "│→")
        return "\n".join(numbered)
    except Exception:
        return f"(Could not read {file_path}:{line})"


def _read_enclosing_function(file_path: str, line: int) -> str:
    """Read the full function that contains the given line."""
    try:
        lines = Path(file_path).read_text().split("\n")
        # Walk backward to find function definition
        func_start = line - 1
        while func_start > 0:
            if lines[func_start].strip().startswith("def "):
                break
            func_start -= 1

        # Walk forward to find function end (next def at same or lower indent)
        indent = len(lines[func_start]) - len(lines[func_start].lstrip())
        func_end = func_start + 1
        while func_end < len(lines):
            stripped = lines[func_end].strip()
            if stripped and not stripped.startswith("#"):
                current_indent = len(lines[func_end]) - len(lines[func_end].lstrip())
                if current_indent <= indent and stripped.startswith("def "):
                    break
            func_end += 1

        numbered = [f"{i+1:4d}│ {lines[i]}" for i in range(func_start, min(func_end, func_start + 60))]
        return "\n".join(numbered)
    except Exception:
        return "(Could not extract function)"


def _find_auth_context_usage(file_path: str) -> list:
    """Find where auth context is accessed in this file."""
    results = []
    try:
        lines = Path(file_path).read_text().split("\n")
        patterns = [
            r"requestContext.*authorizer",
            r"authorizer.*tenant_id",
            r"authorizer.*role",
            r"rc\.get\(['\"]authorizer",
        ]
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line):
                    results.append({"line": i, "code": line.strip()[:100]})
    except Exception:
        pass
    return results


def _find_sanitizers_in_function(file_path: str, line: int) -> list:
    """Find validation/sanitization patterns near the finding."""
    results = []
    try:
        lines = Path(file_path).read_text().split("\n")
        # Check 30 lines around the finding
        start = max(0, line - 15)
        end = min(len(lines), line + 15)
        patterns = [
            (r"check_permission", "RBAC check"),
            (r"if.*tenant_id.*!=", "tenant validation"),
            (r"if not.*customer_id", "customer_id validation"),
            (r"os\.path\.basename", "path sanitization"),
            (r"ExpressionAttributeValues", "parameterized query"),
            (r"return.*40[13]", "early return on auth failure"),
        ]
        for i in range(start, end):
            for pattern, desc in patterns:
                if re.search(pattern, lines[i]):
                    results.append({"line": i + 1, "type": desc, "code": lines[i].strip()[:80]})
    except Exception:
        pass
    return results


def _check_iam_for_file(file_path: str, repo_path: str) -> dict:
    """Determine IAM permissions for the Lambda running this file."""
    # Map file to Lambda based on known structure
    filename = Path(file_path).name

    iam_map = {
        "handler.py": {"role": "agent_lambda_role", "table_access": "full (no LeadingKeys)",
                       "s3_access": "read_write (all keys)"},
        "handler_v2.py": {"role": "agent_v2_lambda_role", "table_access": "full (no LeadingKeys)",
                         "s3_access": "read_write (all keys)"},
        "handler_v3.py": {"role": "agent_v3_lambda_role", "table_access": "full (no LeadingKeys)",
                         "s3_access": "read_write (all keys)"},
        "auth_handler.py": {"role": "auth_lambda_role", "table_access": "full on tenants/policies/user_tenants",
                           "cognito_access": "admin (create/modify/delete users)"},
        "data_handler.py": {"role": "data_lambda_role", "table_access": "full on tenants table",
                           "s3_access": "read_write"},
        "tenant_management.py": {"role": "tenant_mgmt_role", "table_access": "full on tenants/policies",
                                "cognito_access": "admin"},
        "user_management.py": {"role": "user_mgmt_role", "table_access": "full on policies/user_tenants",
                              "cognito_access": "admin"},
    }

    return iam_map.get(filename, {"role": "unknown", "note": "could not determine IAM for this file"})


def _check_authorizer(file_path: str, repo_path: str) -> dict:
    """Check if this handler's API Gateway route has an authorizer."""
    filename = Path(file_path).name

    # Known from CDK analysis
    auth_map = {
        "handler.py": {"authorizer": True, "type": "Lambda JWT authorizer",
                      "injects": ["tenant_id", "user_id", "role", "permissions"]},
        "handler_v2.py": {"authorizer": True, "type": "Lambda JWT authorizer",
                         "injects": ["tenant_id", "user_id", "role", "permissions"],
                         "note": "Also has Function URL path (AWS_IAM auth, no tenant injection)"},
        "handler_v3.py": {"authorizer": "partial", "type": "Function URL with AWS_IAM",
                         "note": "No Lambda authorizer on Function URL path — no tenant_id injection"},
        "auth_handler.py": {"authorizer": False, "note": "/auth/* routes are pre-auth (login/signup)"},
        "data_handler.py": {"authorizer": True, "type": "Lambda JWT authorizer",
                           "injects": ["tenant_id", "user_id", "role"]},
        "tenant_management.py": {"authorizer": True, "type": "Lambda JWT authorizer",
                                "requires_role": "platform_admin"},
        "user_management.py": {"authorizer": True, "type": "Lambda JWT authorizer",
                              "requires_role": "admin"},
    }

    return auth_map.get(filename, {"authorizer": "unknown"})


def _find_related_in_file(file_path: str, line: int) -> list:
    """Find other findings in the same file (for correlation)."""
    # This would query semgrep results — simplified here
    return []


def _get_cwe_context(cwe: str) -> dict:
    """Get CWE definition from knowledge base."""
    cwe_map = {
        "CWE-639": {
            "name": "Authorization Bypass Through User-Controlled Key",
            "description": "The system's authorization relies on a key (tenant_id, customer_id) "
                          "that the user can modify, allowing access to other users' resources. "
                          "In multi-tenant: attacker changes the tenant identifier to access "
                          "another tenant's data."
        },
        "CWE-22": {
            "name": "Path Traversal",
            "description": "User-controlled input used in file path/key construction without "
                          "sanitization. In S3: user-controlled filename becomes part of the "
                          "object key, potentially accessing keys outside intended prefix."
        },
        "CWE-284": {
            "name": "Improper Access Control",
            "description": "The system does not properly restrict access. In Cognito: user "
                          "attributes (role, tenant_id) set from untrusted input during "
                          "account creation without admin approval flow."
        },
        "CWE-77": {
            "name": "Command/Prompt Injection",
            "description": "User input incorporated into a command/prompt executed by the system. "
                          "In LLM applications: user message manipulates the agent's behavior "
                          "to perform unauthorized actions via tool calls."
        },
    }
    return cwe_map.get(cwe, {"name": "Unknown", "description": ""})


# ═══════════════════════════════════════════════════════════════════
# MAIN: Run the full pipeline
# ═══════════════════════════════════════════════════════════════════

def main():
    repo_path = "/Users/indukuk/compliance"
    results_path = "/tmp/semgrep_findings.json"

    if not Path(results_path).exists():
        print("ERROR: Run Semgrep first. No results at", results_path)
        sys.exit(1)

    # Load Semgrep findings
    findings = load_semgrep_results(results_path)
    print(f"Loaded {len(findings)} Semgrep findings")
    print()

    # Deduplicate by rule+file (keep first occurrence)
    seen = set()
    unique = []
    for f in findings:
        key = (f.rule_id, f.file)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    print(f"Unique findings (deduped): {len(unique)}")
    print()

    # Sort: ERROR first, then WARNING
    unique.sort(key=lambda x: {"ERROR": 0, "WARNING": 1}.get(x.severity, 2))

    # Generate CoT prompts for each finding
    all_prompts = []
    for i, finding in enumerate(unique):
        print(f"{'─' * 60}")
        print(f"Gathering context for [{finding.severity}] {finding.rule_id}")
        print(f"  {finding.file}:{finding.line}")

        ctx = gather_context(finding, repo_path)
        prompt = generate_cot_prompt(ctx)
        all_prompts.append(prompt)

        print(f"  Auth context in file: {'YES' if ctx.auth_context_usage else 'NO'}")
        print(f"  Sanitizers found: {len(ctx.sanitizers_on_path)}")
        print(f"  Authorizer: {ctx.authorizer_coverage.get('authorizer', '?')}")

    # Write all prompts to a file for Claude to process
    output_path = Path(__file__).parent / "cot_prompts.md"
    with open(output_path, "w") as f:
        f.write("# Chain-of-Thought Prompts for Claude Analysis\n\n")
        f.write(f"Generated from {len(unique)} Semgrep findings.\n")
        f.write("Each finding below requires 6-step Think & Verify analysis.\n\n")

        for i, (finding, prompt) in enumerate(zip(unique, all_prompts)):
            f.write(f"\n{'═' * 70}\n")
            f.write(f"## Finding {i+1}/{len(unique)}: [{finding.severity}] {finding.rule_id}\n")
            f.write(f"{'═' * 70}\n\n")
            f.write(prompt)
            f.write("\n\n")

    print(f"\n{'═' * 60}")
    print(f"CoT PROMPTS GENERATED: {output_path}")
    print(f"{'═' * 60}")
    print(f"\nFindings for Claude to analyze:")
    for i, f in enumerate(unique):
        print(f"  {i+1}. [{f.severity}] {f.rule_id} — {f.file.split('/')[-1]}:{f.line}")
    print(f"\nNext: Claude reads cot_prompts.md and performs Think & Verify on each.")


if __name__ == "__main__":
    main()
