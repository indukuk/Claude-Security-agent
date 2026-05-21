"""
V2 Cross-Boundary Correlator
==============================
Combines Semgrep app findings + infra deterministic findings
to identify compound risks that neither layer catches alone.
"""
from __future__ import annotations

import json
from pathlib import Path
from dataclasses import dataclass


@dataclass
class CompoundFinding:
    id: str
    severity: str
    title: str
    app_finding: dict
    infra_finding: dict
    attack_narrative: str
    why_compound: str
    remediation: str


CORRELATION_PATTERNS = [
    {
        "id": "COMPOUND-001",
        "name": "No auth context + No IAM LeadingKeys = Unrestricted cross-tenant",
        "app_condition": lambda f: (
            f.get("check_id", "").endswith("cross-tenant-customer-id-from-body")
        ),
        "infra_condition": lambda findings: (
            not any("LeadingKeys" in str(f) for f in findings)
        ),
        "severity": "CRITICAL",
        "attack_narrative": (
            "Application-level vulnerability: customer_id from body reaches DynamoDB. "
            "Infrastructure-level gap: IAM has no LeadingKeys condition. "
            "Combined: ZERO barriers to cross-tenant access. "
            "A single spoofed customer_id field gives access to ALL tenants' data "
            "because neither the application NOR IAM enforces tenant boundaries."
        ),
        "why_compound": (
            "Individually: app vuln is HIGH (maybe auth context is used elsewhere). "
            "Individually: no LeadingKeys is MEDIUM (maybe app validates). "
            "Together: CRITICAL because BOTH defenses are missing simultaneously."
        ),
        "remediation": (
            "Fix BOTH layers:\n"
            "1. App: customer_id = event['requestContext']['authorizer']['tenant_id']\n"
            "2. IAM: Add dynamodb:LeadingKeys condition restricting to tenant prefix\n"
            "Either fix alone reduces risk. Both together = defense-in-depth."
        ),
    },
    {
        "id": "COMPOUND-002",
        "name": "Presigned URL from body + S3 no versioning = Evidence forgery",
        "app_condition": lambda f: (
            f.get("check_id", "").endswith("presigned-url-user-filename")
        ),
        "infra_condition": lambda findings: (
            any("S3" in f.get("title", "") and "logging" in f.get("title", "").lower()
                for f in findings)
        ),
        "severity": "HIGH",
        "attack_narrative": (
            "Application: user-controlled filename in presigned URL key. "
            "Infrastructure: S3 bucket has no access logging AND no versioning. "
            "Combined: attacker uploads forged evidence via manipulated key path, "
            "and there's no audit trail (no logging) and no way to recover "
            "the original (no versioning). Evidence tampering is undetectable."
        ),
        "why_compound": (
            "Individually: presigned URL without basename() is MEDIUM (S3 keys are flat). "
            "Individually: no logging is MEDIUM (operational concern). "
            "Together: HIGH because evidence integrity cannot be proven in audit."
        ),
        "remediation": (
            "1. App: os.path.basename(filename) + UUID prefix\n"
            "2. Infra: Enable S3 versioning (prevents overwrite of originals)\n"
            "3. Infra: Enable S3 access logging (detects unauthorized access)\n"
            "For a compliance platform: all three are mandatory."
        ),
    },
    {
        "id": "COMPOUND-003",
        "name": "Function URL (no authorizer) + broad IAM = Widest attack surface",
        "app_condition": lambda f: (
            f.get("check_id", "").endswith("cross-tenant-customer-id-from-body")
            and "handler_v3" in f.get("path", "")
        ),
        "infra_condition": lambda findings: True,  # Always applies for handler_v3
        "severity": "CRITICAL",
        "attack_narrative": (
            "handler_v3.py accessed via Function URL has NO Lambda authorizer. "
            "SigV4 only verifies the caller is an AWS principal, NOT which tenant. "
            "The Lambda has full DynamoDB + S3 access (no LeadingKeys). "
            "Combined: any AWS-authenticated user can access any tenant's data "
            "with zero application-level or IAM-level tenant enforcement."
        ),
        "why_compound": (
            "The Function URL path is the WORST case: "
            "no authorizer (unlike API Gateway path) + no tenant context injection + "
            "broad IAM. Three missing defenses on the same code path."
        ),
        "remediation": (
            "Option A: Remove Function URL. Route all traffic through API Gateway + authorizer.\n"
            "Option B: Add custom auth validation in handler_v3 (verify tenant from signed header).\n"
            "Option C: Add IAM LeadingKeys + validate customer_id against Cognito lookup."
        ),
    },
]


def correlate(semgrep_results_path: str, infra_results_path: str) -> list[CompoundFinding]:
    """Run cross-boundary correlation."""
    with open(semgrep_results_path) as f:
        semgrep_findings = json.load(f)

    with open(infra_results_path) as f:
        infra_findings = json.load(f)

    compounds = []

    for pattern in CORRELATION_PATTERNS:
        # Check app condition against each Semgrep finding
        matching_app = [f for f in semgrep_findings if pattern["app_condition"](f)]

        # Check infra condition against infra findings
        infra_match = pattern["infra_condition"](infra_findings)

        if matching_app and infra_match:
            compounds.append(CompoundFinding(
                id=pattern["id"],
                severity=pattern["severity"],
                title=pattern["name"],
                app_finding=matching_app[0],
                infra_finding=infra_findings[0] if infra_findings else {},
                attack_narrative=pattern["attack_narrative"],
                why_compound=pattern["why_compound"],
                remediation=pattern["remediation"],
            ))

    return compounds


def main():
    results_dir = Path(__file__).parent / "results"
    semgrep_path = results_dir / "semgrep_findings.json"
    infra_path = results_dir / "infra_findings.json"

    if not semgrep_path.exists() or not infra_path.exists():
        print("ERROR: Run run_v2.sh first to generate findings.")
        return

    print("═══════════════════════════════════════════════════════════")
    print("  CROSS-BOUNDARY CORRELATION")
    print("═══════════════════════════════════════════════════════════")
    print()

    compounds = correlate(str(semgrep_path), str(infra_path))

    print(f"Compound findings: {len(compounds)}")
    print()

    for c in compounds:
        print(f"[{c.severity}] {c.title}")
        print(f"  ID: {c.id}")
        print(f"  Why compound: {c.why_compound[:150]}")
        print(f"  Narrative: {c.attack_narrative[:150]}...")
        print(f"  Remediation: {c.remediation.split(chr(10))[0]}")
        print()

    # Save
    output = [
        {
            "id": c.id,
            "severity": c.severity,
            "title": c.title,
            "attack_narrative": c.attack_narrative,
            "why_compound": c.why_compound,
            "remediation": c.remediation,
        }
        for c in compounds
    ]
    output_path = results_dir / "compound_findings.json"
    output_path.write_text(json.dumps(output, indent=2))
    print(f"Saved to: {output_path}")


if __name__ == "__main__":
    main()
