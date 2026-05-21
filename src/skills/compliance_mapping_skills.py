from __future__ import annotations

"""
Compliance Framework Mapping Skills
=====================================
Map security findings to SOC2 and HIPAA compliance controls.

This is especially important for this codebase because:
1. The platform IS a compliance tool — its own security must meet the standards it evaluates
2. Customers using this platform for SOC2/HIPAA trust it with their compliance data
3. A security finding in this platform = potential violation of the standards it claims to help with
"""


# =============================================================================
# SKILL 1: SOC2 Trust Service Criteria Mapping
# =============================================================================

SOC2_MAPPING = {
    "CC1": {
        "name": "Control Environment",
        "description": "The entity demonstrates commitment to integrity and ethical values, "
                     "exercises oversight responsibility, establishes structure/authority/responsibility.",
        "findings_that_violate": [
            "No MFA enforcement for admin roles (CDK-COG-003)",
            "Shared API key across all users (SEC-003)",
        ],
    },
    "CC5": {
        "name": "Control Activities",
        "sub_criteria": {
            "CC5.1": "Selects and develops control activities that mitigate risks",
            "CC5.2": "Deploys through policies and procedures",
        },
        "findings_that_violate": [
            "Permission bypass via unmapped tools (COMP-AUTH-002)",
            "Deny-by-default not implemented for unknown tools",
            "Scope bypass for compliance_managers (COMP-SCOPE-001)",
        ],
    },
    "CC6": {
        "name": "Logical and Physical Access Controls",
        "sub_criteria": {
            "CC6.1": "Implements logical access security",
            "CC6.2": "Requires authentication before access",
            "CC6.3": "Manages credentials",
            "CC6.6": "Restricts access to system components",
            "CC6.7": "Restricts data access and protects from threats",
            "CC6.8": "Prevents or detects unauthorized software",
        },
        "findings_that_violate": {
            "CC6.1": [
                "Cross-tenant data access (COMP-TENANT-001) — violates logical access",
                "IAM policies without LeadingKey condition (TC-COMP-005)",
                "Overpermissive IAM roles (CDK-IAM-002: bedrock-agentcore:*)",
            ],
            "CC6.2": [
                "API routes without authorizer (CDK-NET-001)",
                "Self-signup without admin approval (CDK-COG-001)",
            ],
            "CC6.3": [
                "Mutable Cognito role attribute (CDK-COG-002) — privilege escalation",
                "Refresh token not rotated (FE-AUTH-004)",
                "30-day refresh token validity without rotation",
            ],
            "CC6.6": [
                "Blast radius too large (agent Lambda: 9.2/10)",
                "Shared IAM role across multiple functions",
            ],
            "CC6.7": [
                "No S3 versioning on evidence bucket (CDK-S3-001)",
                "No S3 access logging (CDK-S3-002)",
                "Evidence tampering undetectable (TC-COMP-003)",
            ],
        },
    },
    "CC7": {
        "name": "System Operations",
        "sub_criteria": {
            "CC7.1": "Detects changes to infrastructure and software",
            "CC7.2": "Monitors system components for anomalies",
            "CC7.3": "Evaluates and communicates security events",
        },
        "findings_that_violate": {
            "CC7.1": [
                "No drift detection between CDK and deployed state",
            ],
            "CC7.2": [
                "7-day CloudWatch log retention (CDK-LOG-001) — insufficient for detection",
                "No S3 access logging — cannot detect unauthorized evidence access",
                "No CloudTrail S3 data events in stack",
            ],
            "CC7.3": [
                "No CloudWatch alarms for authentication failures",
                "No alerting on cross-tenant access attempts",
            ],
        },
    },
    "CC8": {
        "name": "Change Management",
        "sub_criteria": {
            "CC8.1": "Authorizes, designs, develops, acquires, configures, tests, approves, "
                    "and implements changes",
        },
        "findings_that_violate": [
            "CDK nag suppressions without adequate justification review",
        ],
    },
}


# =============================================================================
# SKILL 2: HIPAA Security Rule Mapping (if applicable)
# =============================================================================

HIPAA_MAPPING = {
    "note": "Applicable if the compliance platform processes Protected Health Information (PHI). "
           "Even if it doesn't directly process PHI, customers using it for HIPAA compliance "
           "may store PHI-adjacent data (control evidence, audit findings about PHI systems).",

    "164.312(a)(1)": {
        "name": "Access Control",
        "requirement": "Implement technical policies and procedures for electronic information "
                     "systems that maintain ePHI to allow access only to authorized persons.",
        "findings_that_violate": [
            "Cross-tenant data access (COMP-TENANT-001)",
            "IAM without LeadingKey condition (TC-COMP-005)",
            "Permission bypass via tool manipulation (COMP-AUTH-002)",
        ],
    },
    "164.312(a)(2)(i)": {
        "name": "Unique User Identification",
        "requirement": "Assign a unique name/number for identifying and tracking user identity.",
        "findings_that_violate": [
            "Shared API key (SEC-003) — no per-user attribution",
        ],
    },
    "164.312(a)(2)(iii)": {
        "name": "Automatic Logoff",
        "requirement": "Implement electronic procedures that terminate sessions after inactivity.",
        "compliance_status": "PARTIAL — Access tokens expire in 1 hour (good), "
                           "but refresh tokens valid 30 days without rotation.",
    },
    "164.312(b)": {
        "name": "Audit Controls",
        "requirement": "Implement mechanisms to record and examine activity in systems containing ePHI.",
        "findings_that_violate": [
            "7-day log retention (CDK-LOG-001) — HIPAA requires minimum 6 years",
            "No S3 access logging (CDK-S3-002) — cannot audit evidence access",
            "No CloudTrail data events — cannot audit DynamoDB access",
        ],
    },
    "164.312(c)(1)": {
        "name": "Integrity Controls",
        "requirement": "Implement policies to protect ePHI from improper alteration or destruction.",
        "findings_that_violate": [
            "No S3 versioning (CDK-S3-001) — evidence can be overwritten/deleted",
            "No DynamoDB deletion protection (CDK-DDB-002)",
            "Evidence tampering undetectable (TC-COMP-003)",
        ],
    },
    "164.312(d)": {
        "name": "Person or Entity Authentication",
        "requirement": "Implement procedures to verify identity of person seeking access.",
        "compliance_status": "GOOD — Cognito provides identity verification with MFA option.",
        "gap": "MFA is optional (should be required for roles accessing PHI-adjacent data).",
    },
    "164.312(e)(1)": {
        "name": "Transmission Security",
        "requirement": "Implement measures to guard against unauthorized access to ePHI being transmitted.",
        "compliance_status": "GOOD — API Gateway enforces TLS. S3 enforces SSL (enforce_ssl=True).",
    },
}


# =============================================================================
# SKILL 3: Finding → Compliance Impact Template
# =============================================================================

COMPLIANCE_IMPACT_TEMPLATE = """
## Compliance Impact Assessment

### Finding: {finding_title}
**Severity:** {severity} | **CWE:** {cwe}

### SOC2 Impact:
{soc2_violations}

### HIPAA Impact (if PHI-adjacent data):
{hipaa_violations}

### Business Risk:
- This platform evaluates OTHER organizations' compliance
- A vulnerability in the platform itself undermines trust in its assessments
- If evidence can be tampered with: compliance certifications based on this tool are questionable
- If cross-tenant access exists: one customer's compliance data leaks to another

### Auditor Perspective:
An external auditor reviewing this platform would flag:
{auditor_concerns}

### Remediation Priority:
{priority_rationale}
"""


# =============================================================================
# SKILL 4: Compliance-Aware Severity Adjustment
# =============================================================================

COMPLIANCE_SEVERITY_BOOST = {
    "description": "For a compliance platform, certain findings are more severe than their "
                 "CVSS score suggests because of the TRUST implications.",
    "adjustments": [
        {
            "condition": "Finding affects audit trail integrity",
            "boost": "+1 severity level",
            "reason": "Audit trail is the foundation of compliance. If it can be tampered, "
                    "ALL compliance assessments from this platform are unreliable.",
            "examples": ["No S3 versioning", "Short log retention", "No access logging"],
        },
        {
            "condition": "Finding allows cross-tenant data access",
            "boost": "+1 severity level (minimum CRITICAL)",
            "reason": "Compliance data is customer-confidential. Cross-tenant leak means "
                    "Customer A's audit findings visible to Customer B — regulatory breach.",
        },
        {
            "condition": "Finding enables evidence forgery",
            "boost": "+1 severity level",
            "reason": "If evaluation results or evidence can be forged, the platform "
                    "cannot be trusted for compliance certification purposes.",
        },
        {
            "condition": "Finding violates HIPAA audit control (164.312(b))",
            "boost": "+1 severity level if HIPAA-scoped deployment",
            "reason": "HIPAA requires 6 years of audit records. 7-day retention is "
                    "not just a best-practice gap — it's a regulatory violation.",
        },
    ],
}


# =============================================================================
# SKILL 5: Compliance Report Section Generator
# =============================================================================

def generate_compliance_section(findings: list) -> str:
    """Generate the compliance impact section of the security report."""
    soc2_violations = {}
    hipaa_violations = {}

    for finding in findings:
        for cc, criteria in SOC2_MAPPING.items():
            violations = criteria.get("findings_that_violate", {})
            if isinstance(violations, dict):
                for sub, sub_violations in violations.items():
                    for v in sub_violations:
                        if finding.id in v or finding.title in v:
                            key = f"{cc}.{sub}" if "." not in sub else sub
                            soc2_violations.setdefault(key, []).append(finding)
            elif isinstance(violations, list):
                for v in violations:
                    if finding.id in v or finding.title in v:
                        soc2_violations.setdefault(cc, []).append(finding)

    sections = []
    if soc2_violations:
        sections.append("### SOC2 Trust Service Criteria Violations\n")
        for criteria, findings_list in sorted(soc2_violations.items()):
            sections.append(f"**{criteria}**: {len(findings_list)} finding(s)")
            for f in findings_list:
                sections.append(f"  - [{f.severity}] {f.title}")

    return "\n".join(sections)
