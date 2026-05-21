"""
V4 Report Generator — produces analyst-grade security reports.

Generates structured Markdown reports with:
- Executive summary
- Finding details with evidence walks
- Attack chains
- Confidence annotations (verified/could not verify)
- Suggested fixes referencing existing secure patterns
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from dataclasses import dataclass, field

from v4.analysis.evidence_walker import EvidenceWalk
from v4.analysis.absence_detector import AbsenceFinding
from v4.analysis.differential_analyzer import DifferentialFinding
from v4.analysis.chain_synthesizer import AttackChain

logger = logging.getLogger(__name__)


@dataclass
class ReportFinding:
    """Unified finding format for the report."""
    id: str
    title: str
    severity: str
    confidence: str  # HIGH | MEDIUM | LOW
    risk_type: str
    description: str
    evidence_walk: EvidenceWalk | None = None
    verified: list[str] = field(default_factory=list)
    could_not_verify: list[str] = field(default_factory=list)
    code_locations: list[str] = field(default_factory=list)
    suggested_fix: str = ""
    cwe: str = ""
    source: str = ""  # which detector found this


@dataclass
class V4Report:
    """The complete V4 security report."""
    target_repo: str
    findings: list[ReportFinding]
    attack_chains: list[AttackChain]
    summary: dict = field(default_factory=dict)

    def render_markdown(self) -> str:
        """Render the full report as Markdown."""
        sections = []
        sections.append(self._render_header())
        sections.append(self._render_executive_summary())
        sections.append(self._render_findings_table())
        sections.append(self._render_attack_chains())
        sections.append(self._render_detailed_findings())
        return "\n\n".join(sections)

    def render_json(self) -> str:
        """Render as machine-readable JSON."""
        data = {
            "target": self.target_repo,
            "summary": self.summary,
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "risk_type": f.risk_type,
                    "description": f.description,
                    "cwe": f.cwe,
                    "evidence": f.evidence_walk.render() if f.evidence_walk else "",
                    "verified": f.verified,
                    "could_not_verify": f.could_not_verify,
                    "code_locations": f.code_locations,
                    "suggested_fix": f.suggested_fix,
                }
                for f in self.findings
            ],
            "attack_chains": [
                {
                    "id": c.id,
                    "title": c.title,
                    "composite_severity": c.composite_severity,
                    "steps": [{"id": s.id, "title": s.title, "severity": s.severity} for s in c.steps],
                    "narrative": c.narrative,
                }
                for c in self.attack_chains
            ],
        }
        return json.dumps(data, indent=2)

    def _render_header(self) -> str:
        return (
            "# Security Analysis Report\n\n"
            f"**Target:** `{self.target_repo}`\n\n"
            "---"
        )

    def _render_executive_summary(self) -> str:
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        total = len(self.findings)
        lines = ["## Executive Summary", ""]
        lines.append(
            f"This analysis identified **{total} findings**: "
            f"{sev_counts['CRITICAL']} critical, {sev_counts['HIGH']} high, "
            f"{sev_counts['MEDIUM']} medium, {sev_counts['LOW']} low."
        )

        if self.attack_chains:
            critical_chains = [c for c in self.attack_chains if c.composite_severity == "CRITICAL"]
            if critical_chains:
                lines.append("")
                lines.append(f"**{len(critical_chains)} critical attack chains** were identified:")
                for chain in critical_chains[:3]:
                    lines.append(f"- {chain.title}")

        # Top findings
        critical_findings = [f for f in self.findings if f.severity == "CRITICAL"]
        if critical_findings:
            lines.append("")
            lines.append("**Critical findings requiring immediate attention:**")
            for f in critical_findings[:5]:
                lines.append(f"- {f.title}")

        return "\n".join(lines)

    def _render_findings_table(self) -> str:
        lines = ["## Findings Summary", ""]
        lines.append("| # | Severity | Finding | Confidence |")
        lines.append("|---|----------|---------|------------|")

        for i, f in enumerate(self.findings, 1):
            lines.append(f"| {i} | {f.severity} | {f.title} | {f.confidence} |")

        return "\n".join(lines)

    def _render_attack_chains(self) -> str:
        if not self.attack_chains:
            return ""

        lines = ["## Attack Chains", ""]
        for chain in self.attack_chains:
            lines.append(chain.narrative)
            lines.append("")
            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    def _render_detailed_findings(self) -> str:
        lines = ["## Detailed Findings", ""]

        for i, f in enumerate(self.findings, 1):
            lines.append(f"### Finding {i}: {f.title}")
            lines.append("")
            lines.append(f"| Field | Value |")
            lines.append(f"|-------|-------|")
            lines.append(f"| Severity | {f.severity} |")
            lines.append(f"| Confidence | {f.confidence} |")
            lines.append(f"| Risk Type | {f.risk_type} |")
            if f.cwe:
                lines.append(f"| CWE | {f.cwe} |")
            lines.append("")

            # Description
            lines.append("**Description**")
            lines.append("")
            lines.append(f"{f.description}")
            lines.append("")

            # Evidence walk
            if f.evidence_walk:
                lines.append("**Evidence Walk**")
                lines.append("")
                lines.append("```")
                lines.append(f.evidence_walk.render())
                lines.append("```")
                lines.append("")

            # Verified / Could not verify
            if f.verified:
                lines.append("**Verified:**")
                for v in f.verified:
                    lines.append(f"- {v}")
                lines.append("")

            if f.could_not_verify:
                lines.append("**Could not verify:**")
                for v in f.could_not_verify:
                    lines.append(f"- {v}")
                lines.append("")

            # Code locations
            if f.code_locations:
                lines.append("**Code Locations**")
                for loc in f.code_locations:
                    lines.append(f"- `{loc}`")
                lines.append("")

            # Fix
            if f.suggested_fix:
                lines.append("**Suggested Fix**")
                lines.append("")
                lines.append(f.suggested_fix)
                lines.append("")

            lines.append("---")
            lines.append("")

        return "\n".join(lines)


class ReportGenerator:
    """Assembles findings from all V4 detectors into a unified report."""

    def __init__(self, target_repo: str):
        self.target_repo = target_repo

    def generate(
        self,
        evidence_walks: list[tuple[dict, EvidenceWalk]],
        absence_findings: list[AbsenceFinding],
        differential_findings: list[DifferentialFinding],
        attack_chains: list[AttackChain],
        semgrep_findings: list[dict] | None = None,
        z3_findings: list[dict] | None = None,
    ) -> V4Report:
        """Generate the unified report from all detector outputs."""
        report_findings = []

        # Convert evidence walks (from semgrep findings)
        for finding_dict, walk in evidence_walks:
            rf = ReportFinding(
                id=finding_dict.get("id", ""),
                title=finding_dict.get("title", ""),
                severity=finding_dict.get("severity", "MEDIUM"),
                confidence="HIGH" if walk else "MEDIUM",
                risk_type=finding_dict.get("category", ""),
                description=self._make_description(finding_dict, walk),
                evidence_walk=walk,
                verified=self._extract_verified(walk),
                could_not_verify=self._extract_unverified(finding_dict),
                code_locations=[f"{finding_dict.get('file_path', '')}:{finding_dict.get('line', 0)}"],
                suggested_fix=self._generate_fix(finding_dict, walk),
                cwe=finding_dict.get("cwe", ""),
                source="semgrep+cpg",
            )
            report_findings.append(rf)

        # Convert absence findings
        for af in absence_findings:
            rf = ReportFinding(
                id=af.id,
                title=af.title,
                severity=af.severity,
                confidence="HIGH",
                risk_type=af.category,
                description=af.description,
                verified=[af.evidence],
                could_not_verify=["Whether compensating controls exist at infrastructure level"],
                code_locations=[f"{af.file_path}:{af.line}"],
                suggested_fix=self._fix_for_absence(af),
                cwe=af.cwe,
                source="absence_detector",
            )
            report_findings.append(rf)

        # Convert Z3 IAM findings
        for zf in (z3_findings or []):
            rf = ReportFinding(
                id=zf.get("id", ""),
                title=zf.get("title", ""),
                severity=zf.get("severity", "HIGH"),
                confidence="HIGH",
                risk_type=zf.get("category", "iam"),
                description=zf.get("description", ""),
                verified=[
                    f"Z3 proof: {zf.get('z3_proof', 'formally verified via SMT solver')}",
                    zf.get("evidence", ""),
                ],
                could_not_verify=["Whether runtime controls (WAF, VPC, service control policies) provide compensating mitigation"],
                code_locations=[f"{zf.get('file_path', 'infra/')}:{zf.get('line', 0)}"],
                suggested_fix=self._fix_for_z3(zf),
                cwe=zf.get("cwe", ""),
                source="z3_formal_verification",
            )
            report_findings.append(rf)

        # Convert differential findings
        for df in differential_findings:
            rf = ReportFinding(
                id=df.id,
                title=df.title,
                severity=df.severity,
                confidence="HIGH",
                risk_type=df.category,
                description=df.description,
                verified=[
                    f"Stronger path ({Path(df.stronger_path.entry_file).name}::{df.stronger_path.entry_handler}) has guards: {sorted(df.stronger_path.guard_types)}",
                    f"Weaker path ({Path(df.weaker_path.entry_file).name}::{df.weaker_path.entry_handler}) missing: {df.missing_guards}",
                ],
                could_not_verify=["Whether the weaker path is reachable from the internet"],
                code_locations=[
                    f"{df.weaker_path.entry_file}:{df.weaker_path.sink_line} — weaker path",
                    f"{df.stronger_path.entry_file}:{df.stronger_path.sink_line} — stronger path (reference)",
                ],
                suggested_fix=self._fix_for_differential(df),
                cwe=df.cwe,
                source="differential_analyzer",
            )
            report_findings.append(rf)

        # Sort by severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        report_findings.sort(key=lambda f: sev_order.get(f.severity, 4))

        # Deduplicate by title
        seen_titles = set()
        deduped = []
        for f in report_findings:
            if f.title not in seen_titles:
                seen_titles.add(f.title)
                deduped.append(f)

        # Summary
        sev_counts = {}
        for f in deduped:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        summary = {
            "total_findings": len(deduped),
            "severity_distribution": sev_counts,
            "attack_chains": len(attack_chains),
            "critical_chains": len([c for c in attack_chains if c.composite_severity == "CRITICAL"]),
        }

        return V4Report(
            target_repo=self.target_repo,
            findings=deduped,
            attack_chains=attack_chains,
            summary=summary,
        )

    def _make_description(self, finding: dict, walk: EvidenceWalk | None) -> str:
        title = finding.get("title", "")
        category = finding.get("category", "")

        if "cross-tenant" in category:
            return (
                f"User-controlled input reaches a data operation without tenant ownership verification. "
                f"An authenticated attacker can supply another tenant's identifier to access or modify their data."
            )
        elif "path-traversal" in category:
            return (
                f"User-controlled filename/path components are used in S3 key construction without sanitization. "
                f"An attacker can use path traversal characters (../, /) to escape the tenant prefix."
            )
        elif "privilege-escalation" in category:
            return (
                f"Cognito admin operations are performed without verifying the caller's role permits the action."
            )
        return f"Security finding: {title} ({category})"

    def _extract_verified(self, walk: EvidenceWalk | None) -> list[str]:
        if not walk:
            return []
        verified = []
        for step in walk.steps:
            if step.step_type == "sink":
                verified.append(f"Sink confirmed at {Path(step.file_path).name}:{step.line}: {step.annotation}")
            elif step.step_type == "missing_check":
                verified.append(f"Missing control confirmed: {step.annotation}")
        if walk.missing_controls:
            for mc in walk.missing_controls:
                verified.append(f"Verified absent: {mc}")
        return verified

    def _extract_unverified(self, finding: dict) -> list[str]:
        unverified = []
        category = finding.get("category", "")
        if "cross-tenant" in category:
            unverified.append("Whether compensating controls exist at API Gateway or WAF level")
        if "path-traversal" in category:
            unverified.append("Whether S3 bucket policies restrict key prefixes")
        unverified.append("Whether this finding is exploitable in the deployed environment")
        return unverified

    def _generate_fix(self, finding: dict, walk: EvidenceWalk | None) -> str:
        category = finding.get("category", "")
        if "cross-tenant" in category:
            return (
                "Use the authorizer-verified tenant_id from `event['requestContext']['authorizer']['tenant_id']` "
                "instead of accepting it from the request body. Add ownership verification: "
                "`if session['customer_id'] != customer_id: return 403`."
            )
        elif "path-traversal" in category:
            return (
                "Apply the same sanitization used in handler.py:116-117:\n"
                "```python\n"
                "filename = filename.replace('/', '_').replace('\\\\', '_').replace('..', '_')\n"
                "```\n"
                "Apply to all user-controlled S3 key components (filename, framework, control_id)."
            )
        elif "privilege-escalation" in category:
            return (
                "Add role verification before Cognito admin operations:\n"
                "```python\n"
                "if role not in ('admin',):\n"
                "    return _json_response(403, {'error': 'Insufficient permissions'})\n"
                "```"
            )
        return ""

    def _fix_for_absence(self, af: AbsenceFinding) -> str:
        if "audit" in af.missing_guard:
            return (
                "Add audit logging before data modification operations:\n"
                "```python\n"
                "logger.info(f'AUDIT: {method} {resource} by {tenant_id} role={role}')\n"
                "```"
            )
        elif "ownership" in af.missing_guard:
            return (
                "Add ownership verification after loading the record:\n"
                "```python\n"
                "if session.get('customer_id') != customer_id:\n"
                "    return _json_response(403, {'error': 'Access denied'})\n"
                "```"
            )
        elif "role_check" in af.missing_guard:
            return (
                "Add role-based authorization before write operations:\n"
                "```python\n"
                "WRITE_ROLES = {'admin', 'compliance_manager'}\n"
                "if role not in WRITE_ROLES:\n"
                "    return _json_response(403, {'error': 'Insufficient permissions'})\n"
                "```"
            )
        elif "rate_limit" in af.missing_guard:
            return "Add rate limiting at the API Gateway level or implement token-bucket throttling in the handler."
        elif "input_sanitization" in af.missing_guard:
            return (
                "Sanitize path components before constructing S3 keys:\n"
                "```python\n"
                "def _sanitize_path(val):\n"
                "    return val.replace('/', '_').replace('\\\\', '_').replace('..', '_').strip('._')\n"
                "```"
            )
        return ""

    def _fix_for_z3(self, zf: dict) -> str:
        category = zf.get("category", "")
        if "multi_tenant" in category:
            return (
                "Add DynamoDB LeadingKeys condition to the IAM policy:\n"
                "```python\n"
                "iam.PolicyStatement(\n"
                "    actions=['dynamodb:GetItem', 'dynamodb:PutItem', ...],\n"
                "    resources=[table.table_arn],\n"
                "    conditions={\n"
                "        'ForAllValues:StringLike': {\n"
                "            'dynamodb:LeadingKeys': ['TENANT#${aws:PrincipalTag/tenant_id}*']\n"
                "        }\n"
                "    }\n"
                ")\n"
                "```\n"
                "This provides IAM-level tenant isolation that cannot be bypassed by application code."
            )
        elif "overpermissive" in category or "wildcard" in category.lower():
            return (
                "Replace wildcard actions with the minimum required set:\n"
                "```python\n"
                "actions=['service:SpecificAction1', 'service:SpecificAction2']\n"
                "```\n"
                "Scope resources to specific ARNs instead of '*'."
            )
        return "Apply least-privilege principles to this IAM policy."

    def _fix_for_differential(self, df: DifferentialFinding) -> str:
        stronger = Path(df.stronger_path.entry_file).name
        weaker = Path(df.weaker_path.entry_file).name
        return (
            f"Apply the same security controls used in {stronger}::{df.stronger_path.entry_handler} "
            f"to {weaker}::{df.weaker_path.entry_handler}. "
            f"Missing guards: {', '.join(df.missing_guards)}. "
            f"Consider consolidating into a shared security middleware."
        )
