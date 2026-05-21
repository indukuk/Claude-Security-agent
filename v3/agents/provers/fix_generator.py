"""
Fix Generator — pattern-based remediation code generation.

Generates targeted code fixes for confirmed security findings.
Supports pattern-based fixes for known vulnerability classes and
a generic template for novel patterns.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Fix:
    """A proposed code fix."""
    finding_id: str
    file_path: str
    original_code: str
    fixed_code: str
    description: str
    fix_type: str  # "pattern" | "template"
    confidence: float  # 0.0-1.0

    def as_diff(self) -> str:
        """Render as unified diff-like format."""
        lines = [f"--- {self.file_path}", f"+++ {self.file_path} (fixed)"]
        for line in self.original_code.splitlines():
            lines.append(f"- {line}")
        for line in self.fixed_code.splitlines():
            lines.append(f"+ {line}")
        return "\n".join(lines)


class FixGenerator:
    """
    Generate code fixes for security findings.

    Uses pattern matching for known vulnerability classes:
    - IDOR: replace body-sourced IDs with authorizer context
    - Path traversal: add basename/normpath sanitization
    - XSS: add DOMPurify or textContent
    - IAM wildcard: scope to specific actions
    - Log injection: sanitize before logging
    """

    def generate(self, finding: dict, source_code: str) -> Fix | None:
        """Generate a fix for the given finding and source code."""
        category = finding.get("category", "")
        title = finding.get("title", "")

        # Dispatch to pattern-specific generators
        if "cross_tenant" in category or "cross-tenant" in title or "IDOR" in title:
            return self._fix_idor(finding, source_code)
        elif "missing_authorization" in category or "missing-auth" in title:
            return self._fix_idor(finding, source_code)
        elif "path_traversal" in category or "path-traversal" in title or "presigned-url" in title:
            return self._fix_path_traversal(finding, source_code)
        elif "dom_xss" in category or "innerHTML" in title or "dom-xss" in title:
            return self._fix_xss(finding, source_code)
        elif "log_injection" in category or "log-injection" in title:
            return self._fix_log_injection(finding, source_code)
        elif "overpermissive_iam" in category or "Wildcard action" in title:
            return self._fix_iam_wildcard(finding, source_code)
        elif "cognito" in title or "privilege" in category:
            return self._fix_cognito(finding, source_code)
        else:
            return self._fix_generic(finding, source_code)

    def _fix_idor(self, finding: dict, source_code: str) -> Fix | None:
        """Fix IDOR: replace body-sourced customer/tenant IDs with authorizer context."""
        # Find the vulnerable pattern: body.get("customer_id"), body["customer_id"], etc.
        patterns = [
            (r'(\w+)\s*=\s*body\.get\(["\']customer_id["\']\)',
             'customer_id = event["requestContext"]["authorizer"]["tenant_id"]'),
            (r'(\w+)\s*=\s*body\[["\']customer_id["\']\]',
             'customer_id = event["requestContext"]["authorizer"]["tenant_id"]'),
            (r'body\.get\(["\']customer_id["\']\)',
             'event["requestContext"]["authorizer"]["tenant_id"]'),
            (r'body\[["\']customer_id["\']\]',
             'event["requestContext"]["authorizer"]["tenant_id"]'),
            (r'(\w+)\s*=\s*body\.get\(["\']tenant_id["\']\)',
             'tenant_id = event["requestContext"]["authorizer"]["tenant_id"]'),
            (r'(\w+)\s*=\s*body\.get\(["\']user_id["\']\)',
             'user_id = event["requestContext"]["authorizer"]["sub"]'),
            (r'(\w+)\s*=\s*headers\.get\(["\']x-customer-id["\']\)',
             'customer_id = event["requestContext"]["authorizer"]["tenant_id"]'),
        ]

        for pattern, replacement in patterns:
            match = re.search(pattern, source_code)
            if match:
                original_line = match.group(0)
                return Fix(
                    finding_id=finding.get("id", ""),
                    file_path=finding.get("file_path", ""),
                    original_code=original_line,
                    fixed_code=replacement,
                    description="Use authenticated tenant_id from authorizer context instead of untrusted body parameter",
                    fix_type="pattern",
                    confidence=0.95,
                )

        # Broader pattern: any body.get or body[] with an ID-like field
        id_pattern = re.search(
            r'(\w+)\s*=\s*body(?:\.get\(|\[)["\'](\w*(?:id|Id|ID)\w*)["\'](?:\)|\])',
            source_code
        )
        if id_pattern:
            var_name = id_pattern.group(1)
            field_name = id_pattern.group(2)
            original_line = id_pattern.group(0)
            return Fix(
                finding_id=finding.get("id", ""),
                file_path=finding.get("file_path", ""),
                original_code=original_line,
                fixed_code=f'{var_name} = event["requestContext"]["authorizer"]["tenant_id"]',
                description=f"Replace untrusted body field '{field_name}' with authorizer context",
                fix_type="pattern",
                confidence=0.85,
            )

        return None

    def _fix_path_traversal(self, finding: dict, source_code: str) -> Fix | None:
        """Fix path traversal: add os.path.basename or normpath sanitization."""
        patterns = [
            # f-string with body.get("filename")
            (r'(f["\'][^"\']*\{[^}]*body\.get\(["\']filename["\'][^)]*\)[^}]*\}[^"\']*["\'])',
             lambda m: m.group(0).replace('body.get("filename"', 'os.path.basename(body.get("filename"')
                                 .replace('body.get(\'filename\'', 'os.path.basename(body.get(\'filename\'') + ')'),
            # Direct assignment: filename = body.get("filename")
            (r'(filename\s*=\s*body\.get\(["\']filename["\']\))',
             lambda m: 'filename = os.path.basename(body.get("filename"))'),
            # S3 key construction with filename
            (r'(s3_key\s*=\s*f["\'][^"\']*\{filename\}[^"\']*["\'])',
             lambda m: m.group(0).replace('{filename}', '{os.path.basename(filename)}')),
            # Generic path join with body input
            (r'([\w_]+)\s*=\s*(?:os\.path\.join|f["\'].*)\(.*body\.get\(["\'](\w+)["\']\)',
             lambda m: f'{m.group(1)} = os.path.join(base_dir, os.path.basename(body.get("{m.group(2)}")))'),
        ]

        for pattern, replacement_fn in patterns:
            match = re.search(pattern, source_code)
            if match:
                return Fix(
                    finding_id=finding.get("id", ""),
                    file_path=finding.get("file_path", ""),
                    original_code=match.group(0),
                    fixed_code=replacement_fn(match),
                    description="Sanitize path with os.path.basename to prevent directory traversal",
                    fix_type="pattern",
                    confidence=0.9,
                )

        return None

    def _fix_xss(self, finding: dict, source_code: str) -> Fix | None:
        """Fix XSS: replace innerHTML with DOMPurify.sanitize or textContent."""
        match = re.search(r'(\w+)\.innerHTML\s*=\s*(.+)', source_code)
        if match:
            element = match.group(1)
            value = match.group(2).rstrip(";")
            return Fix(
                finding_id=finding.get("id", ""),
                file_path=finding.get("file_path", ""),
                original_code=match.group(0),
                fixed_code=f"{element}.innerHTML = DOMPurify.sanitize({value});",
                description="Sanitize HTML content with DOMPurify before DOM insertion",
                fix_type="pattern",
                confidence=0.9,
            )
        return None

    def _fix_log_injection(self, finding: dict, source_code: str) -> Fix | None:
        """Fix log injection: sanitize user input before logging."""
        match = re.search(
            r'(logger\.\w+|print)\(.*?(body\.get\(["\'](\w+)["\']\)|(\w+_input))',
            source_code
        )
        if match:
            original = match.group(0)
            user_var = match.group(2) or match.group(4)
            sanitized = original.replace(
                user_var,
                f'{user_var}.replace("\\n", "").replace("\\r", "")'
            )
            return Fix(
                finding_id=finding.get("id", ""),
                file_path=finding.get("file_path", ""),
                original_code=original,
                fixed_code=sanitized,
                description="Strip newlines from user input before logging to prevent log injection",
                fix_type="pattern",
                confidence=0.8,
            )
        return None

    def _fix_iam_wildcard(self, finding: dict, source_code: str) -> Fix | None:
        """Fix IAM wildcard: scope actions to specific operations."""
        match = re.search(r'actions\s*=\s*\[\s*["\'](\w+):\*["\']\s*\]', source_code)
        if match:
            service = match.group(1)
            scoped = {
                "s3": '["s3:GetObject", "s3:PutObject", "s3:ListBucket"]',
                "dynamodb": '["dynamodb:Query", "dynamodb:GetItem", "dynamodb:PutItem"]',
                "bedrock": '["bedrock:InvokeModel"]',
            }
            replacement = scoped.get(service, f'["{service}:Get*", "{service}:List*"]')
            return Fix(
                finding_id=finding.get("id", ""),
                file_path=finding.get("file_path", ""),
                original_code=match.group(0),
                fixed_code=f'actions = {replacement}',
                description=f"Scope {service} IAM actions to least-privilege instead of wildcard",
                fix_type="pattern",
                confidence=0.7,
            )
        return None

    def _fix_cognito(self, finding: dict, source_code: str) -> Fix | None:
        """Fix cognito: validate role/email before passing to admin_create_user."""
        match = re.search(
            r'(cognito(?:_client)?\.admin_create_user\()',
            source_code
        )
        if match:
            original = match.group(0)
            return Fix(
                finding_id=finding.get("id", ""),
                file_path=finding.get("file_path", ""),
                original_code=original,
                fixed_code=(
                    "# Validate inputs before Cognito call\n"
                    "    if not _validate_email(email) or role not in ALLOWED_ROLES:\n"
                    "        return resp(400, {'error': 'Invalid input'})\n"
                    f"    {original}"
                ),
                description="Add input validation before Cognito admin user creation",
                fix_type="pattern",
                confidence=0.7,
            )
        return None

    def _fix_generic(self, finding: dict, source_code: str) -> Fix | None:
        """Generic fix template for unknown patterns."""
        return Fix(
            finding_id=finding.get("id", ""),
            file_path=finding.get("file_path", ""),
            original_code="# See finding for vulnerable code location",
            fixed_code="# Manual remediation required — see description",
            description=f"No automated fix pattern for category: {finding.get('category', 'unknown')}",
            fix_type="template",
            confidence=0.1,
        )
