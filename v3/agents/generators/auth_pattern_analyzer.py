"""
Auth Pattern Analyzer — detects authorization patterns and gaps in handler files.

Identifies:
- Whether a handler accesses authorizer context (tenant_id from JWT)
- Whether body-sourced IDs are compared against auth context
- Unguarded state mutations (DynamoDB writes without permission checks)
"""
from __future__ import annotations

import re
import logging
from pathlib import Path
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Patterns indicating the handler reads tenant identity from the authorizer
AUTH_CONTEXT_PATTERNS = [
    r"event\s*\[.requestContext.\]\s*\[.authorizer.\]",
    r"event\.get\(.requestContext.\)\s*\.get\(.authorizer.\)",
    r"requestContext.*authorizer.*tenant_id",
    r"authorizer.*tenant_id",
    r"auth_context\s*=",
    r"tenant_id\s*=\s*event.*authorizer",
]

# Patterns indicating body-sourced identifiers (user-controlled)
BODY_ID_PATTERNS = [
    (r'body\.get\(["\']customer_id["\']', "customer_id"),
    (r'body\[["\']customer_id["\']\]', "customer_id"),
    (r'body\.get\(["\']tenant_id["\']', "tenant_id"),
    (r'body\[["\']tenant_id["\']\]', "tenant_id"),
    (r'body\.get\(["\']session_id["\']', "session_id"),
    (r'body\[["\']session_id["\']\]', "session_id"),
    (r'body\.get\(["\']user_id["\']', "user_id"),
    (r'body\[["\']user_id["\']\]', "user_id"),
    (r'headers\.get\(["\']x-customer-id["\']', "x-customer-id"),
    (r'input_data\[["\']customer_id["\']\]', "customer_id"),
]

# Patterns indicating data operations (both reads and writes — reading another
# tenant's data is as dangerous as writing it for IDOR detection)
MUTATION_SINK_PATTERNS = [
    r"table\.put_item\(",
    r"table\.update_item\(",
    r"table\.delete_item\(",
    r"table\.query\(",
    r"table\.get_item\(",
    r"cognito.*admin_create_user\(",
    r"cognito.*admin_update_user_attributes\(",
    r"s3.*put_object\(",
    r"s3.*get_object\(",
    r"s3.*list_objects\(",
    r"s3.*delete_object\(",
    r"generate_presigned_url\(",
    r"_tool_list_files\(",
    r"_tool_get_",
    r"s3\.Bucket\(.*\)\.objects\.filter\(",
]

# Patterns indicating authorization validation
AUTH_VALIDATION_PATTERNS = [
    r"if\s+.*customer_id\s*!=\s*.*tenant_id",
    r"if\s+.*tenant_id\s*!=\s*.*customer_id",
    r"assert\s+.*customer_id\s*==\s*.*tenant_id",
    r"check_permission\(",
    r"if\s+not\s+customer_id",
    r"customer_id\s*==\s*auth.*tenant",
    r"tenant_id\s*==\s*.*customer_id",
]


@dataclass
class AuthAnalysisResult:
    """Analysis result for a single file."""
    file_path: str
    has_auth_context: bool = False
    auth_context_lines: list[int] = field(default_factory=list)
    body_sourced_ids: list[dict] = field(default_factory=list)
    mutation_sinks: list[dict] = field(default_factory=list)
    has_auth_validation: bool = False
    auth_validation_lines: list[int] = field(default_factory=list)


class AuthPatternAnalyzer:
    """Analyzes authorization patterns across handler files."""

    def analyze_file(self, file_path: str) -> AuthAnalysisResult:
        """Analyze a single file for auth patterns."""
        try:
            content = Path(file_path).read_text()
        except (FileNotFoundError, PermissionError):
            return AuthAnalysisResult(file_path=file_path)

        lines = content.split("\n")
        result = AuthAnalysisResult(file_path=file_path)

        for i, line in enumerate(lines, 1):
            # Check for auth context access
            for pattern in AUTH_CONTEXT_PATTERNS:
                if re.search(pattern, line):
                    result.has_auth_context = True
                    result.auth_context_lines.append(i)
                    break

            # Check for body-sourced IDs
            for pattern, id_name in BODY_ID_PATTERNS:
                if re.search(pattern, line):
                    result.body_sourced_ids.append({
                        "id_name": id_name,
                        "line": i,
                        "text": line.strip(),
                    })

            # Check for mutation sinks
            for pattern in MUTATION_SINK_PATTERNS:
                if re.search(pattern, line):
                    result.mutation_sinks.append({
                        "line": i,
                        "text": line.strip(),
                    })

            # Check for auth validation
            for pattern in AUTH_VALIDATION_PATTERNS:
                if re.search(pattern, line):
                    result.has_auth_validation = True
                    result.auth_validation_lines.append(i)

        return result

    def find_idor_candidates(self, file_path: str) -> list[dict]:
        """
        Find IDOR candidates: body-sourced IDs flowing to data operations
        WITHOUT comparison against authorizer context.

        IDOR exists when:
        1. Handler reads an ID from body (user-controlled)
        2. That ID reaches a data operation (sink)
        3. The file does NOT access authorizer context OR does not compare body ID vs auth ID
        """
        result = self.analyze_file(file_path)

        if not result.body_sourced_ids or not result.mutation_sinks:
            return []

        # If file has auth validation comparing body ID to auth context → safe
        if result.has_auth_validation:
            return []

        # If file accesses auth context AND uses it for the data key → check more carefully
        if result.has_auth_context:
            content = Path(file_path).read_text()
            # Check if auth context value is used in the data operations
            # Look for patterns like: tenant_id = event[...authorizer...]; table.query(Key=tenant_id)
            for body_id in result.body_sourced_ids:
                id_name = body_id["id_name"]
                # If the body ID is "customer_id" but the code also sets customer_id from authorizer,
                # it might be safe. Check if there's an overwrite.
                overwrite_pattern = rf"{id_name}\s*=\s*.*authorizer.*tenant"
                if re.search(overwrite_pattern, content):
                    continue
                # Body ID flows to sink without being overwritten by auth context
                return [{
                    "file_path": file_path,
                    "body_id": body_id,
                    "sinks": result.mutation_sinks,
                    "auth_context_accessed": True,
                    "auth_validation": False,
                    "reason": f"body.{id_name} reaches data operations; auth context accessed but body ID not validated against it",
                }]
            return []

        # No auth context at all → body IDs go directly to sinks unvalidated
        candidates = []
        for body_id in result.body_sourced_ids:
            candidates.append({
                "file_path": file_path,
                "body_id": body_id,
                "sinks": result.mutation_sinks,
                "auth_context_accessed": False,
                "auth_validation": False,
                "reason": f"body.{body_id['id_name']} reaches data operations; authorizer context NEVER accessed",
            })

        return candidates

    def find_unguarded_state_mutations(self, file_path: str) -> list[dict]:
        """Find DynamoDB/Cognito mutations without any preceding permission check."""
        result = self.analyze_file(file_path)

        if not result.mutation_sinks:
            return []

        # If there's a check_permission() call before the mutations → guarded
        content = Path(file_path).read_text()
        if "check_permission(" in content:
            return []

        # If no auth of any kind and mutations exist → unguarded
        if not result.has_auth_context and not result.has_auth_validation:
            return [{
                "file_path": file_path,
                "mutations": result.mutation_sinks,
                "reason": "State mutations without any authorization check",
            }]

        return []
