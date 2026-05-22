"""
V6 Layer 1, Track B: Commit-Diff Seeding.

Big Sleep's primary technique: use recent security-fix commits
as seeds to find unfixed siblings in the current code.
"""
from __future__ import annotations

import subprocess
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


SYSTEM = """You are analyzing a codebase where a security fix was recently applied.
Your job: find OTHER places in the code where the SAME class of bug exists but HASN'T been fixed.

The fix shows you: what was wrong (before) and what's correct (after).
Now search for code that still looks like the "before" version."""


PROMPT = """## Commit-Diff Seeding: Find Unfixed Siblings

### Recent Security Fix:
```diff
{diff}
```

Commit message: {message}

### What this fix tells us:
The bug was: {bug_pattern}
The fix added: {fix_pattern}

### Target Code (search for unfixed instances):
{evidence}

### Known Findings (already reported):
{known}

### Find:
Code that has the SAME structural flaw as the "before" version of this diff
but was NOT fixed by this commit. Look in different files, different functions,
different modules — anywhere the same pattern might exist.

Output for each unfixed sibling:
```json
{{
  "location": "[file:line]",
  "similar_to": "what in the diff this resembles",
  "why_unfixed": "why this commit didn't catch it (different file/function)",
  "exploitability": "is this reachable?"
}}
```
"""


class CommitDiffSeeder:
    """Extracts security-relevant diffs and seeds variant analysis."""

    def get_security_diffs(self, repo_path: str, max_commits: int = 20) -> list[dict]:
        """Extract recent security-related commits."""
        repo = Path(repo_path)
        if not (repo / ".git").exists():
            return []

        try:
            result = subprocess.run(
                ["git", "log", f"--max-count={max_commits}", "--oneline",
                 "--grep=fix", "--grep=security", "--grep=vuln", "--grep=auth",
                 "--grep=sanitize", "--grep=validate", "--all-match",
                 "--format=%H %s"],
                cwd=str(repo), capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return []

            commits = []
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                parts = line.split(" ", 1)
                if len(parts) == 2:
                    sha, message = parts
                    diff = self._get_diff(repo, sha)
                    if diff:
                        commits.append({"sha": sha, "message": message, "diff": diff})

            return commits

        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []

    def _get_diff(self, repo: Path, sha: str) -> str:
        """Get the diff for a commit."""
        try:
            result = subprocess.run(
                ["git", "diff", f"{sha}~1..{sha}", "--", "*.py"],
                cwd=str(repo), capture_output=True, text=True, timeout=10,
            )
            return result.stdout[:5000] if result.returncode == 0 else ""
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return ""

    def build_prompt(self, commit: dict, evidence_text: str, known: list[str]) -> str:
        """Build prompt for one commit's diff."""
        known_text = "\n".join(f"- {f}" for f in known[:20])
        return PROMPT.format(
            diff=commit["diff"][:3000],
            message=commit["message"],
            bug_pattern="(inferred from diff - pattern before fix)",
            fix_pattern="(inferred from diff - what was added/changed)",
            evidence=evidence_text[:60000],
            known=known_text,
        )

    def get_system(self) -> str:
        return SYSTEM
