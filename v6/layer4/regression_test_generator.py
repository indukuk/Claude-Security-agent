"""
V6 Layer 4: Regression Test Generator.

For each confirmed finding, generates a pytest test that:
- FAILS if the vulnerability exists (proves the exploit works)
- PASSES if the fix is applied (proves the fix works)

This creates permanent regression guards that prevent reintroduction.
"""
from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


SYSTEM = """You generate pytest test cases for security vulnerabilities.
Each test must:
1. FAIL when the vulnerability exists (demonstrate exploitability)
2. PASS when the fix is applied (demonstrate remediation)
3. Be self-contained (no external dependencies beyond the target code)
4. Include clear comments explaining what's being tested and why

Output ONLY the pytest code. No explanation outside the code."""


PROMPT = """## Generate Regression Test

### Finding:
Title: {title}
Severity: {severity}
Category: {category}
File: {file_path}:{line}

### Exploit:
{exploit}

### Fix:
{fix}

### Generate a pytest test that:
1. Imports the relevant handler/function
2. Constructs a request that exploits the vulnerability
3. Asserts the VULNERABLE behavior (this test should FAIL after fix)
4. Has a companion test that asserts the SECURE behavior (should PASS after fix)

Format:
```python
import pytest
# ... imports ...

class TestSecurity_{category}:
    \"\"\"Regression tests for: {title}\"\"\"

    def test_vulnerability_exists(self):
        \"\"\"This test PASSES when vulnerable, FAILS when fixed.
        If this test starts failing, the fix was applied correctly.\"\"\"
        ...

    def test_fix_applied(self):
        \"\"\"This test FAILS when vulnerable, PASSES when fixed.
        If this test passes, the vulnerability is remediated.\"\"\"
        ...
```
"""


class RegressionTestGenerator:
    """Generates pytest regression tests from confirmed findings."""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, finding: dict, exploit: str, fix: str, llm_fn=None) -> str:
        """Generate a regression test for one finding."""
        prompt = PROMPT.format(
            title=finding.get("title", ""),
            severity=finding.get("severity", ""),
            category=finding.get("category", "unknown"),
            file_path=finding.get("file_path", ""),
            line=finding.get("line", 0),
            exploit=exploit[:1000],
            fix=fix[:1000],
        )

        if llm_fn:
            test_code = llm_fn(system=SYSTEM, user=prompt)
        else:
            test_code = self._template_test(finding, exploit)

        # Save test file
        safe_name = finding.get("category", "unknown").replace("-", "_").replace(" ", "_")
        test_file = self.output_dir / f"test_security_{safe_name}_{finding.get('id', 'x')[:8]}.py"
        test_file.write_text(test_code)
        logger.info(f"Generated regression test: {test_file}")

        return test_code

    def _template_test(self, finding: dict, exploit: str) -> str:
        """Generate a template test when no LLM available."""
        category = finding.get("category", "unknown").replace("-", "_")
        title = finding.get("title", "Unknown vulnerability")
        file_path = finding.get("file_path", "")

        return f'''"""
Regression test for: {title}
File: {file_path}:{finding.get("line", 0)}
Severity: {finding.get("severity", "")}

This test ensures the vulnerability does not regress.
"""
import pytest
import json


class TestSecurity_{category}:
    """Regression tests for: {title}"""

    def test_vulnerability_description(self):
        """Document the vulnerability for test readers."""
        # Category: {finding.get("category", "")}
        # CWE: {finding.get("cwe", "")}
        # The exploit:
        # {exploit[:200]}
        pass

    @pytest.mark.security
    def test_fix_applied(self):
        """
        This test FAILS when vulnerable, PASSES when fixed.

        TODO: Implement by:
        1. Import the handler function
        2. Construct a malicious request matching the exploit
        3. Assert that the response is 403/401 (fix blocks the attack)
        """
        # TODO: Implement based on exploit pattern
        pytest.skip("Regression test not yet implemented — requires fix verification")
'''

    def generate_all(self, findings: list[dict], exploits: dict,
                     fixes: dict, llm_fn=None) -> list[str]:
        """Generate tests for all confirmed findings."""
        tests = []
        for finding in findings:
            fid = finding.get("id", "")
            exploit = exploits.get(fid, "")
            fix = fixes.get(fid, "")
            test = self.generate(finding, exploit, fix, llm_fn)
            tests.append(test)
        return tests
