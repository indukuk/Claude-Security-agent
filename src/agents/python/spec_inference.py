"""
LLM-driven specification inference.
Identifies project-specific sources, sinks, and sanitizers.
"""
from __future__ import annotations


import json
import logging
from pathlib import Path

from src.common.llm_client import LLMClient
from src.skills.python_taint_skills import SPEC_INFERENCE_PROMPT

logger = logging.getLogger(__name__)


class SpecInference:
    SYSTEM_PROMPT = (
        "You are a security engineer analyzing a Python codebase to identify "
        "taint-flow entry points and sinks. You specialize in identifying "
        "framework-specific and custom sources/sinks that static tools would miss."
    )

    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client

    def infer(self, python_files: list[str]) -> dict:
        """
        Infer project-specific sources, sinks, and sanitizers.
        Returns augmented spec definitions.
        """
        # Extract imports and function signatures
        imports = self._extract_imports(python_files)
        signatures = self._extract_signatures(python_files)

        if not imports and not signatures:
            logger.info("No imports/signatures found, skipping spec inference")
            return {}

        prompt = SPEC_INFERENCE_PROMPT.format(
            imports="\n".join(imports[:50]),
            signatures="\n".join(signatures[:50]),
        )

        try:
            response = self.llm.analyze(
                system_prompt=self.SYSTEM_PROMPT,
                user_prompt=prompt,
                task_type="inference",
            )
            specs = self._parse_response(response)
            validated = self._validate(specs, python_files)

            logger.info(
                f"Spec inference: {len(validated.get('sources', []))} sources, "
                f"{len(validated.get('sinks', []))} sinks, "
                f"{len(validated.get('sanitizers', []))} sanitizers inferred"
            )
            return validated

        except Exception as e:
            logger.warning(f"Spec inference failed: {e}")
            return {}

    def _extract_imports(self, files: list[str]) -> list[str]:
        """Extract import statements from files."""
        imports = set()
        for file_path in files[:30]:  # Limit files scanned
            try:
                content = Path(file_path).read_text(encoding="utf-8")
                for line in content.split("\n"):
                    stripped = line.strip()
                    if stripped.startswith("import ") or stripped.startswith("from "):
                        imports.add(stripped)
            except Exception:
                continue
        return sorted(imports)

    def _extract_signatures(self, files: list[str]) -> list[str]:
        """Extract function signatures from files."""
        signatures = []
        for file_path in files[:30]:
            try:
                content = Path(file_path).read_text(encoding="utf-8")
                for line in content.split("\n"):
                    stripped = line.strip()
                    if stripped.startswith("def ") and "(" in stripped:
                        # Include file context
                        short_path = Path(file_path).name
                        signatures.append(f"{short_path}: {stripped}")
            except Exception:
                continue
        return signatures[:100]

    def _parse_response(self, response: str) -> dict:
        """Parse LLM response (expects JSON)."""
        # Try to extract JSON from response
        try:
            # Find JSON block in response
            start = response.find("{")
            end = response.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(response[start:end])
        except json.JSONDecodeError:
            pass

        # Fallback: return empty
        logger.warning("Could not parse spec inference response as JSON")
        return {}

    def _validate(self, specs: dict, files: list[str]) -> dict:
        """
        Validate inferred specs against actual code using AST parsing.
        Rejects hallucinated specs that reference nonexistent functions/attributes.
        """
        import ast

        # Build a set of all defined functions, classes, and attributes via AST
        defined_names: set[str] = set()
        decorated_functions: set[str] = set()
        class_methods: set[str] = set()  # "ClassName.method" pairs

        for file_path in files[:50]:
            try:
                content = Path(file_path).read_text(encoding="utf-8")
                tree = ast.parse(content)

                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        defined_names.add(node.name)
                        # Track decorated functions (e.g., @tool)
                        for dec in node.decorator_list:
                            if isinstance(dec, ast.Name):
                                decorated_functions.add(f"@{dec.id}:{node.name}")
                            elif isinstance(dec, ast.Attribute):
                                decorated_functions.add(f"@{dec.attr}:{node.name}")
                    elif isinstance(node, ast.ClassDef):
                        defined_names.add(node.name)
                        for item in node.body:
                            if isinstance(item, ast.FunctionDef):
                                class_methods.add(f"{node.name}.{item.name}")
                                defined_names.add(item.name)
                    elif isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                defined_names.add(target.id)
                    elif isinstance(node, ast.ImportFrom):
                        if node.names:
                            for alias in node.names:
                                defined_names.add(alias.asname or alias.name)
            except (SyntaxError, OSError):
                continue

        validated = {"sources": [], "sinks": [], "sanitizers": [], "propagators": []}

        for category in ("sources", "sinks", "sanitizers", "propagators"):
            for spec in specs.get(category, []):
                func = spec.get("function", "")
                if not func:
                    continue

                # Extract the function/attribute name from patterns like "obj.method(" or "func("
                parts = func.rstrip("(").split(".")
                base_name = parts[-1] if parts else func

                # Validate: function must exist as a defined name, class method, or decorated function
                is_valid = (
                    base_name in defined_names or
                    func.rstrip("(") in class_methods or
                    any(func.rstrip("(") in d for d in decorated_functions)
                )

                if is_valid:
                    validated[category].append(spec)
                else:
                    logger.debug(f"Rejected hallucinated spec: {func} (not found in AST)")

        return validated
