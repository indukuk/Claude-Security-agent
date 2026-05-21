"""
File tools — available to all agents for code reading and searching.
"""
from __future__ import annotations

import os
import re
from pathlib import Path


def read_file(file_path: str, start_line: int = 0, end_line: int = 0) -> str:
    """Read a file or a range of lines."""
    try:
        content = Path(file_path).read_text(encoding="utf-8")
        if start_line or end_line:
            lines = content.split("\n")
            start = max(0, start_line - 1)
            end = end_line or len(lines)
            numbered = [f"{i+1:4d}| {lines[i]}" for i in range(start, min(end, len(lines)))]
            return "\n".join(numbered)
        return content
    except Exception as e:
        return f"Error reading {file_path}: {e}"


def grep_pattern(pattern: str, directory: str, file_ext: str = ".py") -> list[dict]:
    """Search for a pattern across files."""
    results = []
    try:
        regex = re.compile(pattern)
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in ("__pycache__", "node_modules", "cdk.out", ".venv")]
            for fname in files:
                if fname.endswith(file_ext):
                    fpath = os.path.join(root, fname)
                    try:
                        for i, line in enumerate(Path(fpath).read_text().split("\n"), 1):
                            if regex.search(line):
                                results.append({
                                    "file": fpath,
                                    "line": i,
                                    "content": line.strip()[:200],
                                })
                    except Exception:
                        continue
    except Exception as e:
        return [{"error": str(e)}]
    return results


def list_files(directory: str, ext: str = ".py") -> list[str]:
    """List all files with given extension."""
    files = []
    for root, dirs, fnames in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in ("__pycache__", "node_modules", "cdk.out", ".venv")]
        for fname in fnames:
            if fname.endswith(ext):
                files.append(os.path.join(root, fname))
    return sorted(files)


def read_function(file_path: str, function_name: str) -> str:
    """Read a specific function from a file."""
    try:
        content = Path(file_path).read_text()
        lines = content.split("\n")

        # Find function start
        func_start = None
        for i, line in enumerate(lines):
            if re.match(rf'\s*def {function_name}\s*\(', line):
                func_start = i
                break

        if func_start is None:
            return f"Function '{function_name}' not found in {file_path}"

        # Find function end
        indent = len(lines[func_start]) - len(lines[func_start].lstrip())
        func_end = func_start + 1
        while func_end < len(lines):
            line = lines[func_end]
            if line.strip() and not line.strip().startswith("#"):
                current_indent = len(line) - len(line.lstrip())
                if current_indent <= indent and line.strip().startswith("def "):
                    break
            func_end += 1

        numbered = [f"{i+1:4d}| {lines[i]}" for i in range(func_start, min(func_end, func_start + 80))]
        return "\n".join(numbered)
    except Exception as e:
        return f"Error: {e}"
