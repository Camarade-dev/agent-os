"""Repository boundary: Admissible and benchmark must not import agent_os.

Uses AST for import detection (avoids false positives from comments/docstrings
that mention agent_os for documentation). Also verifies that importing
Admissible modules does not load agent_os into sys.modules.
"""

from __future__ import annotations

import ast
import importlib
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

_BOUNDARY_ROOTS: tuple[tuple[Path, str], ...] = (
    (REPO_ROOT / "admissible", "admissible"),
    (REPO_ROOT / "benchmark", "benchmark"),
)


def _python_files_under(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py") if p.is_file())


def _agent_os_imports_in_source(path: Path) -> list[tuple[int, str]]:
    """Return (lineno, description) for each AST import of agent_os."""
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                if name == "agent_os" or name.startswith("agent_os."):
                    hits.append((node.lineno, f"import {name}"))
        elif isinstance(node, ast.ImportFrom):
            module = node.module
            if module and (module == "agent_os" or module.startswith("agent_os.")):
                hits.append((node.lineno, f"from {module} import ..."))
    return hits


def _module_name_for_path(path: Path) -> str:
    rel = path.relative_to(REPO_ROOT)
    if path.name == "__init__.py":
        parts = rel.parent.parts
    else:
        parts = rel.with_suffix("").parts
    return ".".join(parts)


def _discover_boundary_modules() -> list[str]:
    modules: list[str] = []
    for root, _label in _BOUNDARY_ROOTS:
        for path in _python_files_under(root):
            modules.append(_module_name_for_path(path))
    return sorted(set(modules))


class TestAdmissibleAgentOsImportBoundary(unittest.TestCase):
    def test_no_agent_os_imports_in_admissible_or_benchmark_sources(self) -> None:
        violations: list[str] = []
        for root, label in _BOUNDARY_ROOTS:
            self.assertTrue(root.is_dir(), f"missing boundary root: {root}")
            for path in _python_files_under(root):
                for lineno, desc in _agent_os_imports_in_source(path):
                    rel = path.relative_to(REPO_ROOT)
                    violations.append(f"{label}: {rel}:{lineno} {desc}")
        self.assertEqual(
            violations,
            [],
            "Admissible/benchmark must not import agent_os:\n" + "\n".join(violations),
        )

    def test_importing_boundary_modules_does_not_load_agent_os(self) -> None:
        before = {name for name in sys.modules if name == "agent_os" or name.startswith("agent_os.")}
        for module_name in _discover_boundary_modules():
            with self.subTest(module=module_name):
                importlib.import_module(module_name)
        after = {name for name in sys.modules if name == "agent_os" or name.startswith("agent_os.")}
        self.assertEqual(after - before, set(), f"unexpected agent_os modules loaded: {after - before}")


if __name__ == "__main__":
    unittest.main()
