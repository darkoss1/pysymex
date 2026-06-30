"""Architecture guardrails for scanner ownership boundaries."""

from __future__ import annotations

import ast
from pathlib import Path

_SCANNER_ROOT = Path("pysymex/_internal/scanner")
_ANALYSIS_ROOT = Path("pysymex/_internal/analysis")
_FORBIDDEN_PRESENTATION_IMPORTS = ("pysymex._internal.cli", "pysymex._internal.reporting")


def _import_targets(tree: ast.AST) -> list[str]:
    targets: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            targets.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module is not None:
            targets.append(node.module)
    return targets


def test_scanner_modules_do_not_import_presentation_layers() -> None:
    """Scanner core may produce events, but CLI/reporting own presentation."""
    violations: list[str] = []
    for source_path in sorted(_SCANNER_ROOT.rglob("*.py")):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        for target in _import_targets(tree):
            if any(
                target == forbidden or target.startswith(f"{forbidden}.")
                for forbidden in _FORBIDDEN_PRESENTATION_IMPORTS
            ):
                violations.append(f"{source_path}: {target}")

    assert violations == []


def test_scan_reporter_protocol_is_scanner_owned() -> None:
    """Scanner lifecycle callbacks should not be owned by analysis modules."""
    violations: list[str] = []
    for source_path in sorted(_ANALYSIS_ROOT.rglob("*.py")):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "ScanReporter":
                violations.append(str(source_path))

    assert violations == []
