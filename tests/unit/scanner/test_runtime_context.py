"""Tests for scanner runtime-context isolation."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

from pysymex._internal.analysis.scan.loading.package.context import scoped_package_import_path
from pysymex._internal.scanner.file import scan_file


def _package_target(tmp_path: Path) -> Path:
    package = tmp_path / "sample_package"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    target = package / "target.py"
    target.write_text("def target() -> int:\n    return 1\n", encoding="utf-8")
    return target


def test_scoped_package_import_path_is_restored_after_context_exit(tmp_path: Path) -> None:
    """A target package root is available during scanning only."""
    target = _package_target(tmp_path)
    root_text = str(tmp_path)
    assert root_text not in sys.path

    with scoped_package_import_path(target):
        assert sys.path[0] == root_text

    assert root_text not in sys.path


def test_scan_file_restores_package_import_path_after_analysis_failure(tmp_path: Path) -> None:
    """Scanner analysis failures must not leak target package roots into the host."""
    target = _package_target(tmp_path)
    root_text = str(tmp_path)

    with patch(
        "pysymex._internal.scanner.file.build_module_globals", side_effect=RuntimeError("stop")
    ):
        result = scan_file(target, use_sandbox=False)

    assert result.error == "Analysis Error: stop"
    assert root_text not in sys.path
