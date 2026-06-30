"""Tests for the runtime detector package initializer."""

import ast
from pathlib import Path


def test_runtime_detector_initializer_has_no_runtime_surface() -> None:
    init_file = (
        Path(__file__).parents[5]
        / "pysymex"
        / "_internal"
        / "analysis"
        / "detectors"
        / "runtime"
        / "__init__.py"
    )
    init_tree = ast.parse(init_file.read_text(encoding="utf-8"))
    assert init_tree.body == []
