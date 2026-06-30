"""Scanner regressions for PEP 695 generic class bytecode."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from pysymex._internal.scanner.file import scan_file


@pytest.mark.skipif(sys.version_info < (3, 12), reason="PEP 695 syntax requires Python 3.12+")
def test_pep695_generic_class_alias_remains_callable(tmp_path: Path) -> None:
    target = tmp_path / "pep695_generic_alias.py"
    target.write_text(
        "class Box[T]:\n"
        "    def __init__(self, x: int) -> None:\n"
        "        self.x = x\n"
        "\n"
        "\n"
        "def identity[T](value: T) -> T:\n"
        "    return value\n"
        "\n"
        "\n"
        "def target(x: int) -> int:\n"
        "    box = Box[int](identity(x))\n"
        "    return 1 // (box.x - x)\n"
        "\n"
        "\n"
        "def alias_metadata() -> bool:\n"
        "    alias = Box[int]\n"
        "    return alias.__origin__ is Box and len(alias.__args__) == 1\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        trace_enabled=False,
        no_cache=True,
        max_paths=120,
        max_depth=2500,
        max_iterations=15000,
        timeout=20,
    )

    assert result.error is None
    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )
    assert "unsupported_subscript_abstraction" not in result.degraded_passes
    assert "unmodeled_call_abstraction" not in result.degraded_passes
    assert "unmodeled_attribute_havoc" not in result.degraded_passes
    assert not any(issue.get("function_name") == "alias_metadata" for issue in result.issues)
