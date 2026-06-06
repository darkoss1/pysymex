"""Scanner regressions for concrete user-defined context-manager suppression."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pysymex
from pysymex.analysis.domains.exceptions.analyzer.context_managers import (
    known_with_manager_suppresses,
)
from pysymex.core.memory.cow.collections import CowDict
from pysymex.scanner.file import scan_file
from pysymex.analysis.scan.loading import build_module_globals
from pysymex.analysis.static.code_objects import get_code_objects_with_context


def _issue_kind(issue: object) -> object:
    if isinstance(issue, dict):
        issue_map = cast("Mapping[str, object]", issue)
        return issue_map.get("kind")
    raw_kind = getattr(issue, "kind", None)
    return getattr(raw_kind, "name", raw_kind)


def test_scan_file_allows_matching_user_context_manager_suppression(tmp_path: Path) -> None:
    target = tmp_path / "context_manager_suppresses_division.py"
    target.write_text(
        "class SuppressZeroDivision:\n"
        "    def __enter__(self) -> 'SuppressZeroDivision':\n"
        "        return self\n"
        "    def __exit__(self, exc_type: type[BaseException] | None, exc: object,\n"
        "                 tb: object) -> bool:\n"
        "        _ = exc, tb\n"
        "        return exc_type is ZeroDivisionError\n"
        "\n"
        "def target(denominator: int) -> int:\n"
        "    with SuppressZeroDivision():\n"
        "        return 10 // denominator\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_analyze_code_allows_module_plain_context_manager_suppression() -> None:
    result = asyncio.run(
        pysymex.analyze_code(
            "class SuppressZero:\n"
            "    def __enter__(self):\n"
            "        return self\n"
            "\n"
            "    def __exit__(self, exc_type, exc, tb):\n"
            "        return exc_type is ZeroDivisionError\n"
            "\n"
            "with SuppressZero():\n"
            "    1 / 0\n"
            "result = 5\n",
            max_paths=45,
            max_depth=130,
            max_iterations=3000,
            timeout=2.0,
        )
    )

    assert not any(
        _issue_kind(issue) in {"DIVISION_BY_ZERO", "UNHANDLED_EXCEPTION"} for issue in result.issues
    )


def test_scan_file_allows_local_plain_context_manager_suppression(tmp_path: Path) -> None:
    target = tmp_path / "local_context_manager_suppresses_division.py"
    target.write_text(
        "def target() -> int:\n"
        "    class SuppressZero:\n"
        "        def __enter__(self):\n"
        "            return self\n"
        "\n"
        "        def __exit__(self, exc_type, exc, tb):\n"
        "            return exc_type is ZeroDivisionError\n"
        "\n"
        "    with SuppressZero():\n"
        "        1 / 0\n"
        "    result = 5\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"DIVISION_BY_ZERO", "UNHANDLED_EXCEPTION"}
        and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_reports_user_context_manager_that_propagates_division(tmp_path: Path) -> None:
    target = tmp_path / "context_manager_propagates_division.py"
    target.write_text(
        "class PropagateZeroDivision:\n"
        "    def __enter__(self) -> 'PropagateZeroDivision':\n"
        "        return self\n"
        "    def __exit__(self, exc_type: type[BaseException] | None, exc: object,\n"
        "                 tb: object) -> bool:\n"
        "        _ = exc_type, exc, tb\n"
        "        return False\n"
        "\n"
        "def target(denominator: int) -> int:\n"
        "    with PropagateZeroDivision():\n"
        "        return 10 // denominator\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 11
        for issue in result.issues
    )


def test_scan_file_reports_user_context_manager_matching_another_exception(tmp_path: Path) -> None:
    target = tmp_path / "context_manager_matches_value_error.py"
    target.write_text(
        "class SuppressValueError:\n"
        "    def __enter__(self) -> 'SuppressValueError':\n"
        "        return self\n"
        "    def __exit__(self, exc_type: type[BaseException] | None, exc: object,\n"
        "                 tb: object) -> bool:\n"
        "        _ = exc, tb\n"
        "        return exc_type is ValueError\n"
        "\n"
        "def target(denominator: int) -> int:\n"
        "    with SuppressValueError():\n"
        "        return 10 // denominator\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 11
        for issue in result.issues
    )


def test_scan_file_does_not_trust_decorated_exit_method_body(tmp_path: Path) -> None:
    target = tmp_path / "context_manager_decorated_exit.py"
    target.write_text(
        "def propagate(method: object) -> object:\n"
        "    def wrapper(*args: object) -> bool:\n"
        "        return False\n"
        "    return wrapper\n"
        "\n"
        "class DecoratedExit:\n"
        "    def __enter__(self) -> 'DecoratedExit':\n"
        "        return self\n"
        "    @propagate\n"
        "    def __exit__(self, exc_type: type[BaseException] | None, exc: object,\n"
        "                 tb: object) -> bool:\n"
        "        return exc_type is ZeroDivisionError\n"
        "\n"
        "def target(denominator: int) -> int:\n"
        "    with DecoratedExit():\n"
        "        return 10 // denominator\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 16
        for issue in result.issues
    )


def test_inherited_manager_construction_is_not_certified_for_suppression() -> None:
    content = (
        "class Propagate:\n"
        "    def __enter__(self) -> 'Propagate':\n"
        "        return self\n"
        "    def __exit__(self, *args: object) -> bool:\n"
        "        return False\n"
        "\n"
        "class ReplaceOnConstruction:\n"
        "    def __new__(cls) -> Propagate:\n"
        "        return Propagate()\n"
        "\n"
        "class ClaimedSuppress(ReplaceOnConstruction):\n"
        "    def __enter__(self) -> 'ClaimedSuppress':\n"
        "        return self\n"
        "    def __exit__(self, exc_type: type[BaseException] | None, exc: object,\n"
        "                 tb: object) -> bool:\n"
        "        return exc_type is ZeroDivisionError\n"
        "\n"
        "def target(denominator: int) -> int:\n"
        "    with ClaimedSuppress():\n"
        "        return 10 // denominator\n"
        "    return 0\n"
    )
    target = Path("context_manager_inherited_construction.py")
    code = compile(content, str(target), "exec")
    module_globals = build_module_globals(
        content=content,
        file_path=target,
        full_module_name="context_manager_inherited_construction",
        package_name="",
        all_code_with_context=get_code_objects_with_context(code),
    )

    assert not known_with_manager_suppresses(
        CowDict(module_globals), "ZeroDivisionError", "ClaimedSuppress", ()
    )
