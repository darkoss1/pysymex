"""Tests for module/exec namespace behavior visible to nested functions."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import cast

import pysymex


def _issue_kind(issue: object) -> object:
    if isinstance(issue, dict):
        issue_map = cast("Mapping[str, object]", issue)
        return issue_map.get("kind")
    raw_kind = getattr(issue, "kind", None)
    return getattr(raw_kind, "name", raw_kind)


def _assert_no_issue_kinds(result: object, forbidden: set[str]) -> None:
    issues = getattr(result, "issues", [])
    assert not any(_issue_kind(issue) in forbidden for issue in issues)


def test_analyze_code_module_lambda_sees_late_bound_root_name() -> None:
    result = asyncio.run(
        pysymex.analyze_code(
            "funcs = []\n"
            "for value in [1, 2]:\n"
            "    funcs.append(lambda: value)\n"
            "result = funcs[0]()\n",
            max_paths=35,
            max_depth=100,
            max_iterations=2000,
            timeout=2.0,
        )
    )

    _assert_no_issue_kinds(
        result,
        {"NAME_ERROR", "TYPE_ERROR", "ATTRIBUTE_ERROR", "UNBOUND_VARIABLE"},
    )


def test_analyze_code_still_reports_real_missing_global_in_nested_function() -> None:
    result = asyncio.run(
        pysymex.analyze_code(
            "def read_missing():\n    return missing_global_name\nresult = read_missing()\n",
            max_paths=20,
            max_depth=80,
            max_iterations=1000,
            timeout=2.0,
        )
    )

    assert any(_issue_kind(issue) == "NAME_ERROR" for issue in result.issues)


def test_analyze_code_module_symbolic_var_visible_to_property_getter() -> None:
    result = asyncio.run(
        pysymex.analyze_code(
            "class Box:\n"
            "    @property\n"
            "    def value(self) -> int:\n"
            "        return 10 // y\n"
            "\n"
            "box = Box()\n"
            "result = box.value\n",
            symbolic_vars={"y": "int"},
            max_paths=30,
            max_depth=80,
            max_iterations=1500,
            timeout=2.0,
        )
    )

    assert any(_issue_kind(issue) == "DIVISION_BY_ZERO" for issue in result.issues)
    _assert_no_issue_kinds(result, {"NAME_ERROR", "TYPE_ERROR", "ATTRIBUTE_ERROR"})


def test_analyze_code_module_symbolic_var_visible_to_method_body() -> None:
    result = asyncio.run(
        pysymex.analyze_code(
            "class Box:\n"
            "    def value(self) -> int:\n"
            "        return 10 // y\n"
            "\n"
            "box = Box()\n"
            "result = box.value()\n",
            symbolic_vars={"y": "int"},
            max_paths=30,
            max_depth=80,
            max_iterations=1500,
            timeout=2.0,
        )
    )

    assert any(_issue_kind(issue) == "DIVISION_BY_ZERO" for issue in result.issues)
    _assert_no_issue_kinds(result, {"NAME_ERROR", "TYPE_ERROR", "ATTRIBUTE_ERROR"})
