"""Runtime behavior tests for the public API facade."""

from __future__ import annotations

import json
import sys

import pytest

import pysymex.api as mod


_resume_unsupported = pytest.mark.xfail(
    sys.version_info < (3, 13),
    reason="RESUME opcode behavior differs on Python 3.11/3.12",
    strict=False,
)


@_resume_unsupported
@pytest.mark.asyncio
async def test_analyze_simple_function() -> None:
    """analyze() runs symbolic execution on a trivial function."""

    def safe_func(x: int) -> int:
        return x + 1

    result = await mod.analyze(safe_func, {"x": "int"}, max_paths=10, max_iterations=100)
    assert hasattr(result, "issues")


@_resume_unsupported
@pytest.mark.asyncio
async def test_analyze_detects_division_by_zero() -> None:
    """analyze() detects division by zero in a simple function."""

    def div_func(x: int, y: int) -> int:
        return x // y

    result = await mod.analyze(
        div_func,
        {"x": "int", "y": "int"},
        max_paths=50,
        max_iterations=500,
        detect_division_by_zero=True,
    )
    div_issues = [
        i for i in result.issues if "division" in i.format().lower() or "zero" in i.format().lower()
    ]
    assert len(div_issues) >= 1


@_resume_unsupported
@pytest.mark.asyncio
async def test_analyze_code_runs() -> None:
    """analyze_code() compiles and executes code."""
    result = await mod.analyze_code("x = 1 + 2")
    assert hasattr(result, "issues")


@_resume_unsupported
def test_quick_check_returns_list() -> None:
    """quick_check() returns a list of issues."""

    def safe(x: int) -> int:
        return x + 1

    issues = mod.quick_check(safe)
    assert isinstance(issues, list)


@_resume_unsupported
def test_check_division_by_zero() -> None:
    """check_division_by_zero returns division issues."""

    def div(x: int, y: int) -> float:
        return x / y

    issues = mod.check_division_by_zero(div)
    assert isinstance(issues, list)
    assert len(issues) >= 1


@_resume_unsupported
def test_check_assertions() -> None:
    """check_assertions returns assertion issues."""

    def asserting(x: int) -> None:
        assert x > 0

    issues = mod.check_assertions(asserting)
    assert isinstance(issues, list)


@_resume_unsupported
def test_check_index_errors() -> None:
    """check_index_errors returns index issues."""

    def indexing(x: int) -> int:
        lst = [1, 2, 3]
        return lst[x]

    issues = mod.check_index_errors(indexing)
    assert isinstance(issues, list)


@_resume_unsupported
def test_format_issues_text() -> None:
    """format_issues produces text output."""

    def div(x: int, y: int) -> float:
        return x / y

    issues = mod.check_division_by_zero(div)
    if issues:
        text = mod.format_issues(issues, "text")
        assert isinstance(text, str)
        assert len(text) > 0


@_resume_unsupported
def test_format_issues_json() -> None:
    """format_issues produces JSON output."""

    def div(x: int, y: int) -> float:
        return x / y

    issues = mod.check_division_by_zero(div)
    if issues:
        text = mod.format_issues(issues, "json")
        parsed = json.loads(text)
        assert isinstance(parsed, list)
