"""Tests for scanner runtime diagnostics and path-feasibility regressions."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from pysymex._internal.scanner.file import scan_file


def test_scan_file_reports_explicit_assertion_error_diagnostics_without_impossible_path(
    tmp_path: Path,
) -> None:
    """The buggy_file-style diagnostic should report feasible AssertionError bugs only."""
    target = tmp_path / "buggy_file.py"
    target.write_text(
        "def test_01_basic_math(a: int, b: int):\n"
        "    if a > 1000 and b <= 500:\n"
        "        if a - b == 3333:\n"
        "            raise AssertionError('BUG 1 FOUND')\n"
        "\n"
        "def test_02_diamond_flow(x: int, y: int, z: int):\n"
        "    val = 0\n"
        "    if x == 10:\n"
        "        val += 1\n"
        "    if y == 20:\n"
        "        val += 10\n"
        "    if z == 30:\n"
        "        val += 100\n"
        "    if val == 111:\n"
        "        raise AssertionError('BUG 2 FOUND')\n"
        "\n"
        "def test_03_impossible_path(m: int):\n"
        "    if m > 10:\n"
        "        if m < 5:\n"
        "            raise AssertionError('FATAL BUG')\n"
        "    if m == 7:\n"
        "        raise AssertionError('BUG 3 FOUND')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)
    assertion_lines = {
        issue.get("line") for issue in result.issues if issue.get("kind") == "ASSERTION_ERROR"
    }

    assert assertion_lines == {4, 15, 22}


def test_scan_file_deduplicates_runtime_and_range_warning_for_same_site(
    tmp_path: Path,
) -> None:
    """Runtime counterexample should dominate same-site abstract/range warning."""
    target = tmp_path / "duplicate_division.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    if x > -2 and x < 2:\n"
        "        q = x // 2\n"
        "        if q == 0:\n"
        "            return 1 // 0\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)
    matching = [
        issue
        for issue in result.issues
        if issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("line") == 5
    ]

    assert len(matching) == 1
    assert not str(matching[0].get("message", "")).startswith("[Value Range]")


@pytest.mark.slow
def test_scan_file_preserves_trigger_backed_index_error_variant(tmp_path: Path) -> None:
    """Dedup should not replace a model-backed IndexError with a no-trigger variant."""
    target = tmp_path / "fanout_index.py"
    target.write_text(
        "def target(a: int, b: int, c: int, d: int, e: int, f: int, g: int) -> int:\n"
        "    arr = [1, 3, 5]\n"
        "    idx = 0\n"
        "    for v in (a, b, c, d, e, f, g):\n"
        "        if v > 4:\n"
        "            idx += v\n"
        "        else:\n"
        "            idx -= 1\n"
        "    if all(v > 4 for v in (a, b, c, d, e, f, g)):\n"
        "        return arr[idx]\n"
        "    return arr[1]\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=500,
        max_iterations=20000,
        timeout=20,
    )
    matching = [
        issue
        for issue in result.issues
        if issue.get("kind") == "INDEX_ERROR" and issue.get("function_name") == "target"
    ]

    assert len(matching) == 1
    counterexample = matching[0].get("counterexample")
    assert isinstance(counterexample, dict)
    assert counterexample["a"] == 5
    assert counterexample["g"] == 5


def test_scan_file_does_not_merge_fixed_range_loop_into_false_zero_division(
    tmp_path: Path,
) -> None:
    """State merging must preserve fixed-loop history closely enough to avoid false bugs."""
    target = tmp_path / "fixed_range_loop_guard.py"
    target.write_text(
        "def target(z: int) -> int:\n"
        "    total = 0\n"
        "    for _ in range(3):\n"
        "        total += 1\n"
        "    if total == 3 and z == 0:\n"
        "        z = 1\n"
        "    return 1 // z\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 7
        for issue in result.issues
    )


def test_scan_file_keeps_literal_tuple_loop_values_concrete(tmp_path: Path) -> None:
    """Literal tuple loop variables should not become arbitrary zero/string values."""
    target = tmp_path / "literal_tuple_loop.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    total = x\n"
        "    for step in (2, 4, 6):\n"
        "        if total % step == 0:\n"
        "            total += step\n"
        "        else:\n"
        "            total -= step\n"
        "    return 1 // x\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)
    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("line") == 4
        for issue in result.issues
    )
    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("line") == 8
        for issue in result.issues
    )


def test_scan_file_reports_unbound_local_without_follow_on_type_error(tmp_path: Path) -> None:
    """Unbound local diagnostics should not cascade into same-line arithmetic type noise."""
    target = tmp_path / "unbound_local.py"
    target.write_text(
        "def target(flag: bool, seed: int) -> int:\n"
        "    if flag:\n"
        "        total = seed + 1\n"
        "    return total + seed\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)
    line_four = [issue for issue in result.issues if issue.get("line") == 4]

    assert any(issue.get("kind") == "UNBOUND_VARIABLE" for issue in line_four)
    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in line_four)


def test_scan_file_unbound_callee_does_not_continue_into_caller_arithmetic(
    tmp_path: Path,
) -> None:
    target = tmp_path / "unbound_callee_caller_arithmetic.py"
    target.write_text(
        "class Scope:\n"
        "    def __enter__(self) -> 'Scope':\n"
        "        return self\n"
        "    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:\n"
        "        return False\n\n"
        "def late(mode: int) -> int:\n"
        "    if mode == 10:\n"
        "        if mode > 100:\n"
        "            hidden = mode\n"
        "        return hidden\n"
        "    return mode\n\n"
        "def target(mode: int) -> int:\n"
        "    acc = 1\n"
        "    with Scope():\n"
        "        match (mode % 2, True):\n"
        "            case (_, True) if mode == 10:\n"
        "                acc += late(mode)\n"
        "            case _:\n"
        "                acc += late(mode)\n"
        "    return acc\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert any(
        issue.get("kind") == "UNBOUND_VARIABLE"
        and issue.get("function_name") == "late"
        and issue.get("line") == 11
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "UNHANDLED_EXCEPTION"
        and issue.get("function_name") == "target"
        and "UnboundLocalError" in str(issue.get("message"))
        and "hidden" in str(issue.get("message"))
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("line") == 19
        and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_reports_missing_global_name_error(tmp_path: Path) -> None:
    """Undefined globals inside functions are feasible CPython NameError paths."""
    target = tmp_path / "missing_global.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    if x == 0:\n"
        "        return missing_global_name\n"
        "    return x\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "NAME_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 3
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "TYPE_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_treats_any_empty_as_false(tmp_path: Path) -> None:
    """Heap-backed BUILD_LIST results must keep any([]) unreachable."""
    target = tmp_path / "any_empty.py"
    target.write_text(
        "def target(x: int) -> int:\n    if any([]):\n        return 1 // 0\n    return x\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 3
        for issue in result.issues
    )


def test_scan_file_reports_optional_string_none_dereference(tmp_path: Path) -> None:
    """Scanner-created optional strings should preserve the feasible None branch."""
    target = tmp_path / "optional_string_none.py"
    target.write_text(
        "def target(token: str | None) -> str:\n"
        "    if token is None:\n"
        "        return token.strip()\n"
        "    return token.strip()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "NULL_DEREFERENCE"
        and issue.get("function_name") == "target"
        and issue.get("line") == 3
        for issue in result.issues
    )


def test_scan_file_respects_optional_string_none_guard(tmp_path: Path) -> None:
    """Assigning away the None branch should prevent optional-string null reports."""
    target = tmp_path / "optional_string_guard.py"
    target.write_text(
        "def target(token: str | None) -> str:\n"
        "    if token is None:\n"
        "        token = ''\n"
        "    return token.strip()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "NULL_DEREFERENCE" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_reports_invalid_int_literal_value_error(tmp_path: Path) -> None:
    """Concrete invalid int() conversions should survive exact string method models."""
    target = tmp_path / "invalid_int_literal.py"
    target.write_text(
        "def target(seed: int) -> int:\n"
        "    token = ' 12X '\n"
        "    token = token.strip().lower()\n"
        "    if seed > 0:\n"
        "        seed += 1\n"
        "    return int(token)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "VALUE_ERROR" and issue.get("line") == 6 for issue in result.issues
    )


def test_scan_file_does_not_crash_on_symbolic_float_true_division(tmp_path: Path) -> None:
    """Symbolic float division must not cast Z3 expressions to Python booleans."""
    target = tmp_path / "symbolic_float_division.py"
    target.write_text(
        "def target(x: float, flag: bool) -> float:\n"
        "    denom = 0.0 if flag else x\n"
        "    if denom == 0.0:\n"
        "        denom = 2.0\n"
        "    return 1.5 / denom\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert result.error is None
    assert not any(issue.get("kind") == "RUNTIME_ERROR" for issue in result.issues)


def test_scan_file_preserves_internal_execution_failure_as_scan_error(tmp_path: Path) -> None:
    """Unexpected executor failures are incomplete scans, not reported program bugs."""
    target = tmp_path / "executor_failure.py"
    target.write_text("def target(value: int) -> int:\n    return value + 1\n", encoding="utf-8")

    with patch(
        "pysymex._internal.execution.executors.core.SymbolicExecutor.execute_code",
        side_effect=RuntimeError("engine stopped"),
    ):
        result = scan_file(target, use_sandbox=False)

    assert result.error == "Execution Error: target: RuntimeError(engine stopped)"
    assert not any(issue.get("kind") == "RUNTIME_ERROR" for issue in result.issues)


def test_scan_file_reports_modulo_by_zero_kind(tmp_path: Path) -> None:
    """Modulo-by-zero should keep its distinct issue kind."""
    target = tmp_path / "modulo_by_zero.py"
    target.write_text(
        "def target(x: int, step: int) -> int:\n"
        "    if x > 0 and step < 0:\n"
        "        step = 0\n"
        "    return x % step\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "MODULO_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )


def test_scan_file_reports_modulo_by_zero_through_finally_without_division_duplicate(
    tmp_path: Path,
) -> None:
    target = tmp_path / "modulo_by_zero_finally.py"
    target.write_text(
        "def target(x: int, step: int) -> int:\n"
        "    try:\n"
        "        if x > 0 and step < 0:\n"
        "            step = 0\n"
        "        return x % step\n"
        "    finally:\n"
        "        x + 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    modulo_issues = [
        issue
        for issue in result.issues
        if issue.get("kind") == "MODULO_BY_ZERO" and issue.get("function_name") == "target"
    ]
    assert len(modulo_issues) == 1
    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_reports_type_error_raised_before_finally_cleanup(tmp_path: Path) -> None:
    """Modeled exceptions raised before finally cleanup must escape after RERAISE."""
    target = tmp_path / "finally_unary_type_error.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    try:\n"
        "        if x == 4:\n"
        '            return +"text"\n'
        "        return x\n"
        "    finally:\n"
        "        x + 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )


def test_scan_file_dict_get_with_defaults_keeps_concrete_numeric_values(
    tmp_path: Path,
) -> None:
    """dict.get on concrete-backed dicts should not create arbitrary string values."""
    target = tmp_path / "dict_get_defaults.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = {'present': 1}\n"
        "    return data.get('missing', 0) + data.get('present', 1)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 3
        for issue in result.issues
    )


def test_scan_file_symbolic_dict_get_with_int_default_returns_int(
    tmp_path: Path,
) -> None:
    """dict.get on symbolic int dictionaries should not return arbitrary strings."""
    target = tmp_path / "symbolic_dict_get_defaults.py"
    target.write_text(
        "def target(data: dict[str, int]) -> int:\n"
        "    return data.get('missing', 0) + data.get('present', 1)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 2
        for issue in result.issues
    )


def test_scan_file_dict_get_symbolic_int_key_reports_real_default_zero_division(
    tmp_path: Path,
) -> None:
    """dict.get with an integer symbolic key should keep default-zero paths feasible."""
    target = tmp_path / "dict_get_default_division.py"
    target.write_text(
        "def target(y: int) -> int:\n"
        "    mapping = {1: 1}\n"
        "    divisor = mapping.get(y, 0)\n"
        "    return 10 // divisor\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "TYPE_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_dict_get_symbolic_int_key_over_existing_keys_is_nonzero(
    tmp_path: Path,
) -> None:
    """dict.get should not use the default when all symbolic integer-key cases exist."""
    target = tmp_path / "dict_get_existing_guarded.py"
    target.write_text(
        "def target(y: int) -> int:\n"
        "    fallback = 2\n"
        "    mapping = {0: fallback, 1: 1}\n"
        "    key = 0 if y == 0 else 1\n"
        "    divisor = mapping.get(key, 0)\n"
        "    return 10 // divisor\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"DIVISION_BY_ZERO", "TYPE_ERROR"}
        and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_dict_get_symbolic_int_key_over_string_values_is_nonempty(
    tmp_path: Path,
) -> None:
    """dict.get should preserve retained string lengths for finite symbolic keys."""
    target = tmp_path / "dict_get_string_values_nonempty.py"
    target.write_text(
        "def target(y: int) -> int:\n"
        "    mapping = {0: 'a', 1: 'bb'}\n"
        "    item = mapping.get(y % 2, 'ccc')\n"
        "    return 10 // len(item)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not any(
        issue.get("kind") in {"DIVISION_BY_ZERO", "TYPE_ERROR"}
        and issue.get("function_name") == "target"
        for issue in result.issues
    )
    assert result.degraded_passes == []


def test_scan_file_dict_get_symbolic_int_key_reports_string_equality_bug(
    tmp_path: Path,
) -> None:
    """dict.get should keep equality against retained finite string values feasible."""
    target = tmp_path / "dict_get_string_values_equality_bug.py"
    target.write_text(
        "def target(y: int) -> int:\n"
        "    mapping = {0: 'a', 1: 'bb'}\n"
        "    item = mapping.get(y % 2, 'ccc')\n"
        "    if item == 'bb':\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "TYPE_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )
    assert result.degraded_passes == []


def test_scan_file_dict_get_symbolic_int_key_preserves_empty_string_default_bug(
    tmp_path: Path,
) -> None:
    """dict.get should keep string default branches when finite keys may miss."""
    target = tmp_path / "dict_get_empty_string_default_bug.py"
    target.write_text(
        "def target(y: int) -> int:\n"
        "    mapping = {0: 'a', 1: 'bb'}\n"
        "    item = mapping.get(y % 3, '')\n"
        "    return 10 // len(item)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "TYPE_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )
    assert result.degraded_passes == []


def test_scan_file_listcomp_guarded_divisor_has_no_range_zero_warning(
    tmp_path: Path,
) -> None:
    """Value-range analysis should not invent a zero item inside list comprehensions."""
    target = tmp_path / "listcomp_guarded_division.py"
    target.write_text(
        "def target(y: int) -> object:\n"
        "    divisor = y\n"
        "    if divisor == 0:\n"
        "        divisor = 1\n"
        "    values = [10 // item for item in [divisor]]\n"
        "    result = values[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_listcomp_scope_shadow_does_not_leak_outer_zero(
    tmp_path: Path,
) -> None:
    """Inlined comprehension loop variables should not reuse an outer zero binding."""
    target = tmp_path / "listcomp_scope_shadow_guarded.py"
    target.write_text(
        "def target(y: int) -> object:\n"
        "    item = 0\n"
        "    values = [10 // item for item in [1]]\n"
        "    result = values[0] + y\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_symbolic_dict_setdefault_establishes_key(tmp_path: Path) -> None:
    """dict.setdefault mutates the dictionary before a subsequent direct access."""
    target = tmp_path / "symbolic_dict_setdefault.py"
    target.write_text(
        "def target(data: dict[str, int]) -> int:\n"
        "    data.setdefault('count', 0)\n"
        "    return data['count']\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "KEY_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 3
        for issue in result.issues
    )


def test_scan_file_does_not_report_unbounded_range_float_warning(tmp_path: Path) -> None:
    """The range pass should not turn unbounded float uncertainty into a false positive."""
    target = tmp_path / "guarded_float_division.py"
    target.write_text(
        "def target(x: float, flag: bool) -> float:\n"
        "    denom = 0.0 if flag else x\n"
        "    if denom == 0.0:\n"
        "        denom = 2.0\n"
        "    return 1.5 / denom\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )
