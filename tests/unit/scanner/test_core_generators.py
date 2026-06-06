"""Scanner regressions for bounded resumable generator execution."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def test_scan_file_reports_type_error_for_send_before_first_yield(tmp_path: Path) -> None:
    target = tmp_path / "unstarted_generator.py"
    target.write_text(
        "def yield_once():\n"
        "    yield 1\n"
        "\n"
        "def target_send():\n"
        "    iterator = yield_once()\n"
        "    return iterator.send(1)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "TYPE_ERROR" and "just-started generator" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_resumes_generator_through_successive_next_calls(tmp_path: Path) -> None:
    target = tmp_path / "successive_next.py"
    target.write_text(
        "def target():\n"
        "    def values():\n"
        "        yield 0\n"
        "        yield 1\n"
        "    iterator = values()\n"
        "    next(iterator)\n"
        "    value = next(iterator)\n"
        "    return 1 // (value - 1)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_generator" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_iterates_modeled_generator_for_loop_precisely(tmp_path: Path) -> None:
    target = tmp_path / "generator_for_loop.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    def values():\n"
        "        yield x + 1\n"
        "        yield x - 1\n"
        "    total = 0\n"
        "    for item in values():\n"
        "        total += item\n"
        "    return 10 // (total - (2 * x))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_generator" not in result.degraded_passes
    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_resumes_generator_send_after_priming(tmp_path: Path) -> None:
    target = tmp_path / "generator_send.py"
    target.write_text(
        "def target():\n"
        "    def accumulator():\n"
        "        value = yield 0\n"
        "        yield value\n"
        "    iterator = accumulator()\n"
        "    next(iterator)\n"
        "    value = iterator.send(10)\n"
        "    return 1 // (value - 10)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_generator" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_empty_generator_next_default_produces_none_index_type_error(tmp_path: Path) -> None:
    target = tmp_path / "empty_generator_default.py"
    target.write_text(
        "def target():\n"
        "    def empty():\n"
        "        items = []\n"
        "        for item in items:\n"
        "            yield item\n"
        "    value = next(empty(), None)\n"
        "    return [1, 2, 3][value]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "INDEX_ERROR" for issue in result.issues)
    assert any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)


def test_generator_pep479_conversion_does_not_emit_unreachable_finding(tmp_path: Path) -> None:
    target = tmp_path / "generator_pep479.py"
    target.write_text(
        "def target():\n"
        "    def bad_gen():\n"
        "        raise StopIteration('internal')\n"
        "        yield 1\n"
        "    try:\n"
        "        next(bad_gen())\n"
        "    except RuntimeError:\n"
        "        pass\n"
        "    except StopIteration:\n"
        "        return 1 // 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_generator" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_respects_all_generator_nonzero_guard(tmp_path: Path) -> None:
    target = tmp_path / "all_generator_guard.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x, x + 1]\n"
        "    if all(value != 0 for value in values):\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_generator" not in result.degraded_passes
    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )


def test_scan_file_reports_any_generator_zero_guarded_division(tmp_path: Path) -> None:
    target = tmp_path / "any_generator_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    if any(value == 0 for value in values):\n"
        "        return 10 // x\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_generator" not in result.degraded_passes
    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )


def test_scan_file_respects_all_generator_positive_guard(tmp_path: Path) -> None:
    target = tmp_path / "all_generator_positive_guard.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x, x + 1]\n"
        "    if all(value > 0 for value in values):\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_generator" not in result.degraded_passes
    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )


def test_scan_file_reports_any_generator_nonpositive_guarded_division(
    tmp_path: Path,
) -> None:
    target = tmp_path / "any_generator_nonpositive_bug.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    if any(value <= 0 for value in values):\n"
        "        return 10 // x\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_generator" not in result.degraded_passes
    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )


def test_scan_file_respects_all_generator_direct_truth_guard(tmp_path: Path) -> None:
    target = tmp_path / "all_generator_direct_truth_guard.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    if all(value for value in values):\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_generator" not in result.degraded_passes
    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )


def test_scan_file_respects_any_generator_direct_truth_guard(tmp_path: Path) -> None:
    target = tmp_path / "any_generator_direct_truth_guard.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    values = [x]\n"
        "    if any(value for value in values):\n"
        "        return 10 // x\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_generator" not in result.degraded_passes
    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 4
        for issue in result.issues
    )


def test_scan_file_routes_any_generator_predicate_exception_to_handler(
    tmp_path: Path,
) -> None:
    target = tmp_path / "any_generator_predicate_exception.py"
    target.write_text(
        "def _gate(value: int, flag: int) -> bool:\n"
        "    if flag == 1 and value == 0:\n"
        "        raise LookupError('masked zero')\n"
        "    return value == 0\n"
        "\n"
        "def target(a: int, b: int, c: int) -> int:\n"
        "    values = [a - b, b - c]\n"
        "    denominator = 1\n"
        "    try:\n"
        "        if any(_gate(item, c) for item in values):\n"
        "            denominator = 1\n"
        "    except LookupError:\n"
        "        denominator = values[0]\n"
        "    if a == b and c == 1:\n"
        "        return 150 // denominator\n"
        "    return denominator + values[1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_generator" not in result.degraded_passes
    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )
    assert not any(issue.get("kind") == "UNHANDLED_EXCEPTION" for issue in result.issues)


def test_scan_file_keeps_safe_any_generator_predicate_exception_handler(
    tmp_path: Path,
) -> None:
    target = tmp_path / "any_generator_predicate_exception_safe.py"
    target.write_text(
        "def _gate(value: int, flag: int) -> bool:\n"
        "    if flag == 1 and value == 0:\n"
        "        raise LookupError('masked zero')\n"
        "    return value == 0\n"
        "\n"
        "def target(a: int, b: int, c: int) -> int:\n"
        "    values = [a - b, b - c]\n"
        "    denominator = 1\n"
        "    try:\n"
        "        if any(_gate(item, c) for item in values):\n"
        "            denominator = 1\n"
        "    except LookupError:\n"
        "        denominator = values[0] + 1\n"
        "    if a == b and c == 1 and denominator == 0:\n"
        "        return 150 // denominator\n"
        "    if denominator != 0:\n"
        "        return 150 // denominator\n"
        "    return values[1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_generator" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(issue.get("kind") == "UNHANDLED_EXCEPTION" for issue in result.issues)
