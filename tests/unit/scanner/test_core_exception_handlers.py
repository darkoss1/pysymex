"""Scanner regressions for exception-handler execution paths."""

import asyncio
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pysymex
from pysymex.scanner.file import scan_file


def _issue_kind(issue: object) -> object:
    if isinstance(issue, dict):
        issue_map = cast("Mapping[str, object]", issue)
        return issue_map.get("kind")
    raw_kind = getattr(issue, "kind", None)
    return getattr(raw_kind, "name", raw_kind)


def test_modeled_method_call_in_handler_does_not_corrupt_cleanup_stack(tmp_path: Path) -> None:
    """A resolved list method cannot branch as a synthetic non-callable value."""
    target = tmp_path / "handler_method_call.py"
    target.write_text(
        "def target(values: list) -> int:\n"
        "    errors = []\n"
        "    for value in values:\n"
        "        try:\n"
        "            10 // value\n"
        "        except ZeroDivisionError as exc:\n"
        "            errors.append(exc)\n"
        "    return len(errors)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_vm_state" not in result.degraded_passes
    assert not any(
        issue.get("kind") == "UNKNOWN"
        and isinstance(message := issue.get("message"), str)
        and "COPY" in message
        for issue in result.issues
    )


def test_scan_file_reports_bare_reraise_of_caught_zero_division(tmp_path: Path) -> None:
    target = tmp_path / "bare_reraise.py"
    target.write_text(
        "def target(value: int) -> None:\n"
        "    try:\n"
        "        1 // value\n"
        "    except ZeroDivisionError:\n"
        "        raise\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "UNHANDLED_EXCEPTION"
        and "ZeroDivisionError" in str(issue.get("message"))
        and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_analyze_code_caught_zero_division_does_not_report_builtin_exception_name() -> None:
    result = asyncio.run(
        pysymex.analyze_code(
            "try:\n    result = 10 // y\nexcept ZeroDivisionError:\n    result = x + 1\n",
            symbolic_vars={"x": "int", "y": "int"},
            max_paths=30,
            max_depth=60,
            max_iterations=1500,
            timeout=1.0,
        )
    )

    assert not any(
        _issue_kind(issue)
        in {"DIVISION_BY_ZERO", "UNHANDLED_EXCEPTION", "NAME_ERROR", "UNBOUND_VARIABLE"}
        for issue in result.issues
    )


def test_analyze_code_caught_runtime_error_constructor_is_handled() -> None:
    result = asyncio.run(
        pysymex.analyze_code(
            "try:\n"
            "    if flag:\n"
            "        raise RuntimeError('caught fuzz raise')\n"
            "    result = 1\n"
            "except RuntimeError:\n"
            "    result = 0\n",
            symbolic_vars={"flag": "bool"},
            max_paths=30,
            max_depth=60,
            max_iterations=1500,
            timeout=1.0,
        )
    )

    assert "unmodeled_call_abstraction" not in result.degraded_passes
    assert not any(
        _issue_kind(issue) in {"UNHANDLED_EXCEPTION", "NAME_ERROR", "UNBOUND_VARIABLE"}
        for issue in result.issues
    )


def test_analyze_code_uncaught_runtime_error_constructor_is_reported() -> None:
    result = asyncio.run(
        pysymex.analyze_code(
            "if flag:\n    raise RuntimeError('uncaught branch raise')\nresult = 1\n",
            symbolic_vars={"flag": "bool"},
            max_paths=30,
            max_depth=60,
            max_iterations=1500,
            timeout=1.0,
        )
    )

    assert "unmodeled_call_abstraction" not in result.degraded_passes
    assert any(_issue_kind(issue) == "UNHANDLED_EXCEPTION" for issue in result.issues)


def test_analyze_code_key_error_class_is_caught_by_lookup_error() -> None:
    result = asyncio.run(
        pysymex.analyze_code(
            "try:\n    raise KeyError\nexcept LookupError:\n    result = 5\n",
            max_paths=35,
            max_depth=100,
            max_iterations=2000,
            timeout=2.0,
        )
    )

    assert not any(
        _issue_kind(issue) in {"UNHANDLED_EXCEPTION", "UNBOUND_VARIABLE", "NAME_ERROR"}
        for issue in result.issues
    )


def test_scan_file_key_error_class_is_caught_by_lookup_error(tmp_path: Path) -> None:
    target = tmp_path / "subclass_exception_handler.py"
    target.write_text(
        "def target() -> int:\n"
        "    try:\n"
        "        raise KeyError\n"
        "    except LookupError:\n"
        "        result = 5\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"UNHANDLED_EXCEPTION", "UNBOUND_VARIABLE", "NAME_ERROR"}
        for issue in result.issues
    )


def test_scan_file_local_custom_exception_class_is_caught(tmp_path: Path) -> None:
    target = tmp_path / "local_custom_exception_caught.py"
    target.write_text(
        "def target() -> int:\n"
        "    class MyError(Exception):\n"
        "        pass\n"
        "\n"
        "    try:\n"
        "        raise MyError\n"
        "    except MyError:\n"
        "        result = 4\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "UNHANDLED_EXCEPTION" for issue in result.issues)
    assert result.degraded_passes == []


def test_scan_file_mismatched_local_custom_exception_is_reported(tmp_path: Path) -> None:
    target = tmp_path / "local_custom_exception_mismatch.py"
    target.write_text(
        "def target() -> int:\n"
        "    class MyError(Exception):\n"
        "        pass\n"
        "\n"
        "    class OtherError(Exception):\n"
        "        pass\n"
        "\n"
        "    try:\n"
        "        raise OtherError\n"
        "    except MyError:\n"
        "        result = 4\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "UNHANDLED_EXCEPTION" and "OtherError" in str(issue.get("message", ""))
        for issue in result.issues
    )
