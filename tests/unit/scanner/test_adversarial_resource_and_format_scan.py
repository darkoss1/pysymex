"""Scanner regressions for specialized resource and format detectors."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def _scan_source(tmp_path: Path, filename: str, source: str):
    target = tmp_path / filename
    target.write_text(source, encoding="utf-8")
    return scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=200,
        timeout=8,
        max_iterations=10000,
    )


RESOURCE_LEAK_TARGET = """
from builtins import open as open_resource


def target(mode: int, a: int, b: int, c: int, d: int) -> int:
    handle = open_resource("virtual", "w")
    if a > 0:
        if b > 0:
            handle.close()
            return 2
        if mode == 0 and c > d:
            return 1
    handle.close()
    return 3
"""


RESOURCE_LEAK_SAFE_CONTROL = """
from builtins import open as open_resource


def target(mode: int, a: int, b: int, c: int, d: int) -> int:
    handle = open_resource("virtual", "w")
    if a > 0:
        if b > 0:
            handle.close()
            return 2
        if mode == 0 and c > d:
            handle.close()
            return 1
    handle.close()
    return 3
"""


def test_scan_file_reports_branch_hidden_resource_leak(tmp_path: Path) -> None:
    result = _scan_source(tmp_path, "branch_hidden_resource_leak.py", RESOURCE_LEAK_TARGET)

    assert result.error is None
    assert result.degraded_passes == ["builtin_open_semantics_unknown"]
    assert any(issue.get("kind") == "RESOURCE_LEAK" for issue in result.issues)
    assert result.paths_explored <= 20


def test_scan_file_resource_leak_safe_control_stays_clean(tmp_path: Path) -> None:
    result = _scan_source(
        tmp_path, "branch_hidden_resource_leak_control.py", RESOURCE_LEAK_SAFE_CONTROL
    )

    assert result.error is None
    assert result.degraded_passes == ["builtin_open_semantics_unknown"]
    assert not result.issues
    assert result.paths_explored <= 20


def test_scan_file_reports_havoc_backed_format_argument(tmp_path: Path) -> None:
    result = _scan_source(
        tmp_path,
        "havoc_backed_format_argument.py",
        """
def target(callback: object) -> str:
    return f"{callback()}"
""",
    )

    assert result.error is None
    assert "unmodeled_call_abstraction" in result.degraded_passes
    assert any(issue.get("kind") == "INVALID_ARGUMENT" for issue in result.issues)
    assert result.paths_explored <= 10


def test_scan_file_concrete_format_control_stays_clean(tmp_path: Path) -> None:
    result = _scan_source(
        tmp_path,
        "concrete_format_control.py",
        """
def target(value: int) -> str:
    return f"{value + 1}"
""",
    )

    assert result.error is None
    assert not result.degraded_passes
    assert not result.issues
    assert result.paths_explored <= 10


def test_scan_file_reports_havoc_backed_format_spec_value(tmp_path: Path) -> None:
    result = _scan_source(
        tmp_path,
        "havoc_backed_format_spec_value.py",
        """
def target(callback: object) -> str:
    return f"{callback():>10}"
""",
    )

    assert result.error is None
    assert "unmodeled_call_abstraction" in result.degraded_passes
    assert any(issue.get("kind") == "INVALID_ARGUMENT" for issue in result.issues)
    assert result.paths_explored <= 10


def test_scan_file_concrete_format_spec_control_stays_clean(tmp_path: Path) -> None:
    result = _scan_source(
        tmp_path,
        "concrete_format_spec_control.py",
        """
def target(value: int) -> str:
    return f"{value:>10}"
""",
    )

    assert result.error is None
    assert not result.degraded_passes
    assert not result.issues
    assert result.paths_explored <= 10


def test_scan_file_modeled_file_read_does_not_degrade(tmp_path: Path) -> None:
    result = _scan_source(
        tmp_path,
        "modeled_file_read.py",
        """
from builtins import open as open_resource


def target(flag: int) -> int:
    handle = open_resource("virtual", "w")
    if flag >= 0:
        value = handle.read()
        handle.close()
        return len(value)
    handle.close()
    return 0
""",
    )

    assert result.error is None
    assert "unmodeled_call_abstraction" not in result.degraded_passes
    assert not result.issues
    assert result.paths_explored <= 10


def test_scan_file_closed_file_read_still_reports_resource_use(tmp_path: Path) -> None:
    result = _scan_source(
        tmp_path,
        "closed_file_read.py",
        """
from builtins import open as open_resource


def target() -> object:
    handle = open_resource("virtual", "w")
    handle.close()
    return handle.read()
""",
    )

    assert result.error is None
    assert "unmodeled_call_abstraction" not in result.degraded_passes
    assert any(issue.get("kind") == "ATTRIBUTE_ERROR" for issue in result.issues)
    assert result.paths_explored <= 10


def test_scan_file_respects_shadowed_builtin_len_for_bug_path(tmp_path: Path) -> None:
    result = _scan_source(
        tmp_path,
        "shadowed_builtin_len.py",
        """
def len(value: object) -> int:
    return 0


def target(x: int) -> int:
    return 1 // len([x])
""",
    )

    assert result.error is None
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)


def test_scan_file_respects_shadowed_builtin_int_and_open_controls(tmp_path: Path) -> None:
    result = _scan_source(
        tmp_path,
        "shadowed_builtin_int_open.py",
        """
class Handle:
    def __init__(self) -> None:
        self.events: list[object] = []

    def close(self) -> None:
        self.events.append("closed")


def int(value: object) -> int:
    return 1


def open(*args: object, **kwargs: object) -> Handle:
    return Handle()


def target(flag: int) -> int:
    handle = open("virtual", "w")
    handle.close()
    if flag > 0:
        return int("not-an-int")
    return len(handle.events)
""",
    )

    assert result.error is None
    assert not any(
        issue.get("kind") in {"ATTRIBUTE_ERROR", "TYPE_ERROR", "VALUE_ERROR"}
        for issue in result.issues
    )


def test_scan_file_respects_shadowed_fromhex_for_value_error(tmp_path: Path) -> None:
    result = _scan_source(
        tmp_path,
        "shadowed_fromhex.py",
        """
def fromhex(value: object) -> bytes:
    return b"ok"


def target(flag: int) -> int:
    return len(fromhex("zz"))
""",
    )

    assert result.error is None
    assert not any(issue.get("kind") == "VALUE_ERROR" for issue in result.issues)


def test_scan_file_reports_dynamic_code_runtime_error(tmp_path: Path) -> None:
    result = _scan_source(
        tmp_path,
        "dynamic_code_runtime_error.py",
        """
def target(x: int, flag: int) -> object:
    expression = "x + 1"
    if flag > 0:
        expression = "x + 2"
    return eval(expression)
""",
    )

    assert result.error is None
    assert result.degraded_passes == ["builtin_eval_semantics_unsupported"]
    assert any(issue.get("kind") == "RUNTIME_ERROR" for issue in result.issues)
    assert result.paths_explored <= 10


def test_scan_file_concrete_expression_control_has_no_runtime_error(
    tmp_path: Path,
) -> None:
    result = _scan_source(
        tmp_path,
        "concrete_expression_control.py",
        """
def target(x: int, flag: int) -> int:
    if flag > 0:
        return x + 2
    return x + 1
""",
    )

    assert result.error is None
    assert not result.degraded_passes
    assert not any(issue.get("kind") == "RUNTIME_ERROR" for issue in result.issues)
    assert result.paths_explored <= 10



