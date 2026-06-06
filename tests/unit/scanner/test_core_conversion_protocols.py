from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def test_scan_file_executes_safe_custom_int_result(tmp_path: Path) -> None:
    target = tmp_path / "custom_int_safe.py"
    target.write_text(
        "class Number:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __int__(self) -> int:\n"
        "        return 1 if self.value == 0 else self.value\n\n"
        "def target(value: int) -> int:\n"
        "    return 10 // int(Number(value))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_safe_custom_float_result(tmp_path: Path) -> None:
    target = tmp_path / "custom_float_safe.py"
    target.write_text(
        "class Number:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __float__(self) -> float:\n"
        "        return 1.0\n\n"
        "def target(value: int) -> float:\n"
        "    return 10.0 / float(Number(value))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_reports_invalid_custom_float_result(tmp_path: Path) -> None:
    target = tmp_path / "custom_float_invalid.py"
    target.write_text(
        "class Number:\n"
        "    def __float__(self) -> int:\n"
        "        return 1\n\n"
        "def target() -> float:\n"
        "    return float(Number())\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and "__float__ returned non-float" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_uses_custom_index_as_int_fallback(tmp_path: Path) -> None:
    target = tmp_path / "custom_index_int_safe.py"
    target.write_text(
        "class Number:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __index__(self) -> int:\n"
        "        return 1 if self.value == 0 else self.value\n\n"
        "def target(value: int) -> int:\n"
        "    return 10 // int(Number(value))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_safe_custom_index_for_slice_start(tmp_path: Path) -> None:
    target = tmp_path / "custom_index_slice_start_safe.py"
    target.write_text(
        "class Index:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __index__(self) -> int:\n"
        "        10 // (1 if self.value == 0 else self.value)\n"
        "        return 0\n\n"
        "def target(value: int) -> list[int]:\n"
        "    return [1, 2][Index(value):2]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_preserves_custom_index_bug_for_slice_start(tmp_path: Path) -> None:
    target = tmp_path / "custom_index_slice_start_bug.py"
    target.write_text(
        "class Index:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __index__(self) -> int:\n"
        "        10 // self.value\n"
        "        return 0\n\n"
        "def target(value: int) -> list[int]:\n"
        "    return [1, 2][Index(value):2]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_custom_index_for_slice_stop_after_start(tmp_path: Path) -> None:
    target = tmp_path / "custom_index_slice_stop_bug.py"
    target.write_text(
        "class Start:\n"
        "    def __index__(self) -> int:\n"
        "        return 0\n\n"
        "class Stop:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __index__(self) -> int:\n"
        "        10 // self.value\n"
        "        return 1\n\n"
        "def target(value: int) -> list[int]:\n"
        "    return [1, 2][Start():Stop(value)]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_safe_custom_index_for_slice_store_start(tmp_path: Path) -> None:
    target = tmp_path / "custom_index_slice_store_start_safe.py"
    target.write_text(
        "class Index:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __index__(self) -> int:\n"
        "        10 // (1 if self.value == 0 else self.value)\n"
        "        return 0\n\n"
        "def target(value: int) -> None:\n"
        "    items = [1, 2]\n"
        "    items[Index(value):1] = [3]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_custom_index_for_slice_store_stop(tmp_path: Path) -> None:
    target = tmp_path / "custom_index_slice_store_stop_bug.py"
    target.write_text(
        "class Start:\n"
        "    def __index__(self) -> int:\n"
        "        return 0\n\n"
        "class Stop:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __index__(self) -> int:\n"
        "        10 // self.value\n"
        "        return 1\n\n"
        "def target(value: int) -> None:\n"
        "    items = [1, 2]\n"
        "    items[Start():Stop(value)] = [3]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_safe_custom_index_for_built_slice_start(tmp_path: Path) -> None:
    target = tmp_path / "custom_index_built_slice_start_safe.py"
    target.write_text(
        "class Index:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __index__(self) -> int:\n"
        "        10 // (1 if self.value == 0 else self.value)\n"
        "        return 0\n\n"
        "def target(value: int) -> list[int]:\n"
        "    return [1, 2, 3][Index(value):2:1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_custom_index_for_built_slice_step(tmp_path: Path) -> None:
    target = tmp_path / "custom_index_built_slice_step_bug.py"
    target.write_text(
        "class Start:\n"
        "    def __index__(self) -> int:\n"
        "        return 0\n\n"
        "class Step:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __index__(self) -> int:\n"
        "        10 // self.value\n"
        "        return 1\n\n"
        "def target(value: int) -> list[int]:\n"
        "    return [1, 2, 3][Start():2:Step(value)]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_uses_normalized_built_slice_read_result(tmp_path: Path) -> None:
    target = tmp_path / "custom_index_built_slice_read_result.py"
    target.write_text(
        "class Step:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __index__(self) -> int:\n"
        "        10 // (1 if self.value == 0 else self.value)\n"
        "        return 2\n\n"
        "def target(value: int) -> int:\n"
        "    return 10 // [1, 4, 0][0:3:Step(value)][1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(issue.get("kind") == "INDEX_ERROR" for issue in result.issues)
    assert "unsupported_slice_abstraction" not in result.degraded_passes


def test_scan_file_reports_zero_step_built_slice_read(tmp_path: Path) -> None:
    target = tmp_path / "custom_index_built_slice_zero_step.py"
    target.write_text(
        "def target() -> list[int]:\n    return [1, 2, 3][0:3:0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "VALUE_ERROR"
        and "slice step cannot be zero" in str(issue.get("message"))
        for issue in result.issues
    )
    assert "unsupported_slice_abstraction" not in result.degraded_passes


def test_scan_file_reports_symbolic_zero_step_built_slice_read(tmp_path: Path) -> None:
    target = tmp_path / "symbolic_built_slice_zero_step.py"
    target.write_text(
        "def target(step: int) -> list[int]:\n    return [1, 2, 3][::step]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "VALUE_ERROR"
        and "slice step cannot be zero" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_does_not_report_guarded_symbolic_zero_step_built_slice_read(
    tmp_path: Path,
) -> None:
    target = tmp_path / "guarded_symbolic_built_slice_zero_step.py"
    target.write_text(
        "def target(step: int) -> list[int]:\n"
        "    safe_step = 1 if step == 0 else step\n"
        "    return [1, 2, 3][::safe_step]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "VALUE_ERROR" for issue in result.issues)


def test_scan_file_executes_safe_custom_index_for_built_slice_delete(tmp_path: Path) -> None:
    target = tmp_path / "custom_index_built_slice_delete_safe.py"
    target.write_text(
        "class Step:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __index__(self) -> int:\n"
        "        10 // (1 if self.value == 0 else self.value)\n"
        "        return 1\n\n"
        "def target(value: int) -> None:\n"
        "    items = [1, 2, 3]\n"
        "    del items[0:2:Step(value)]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(issue.get("kind") == "INDEX_ERROR" for issue in result.issues)
    assert "unsupported_slice_abstraction" not in result.degraded_passes


def test_scan_file_executes_custom_index_for_built_slice_delete_step(tmp_path: Path) -> None:
    target = tmp_path / "custom_index_built_slice_delete_bug.py"
    target.write_text(
        "class Step:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __index__(self) -> int:\n"
        "        10 // self.value\n"
        "        return 1\n\n"
        "def target(value: int) -> None:\n"
        "    items = [1, 2, 3]\n"
        "    del items[0:2:Step(value)]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
