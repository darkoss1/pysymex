from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def test_scan_file_respects_custom_zero_length_guard(tmp_path: Path) -> None:
    target = tmp_path / "custom_len_false_guard.py"
    target.write_text(
        "class Box:\n"
        "    def __len__(self) -> int:\n"
        "        return 0\n\n"
        "def target(value: int) -> int:\n"
        "    box = Box()\n"
        "    if box:\n"
        "        return 1 // value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_respects_custom_nonzero_length_bug_path(tmp_path: Path) -> None:
    target = tmp_path / "custom_len_true_guard.py"
    target.write_text(
        "class Box:\n"
        "    def __len__(self) -> int:\n"
        "        return 1\n\n"
        "def target(value: int) -> int:\n"
        "    box = Box()\n"
        "    if box:\n"
        "        return 1 // value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_reports_negative_custom_length(tmp_path: Path) -> None:
    target = tmp_path / "custom_len_negative.py"
    target.write_text(
        "class Box:\n"
        "    def __len__(self) -> int:\n"
        "        return -1\n\n"
        "def target() -> bool:\n"
        "    return bool(Box())\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "VALUE_ERROR"
        and "__len__() should return >= 0" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_reports_non_integer_custom_length(tmp_path: Path) -> None:
    target = tmp_path / "custom_len_type_error.py"
    target.write_text(
        "class Box:\n"
        "    def __len__(self) -> str:\n"
        "        return 'bad'\n\n"
        "def target() -> bool:\n"
        "    return bool(Box())\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and "__len__ result cannot be interpreted as an integer" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_executes_custom_len_builtin_result(tmp_path: Path) -> None:
    target = tmp_path / "custom_len_builtin_safe.py"
    target.write_text(
        "class Box:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __len__(self) -> int:\n"
        "        return 1 if self.value == 0 else self.value\n\n"
        "def target(value: int) -> int:\n"
        "    return 10 // len(Box(value))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_reports_negative_custom_len_builtin_result(tmp_path: Path) -> None:
    target = tmp_path / "custom_len_builtin_negative.py"
    target.write_text(
        "class Box:\n"
        "    def __len__(self) -> int:\n"
        "        return -1\n\n"
        "def target() -> int:\n"
        "    return len(Box())\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "VALUE_ERROR"
        and "__len__() should return >= 0" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_executes_path_proven_nonnegative_symbolic_length(tmp_path: Path) -> None:
    target = tmp_path / "custom_len_guarded_symbolic.py"
    target.write_text(
        "class Box:\n"
        "    def __init__(self, size: int) -> None:\n"
        "        self.size = size\n\n"
        "    def __len__(self) -> int:\n"
        "        return self.size\n\n"
        "def target(size: int) -> int:\n"
        "    if size < 0:\n"
        "        return 1\n"
        "    if Box(size):\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert "unsupported_truth_protocol" not in result.degraded_passes


def test_scan_file_executes_path_proven_positive_len_builtin_result(tmp_path: Path) -> None:
    target = tmp_path / "custom_len_builtin_guarded_positive.py"
    target.write_text(
        "class Box:\n"
        "    def __init__(self, size: int) -> None:\n"
        "        self.size = size\n\n"
        "    def __len__(self) -> int:\n"
        "        return self.size\n\n"
        "def target(size: int) -> int:\n"
        "    if size <= 0:\n"
        "        return 1\n"
        "    return 10 // len(Box(size))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert "unsupported_truth_protocol" not in result.degraded_passes


def test_scan_file_reports_path_proven_nonnegative_len_builtin_result(tmp_path: Path) -> None:
    target = tmp_path / "custom_len_builtin_guarded_nonnegative.py"
    target.write_text(
        "class Box:\n"
        "    def __init__(self, size: int) -> None:\n"
        "        self.size = size\n\n"
        "    def __len__(self) -> int:\n"
        "        return self.size\n\n"
        "def target(size: int) -> int:\n"
        "    if size < 0:\n"
        "        return 1\n"
        "    return 10 // len(Box(size))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert "unsupported_truth_protocol" not in result.degraded_passes


def test_scan_file_forks_unbounded_symbolic_len_builtin_result(tmp_path: Path) -> None:
    target = tmp_path / "custom_len_builtin_unbounded_symbolic.py"
    target.write_text(
        "class Box:\n"
        "    def __init__(self, size: int) -> None:\n"
        "        self.size = size\n\n"
        "    def __len__(self) -> int:\n"
        "        return self.size\n\n"
        "def target(size: int) -> int:\n"
        "    return 10 // len(Box(size))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert any(issue.get("kind") == "VALUE_ERROR" for issue in result.issues)
    assert "unsupported_truth_protocol" not in result.degraded_passes


def test_scan_file_forks_unbounded_symbolic_length_truth_result(tmp_path: Path) -> None:
    target = tmp_path / "custom_len_symbolic_truth.py"
    target.write_text(
        "class Box:\n"
        "    def __init__(self, size: int) -> None:\n"
        "        self.size = size\n\n"
        "    def __len__(self) -> int:\n"
        "        return self.size\n\n"
        "def target(size: int) -> int:\n"
        "    if Box(size):\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert any(issue.get("kind") == "VALUE_ERROR" for issue in result.issues)
    assert "unsupported_truth_protocol" not in result.degraded_passes


def test_scan_file_routes_symbolic_len_value_error_into_caller_handler(tmp_path: Path) -> None:
    target = tmp_path / "custom_len_builtin_symbolic_caught.py"
    target.write_text(
        "class Box:\n"
        "    def __init__(self, size: int) -> None:\n"
        "        self.size = size\n\n"
        "    def __len__(self) -> int:\n"
        "        return self.size\n\n"
        "def target(size: int) -> int:\n"
        "    try:\n"
        "        return 10 // len(Box(size))\n"
        "    except ValueError:\n"
        "        return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(issue.get("kind") == "VALUE_ERROR" for issue in result.issues)
    assert "unsupported_truth_protocol" not in result.degraded_passes
