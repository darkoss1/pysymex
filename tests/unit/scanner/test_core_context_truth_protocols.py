from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_suppresses_body_issue_after_positive_length_exit_result(tmp_path: Path) -> None:
    target = tmp_path / "context_exit_positive_length_result.py"
    target.write_text(
        "class LengthResult:\n"
        "    def __len__(self) -> int:\n"
        "        return 1\n\n"
        "class Manager:\n"
        "    def __enter__(self) -> int:\n"
        "        return 1\n\n"
        "    def __exit__(self, exc_type: object, exc: object, tb: object) -> LengthResult:\n"
        "        return LengthResult()\n\n"
        "def target() -> int:\n"
        "    with Manager():\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_reports_one_body_issue_after_zero_length_exit_result(tmp_path: Path) -> None:
    target = tmp_path / "context_exit_zero_length_result.py"
    target.write_text(
        "class LengthResult:\n"
        "    def __len__(self) -> int:\n"
        "        return 0\n\n"
        "class Manager:\n"
        "    def __enter__(self) -> int:\n"
        "        return 1\n\n"
        "    def __exit__(self, exc_type: object, exc: object, tb: object) -> LengthResult:\n"
        "        return LengthResult()\n\n"
        "def target() -> int:\n"
        "    with Manager():\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)
    division_issues = [issue for issue in result.issues if issue.get("kind") == "DIVISION_BY_ZERO"]

    assert len(division_issues) == 1
    assert division_issues[0].get("line") == 14


def test_scan_file_forks_symbolic_length_exit_result_into_cleanup_outcomes(
    tmp_path: Path,
) -> None:
    target = tmp_path / "context_exit_symbolic_length_result.py"
    target.write_text(
        "class LengthResult:\n"
        "    def __init__(self, length: int) -> None:\n"
        "        self.length = length\n\n"
        "    def __len__(self) -> int:\n"
        "        return self.length\n\n"
        "class Manager:\n"
        "    def __init__(self, length: int) -> None:\n"
        "        self.length = length\n\n"
        "    def __enter__(self) -> int:\n"
        "        return 1\n\n"
        "    def __exit__(self, exc_type: object, exc: object, tb: object) -> LengthResult:\n"
        "        return LengthResult(self.length)\n\n"
        "def target(length: int) -> int:\n"
        "    with Manager(length):\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    division_issues = [issue for issue in result.issues if issue.get("kind") == "DIVISION_BY_ZERO"]
    assert len(division_issues) == 1
    assert any(
        issue.get("kind") == "VALUE_ERROR"
        and "__len__() should return >= 0" in str(issue.get("message", ""))
        for issue in result.issues
    )
    assert "unsupported_truth_protocol" not in result.degraded_passes


def test_scan_file_catches_negative_symbolic_length_exit_replacement(tmp_path: Path) -> None:
    target = tmp_path / "context_exit_symbolic_length_caught.py"
    target.write_text(
        "class LengthResult:\n"
        "    def __init__(self, length: int) -> None:\n"
        "        self.length = length\n\n"
        "    def __len__(self) -> int:\n"
        "        return self.length\n\n"
        "class Manager:\n"
        "    def __init__(self, length: int) -> None:\n"
        "        self.length = length\n\n"
        "    def __enter__(self) -> int:\n"
        "        return 1\n\n"
        "    def __exit__(self, exc_type: object, exc: object, tb: object) -> LengthResult:\n"
        "        return LengthResult(self.length)\n\n"
        "def target(length: int) -> int:\n"
        "    value = 0\n"
        "    try:\n"
        "        with Manager(length):\n"
        "            return 10 // 0\n"
        "    except ValueError:\n"
        "        value = 1\n"
        "    assert value == 0\n"
        "    return value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    division_issues = [issue for issue in result.issues if issue.get("kind") == "DIVISION_BY_ZERO"]
    assert len(division_issues) == 1
    assert any(issue.get("kind") == "ASSERTION_ERROR" for issue in result.issues)
    assert not any(issue.get("kind") == "UNHANDLED_EXCEPTION" for issue in result.issues)
    assert "unsupported_truth_protocol" not in result.degraded_passes


def test_scan_file_replaces_body_issue_after_invalid_bool_exit_result(tmp_path: Path) -> None:
    target = tmp_path / "context_exit_invalid_bool_result.py"
    target.write_text(
        "class BadResult:\n"
        "    def __bool__(self) -> int:\n"
        "        return 1\n\n"
        "class Manager:\n"
        "    def __enter__(self) -> int:\n"
        "        return 1\n\n"
        "    def __exit__(self, exc_type: object, exc: object, tb: object) -> BadResult:\n"
        "        return BadResult()\n\n"
        "def target() -> int:\n"
        "    with Manager():\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and "__bool__ should return bool" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_replaces_body_issue_after_negative_length_exit_result(tmp_path: Path) -> None:
    target = tmp_path / "context_exit_negative_length_result.py"
    target.write_text(
        "class BadResult:\n"
        "    def __len__(self) -> int:\n"
        "        return -1\n\n"
        "class Manager:\n"
        "    def __enter__(self) -> int:\n"
        "        return 1\n\n"
        "    def __exit__(self, exc_type: object, exc: object, tb: object) -> BadResult:\n"
        "        return BadResult()\n\n"
        "def target() -> int:\n"
        "    with Manager():\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert any(
        issue.get("kind") == "VALUE_ERROR"
        and "__len__() should return >= 0" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_suppresses_with_path_proven_positive_length_exit_result(tmp_path: Path) -> None:
    target = tmp_path / "context_exit_guarded_positive_length.py"
    target.write_text(
        "class Result:\n"
        "    def __init__(self, size: int) -> None:\n"
        "        self.size = size\n\n"
        "    def __len__(self) -> int:\n"
        "        return self.size\n\n"
        "class Manager:\n"
        "    def __init__(self, size: int) -> None:\n"
        "        self.size = size\n\n"
        "    def __enter__(self) -> int:\n"
        "        return 1\n\n"
        "    def __exit__(self, exc_type: object, exc: object, tb: object) -> Result:\n"
        "        return Result(self.size)\n\n"
        "def target(size: int) -> int:\n"
        "    if size <= 0:\n"
        "        return 1\n"
        "    with Manager(size):\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert "unsupported_truth_protocol" not in result.degraded_passes


def test_scan_file_reports_with_path_proven_nonnegative_length_exit_result(
    tmp_path: Path,
) -> None:
    target = tmp_path / "context_exit_guarded_nonnegative_length.py"
    target.write_text(
        "class Result:\n"
        "    def __init__(self, size: int) -> None:\n"
        "        self.size = size\n\n"
        "    def __len__(self) -> int:\n"
        "        return self.size\n\n"
        "class Manager:\n"
        "    def __init__(self, size: int) -> None:\n"
        "        self.size = size\n\n"
        "    def __enter__(self) -> int:\n"
        "        return 1\n\n"
        "    def __exit__(self, exc_type: object, exc: object, tb: object) -> Result:\n"
        "        return Result(self.size)\n\n"
        "def target(size: int) -> int:\n"
        "    if size < 0:\n"
        "        return 1\n"
        "    with Manager(size):\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)
    division_issues = [issue for issue in result.issues if issue.get("kind") == "DIVISION_BY_ZERO"]

    assert len(division_issues) == 1
    assert "unsupported_truth_protocol" not in result.degraded_passes


def test_scan_file_reports_outer_handler_issue_after_false_exit_truth_result(
    tmp_path: Path,
) -> None:
    target = tmp_path / "context_exit_false_handler_issue.py"
    target.write_text(
        "class FalseResult:\n"
        "    def __bool__(self) -> bool:\n"
        "        return False\n\n"
        "class Manager:\n"
        "    def __enter__(self) -> int:\n"
        "        return 1\n\n"
        "    def __exit__(self, exc_type: object, exc: object, tb: object) -> FalseResult:\n"
        "        return FalseResult()\n\n"
        "def target(denominator: int) -> int:\n"
        "    try:\n"
        "        with Manager():\n"
        "            raise ValueError('body')\n"
        "    except ValueError:\n"
        "        return 10 // denominator\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)
    division_issues = [issue for issue in result.issues if issue.get("kind") == "DIVISION_BY_ZERO"]

    assert len(division_issues) == 1
    assert division_issues[0].get("line") == 17
    assert not any(issue.get("kind") == "UNHANDLED_EXCEPTION" for issue in result.issues)
    assert "unsupported_truth_protocol" not in result.degraded_passes


def test_scan_file_does_not_report_outer_handler_issue_after_truthy_exit_result(
    tmp_path: Path,
) -> None:
    target = tmp_path / "context_exit_truthy_handler_unreachable.py"
    target.write_text(
        "class TruthyResult:\n"
        "    def __bool__(self) -> bool:\n"
        "        return True\n\n"
        "class Manager:\n"
        "    def __enter__(self) -> int:\n"
        "        return 1\n\n"
        "    def __exit__(self, exc_type: object, exc: object, tb: object) -> TruthyResult:\n"
        "        return TruthyResult()\n\n"
        "def target(denominator: int) -> int:\n"
        "    try:\n"
        "        with Manager():\n"
        "            raise ValueError('body')\n"
        "    except ValueError:\n"
        "        return 10 // denominator\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(issue.get("kind") == "UNHANDLED_EXCEPTION" for issue in result.issues)
    assert "unsupported_truth_protocol" not in result.degraded_passes
