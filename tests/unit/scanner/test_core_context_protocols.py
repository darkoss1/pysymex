from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def test_scan_file_executes_safe_custom_enter_result(tmp_path: Path) -> None:
    target = tmp_path / "context_enter_safe.py"
    target.write_text(
        "class Manager:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __enter__(self) -> int:\n"
        "        return 1 if self.value == 0 else self.value\n\n"
        "    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:\n"
        "        return False\n\n"
        "def target(value: int) -> int:\n"
        "    with Manager(value) as denominator:\n"
        "        return 10 // denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_preserves_custom_enter_bug_result(tmp_path: Path) -> None:
    target = tmp_path / "context_enter_bug.py"
    target.write_text(
        "class Manager:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __enter__(self) -> int:\n"
        "        return self.value\n\n"
        "    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:\n"
        "        return False\n\n"
        "def target(value: int) -> int:\n"
        "    with Manager(value) as denominator:\n"
        "        return 10 // denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_custom_exit_on_normal_cleanup(tmp_path: Path) -> None:
    target = tmp_path / "context_exit_body_bug.py"
    target.write_text(
        "class Manager:\n"
        "    def __enter__(self) -> int:\n"
        "        return 1\n\n"
        "    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:\n"
        "        10 // 0\n"
        "        return False\n\n"
        "def target() -> int:\n"
        "    with Manager() as value:\n"
        "        return value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_catches_replacement_from_custom_exit(tmp_path: Path) -> None:
    target = tmp_path / "context_exit_replacement_caught.py"
    target.write_text(
        "class Manager:\n"
        "    def __enter__(self) -> int:\n"
        "        return 1\n\n"
        "    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:\n"
        "        raise ValueError('replacement')\n\n"
        "def target(denominator: int) -> int:\n"
        "    value = 0\n"
        "    try:\n"
        "        with Manager():\n"
        "            value = 10 // denominator\n"
        "    except ValueError:\n"
        "        value = 1\n"
        "    assert value == 0\n"
        "    return value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"DIVISION_BY_ZERO", "UNHANDLED_EXCEPTION"} for issue in result.issues
    )
    assert any(issue.get("kind") == "ASSERTION_ERROR" for issue in result.issues)


def test_scan_file_reports_uncaught_replacement_from_custom_exit(tmp_path: Path) -> None:
    target = tmp_path / "context_exit_replacement_uncaught.py"
    target.write_text(
        "class Manager:\n"
        "    def __enter__(self) -> int:\n"
        "        return 1\n\n"
        "    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:\n"
        "        raise ValueError('replacement')\n\n"
        "def target(denominator: int) -> int:\n"
        "    with Manager():\n"
        "        return 10 // denominator\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert any(
        issue.get("kind") == "UNHANDLED_EXCEPTION" and "ValueError" in str(issue.get("message", ""))
        for issue in result.issues
    )


def test_scan_file_preserves_multiple_context_enter_instances(tmp_path: Path) -> None:
    target = tmp_path / "multiple_context_enter_instances.py"
    target.write_text(
        "class Resource:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "    def __enter__(self) -> 'Resource':\n"
        "        return self\n\n"
        "    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:\n"
        "        return False\n\n"
        "def target(first: int, second: int) -> int:\n"
        "    with Resource(first) as left, Resource(second) as right:\n"
        "        _ = 10 // (1 if left.value == 0 else left.value)\n"
        "        return 10 // right.value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(
        issue.get("kind") in {"NULL_DEREFERENCE", "ATTRIBUTE_ERROR"} for issue in result.issues
    )


def test_scan_file_suppresses_body_issue_after_truthy_object_exit_result(tmp_path: Path) -> None:
    target = tmp_path / "context_exit_truthy_result.py"
    target.write_text(
        "class TruthyResult:\n"
        "    def __bool__(self) -> bool:\n"
        "        return True\n\n"
        "class Manager:\n"
        "    def __enter__(self) -> int:\n"
        "        return 1\n\n"
        "    def __exit__(self, exc_type: object, exc: object, tb: object) -> TruthyResult:\n"
        "        return TruthyResult()\n\n"
        "def target() -> int:\n"
        "    with Manager():\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_reports_one_body_issue_after_false_object_exit_result(tmp_path: Path) -> None:
    target = tmp_path / "context_exit_false_result.py"
    target.write_text(
        "class FalseResult:\n"
        "    def __bool__(self) -> bool:\n"
        "        return False\n\n"
        "class Manager:\n"
        "    def __enter__(self) -> int:\n"
        "        return 1\n\n"
        "    def __exit__(self, exc_type: object, exc: object, tb: object) -> FalseResult:\n"
        "        return FalseResult()\n\n"
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
