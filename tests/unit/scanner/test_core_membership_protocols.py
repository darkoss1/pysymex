from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def test_scan_file_preserves_custom_contains_bug_path(tmp_path: Path) -> None:
    target = tmp_path / "custom_contains_bug.py"
    target.write_text(
        "class Keys:\n"
        "    def __init__(self, key: int) -> None:\n"
        "        self.key = key\n\n"
        "    def __contains__(self, item: int) -> bool:\n"
        "        return item == self.key\n\n"
        "def target(value: int) -> int:\n"
        "    keys = Keys(value)\n"
        "    if 0 in keys:\n"
        "        return 1 // value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("line") == 11
        for issue in result.issues
    )


def test_scan_file_inverts_custom_contains_for_not_in(tmp_path: Path) -> None:
    target = tmp_path / "custom_not_contains_safe.py"
    target.write_text(
        "class Keys:\n"
        "    def __init__(self, key: int) -> None:\n"
        "        self.key = key\n\n"
        "    def __contains__(self, item: int) -> bool:\n"
        "        return item == self.key\n\n"
        "def target(value: int) -> int:\n"
        "    keys = Keys(value)\n"
        "    if 0 not in keys:\n"
        "        return 1 // value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("line") == 11
        for issue in result.issues
    )


def test_scan_file_passes_same_instance_to_custom_contains(tmp_path: Path) -> None:
    target = tmp_path / "custom_contains_same_instance.py"
    target.write_text(
        "class Keys:\n"
        "    def __contains__(self, item: object) -> bool:\n"
        "        return True\n\n"
        "def target(value: int) -> int:\n"
        "    keys = Keys()\n"
        "    if keys in keys:\n"
        "        return 1 // value\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_truth_tests_nonboolean_contains_false_result(
    tmp_path: Path,
) -> None:
    target = tmp_path / "custom_contains_object_result.py"
    target.write_text(
        "class FalseResult:\n"
        "    def __bool__(self) -> bool:\n"
        "        return False\n\n"
        "class Keys:\n"
        "    def __contains__(self, item: object) -> FalseResult:\n"
        "        return FalseResult()\n\n"
        "def target() -> int:\n"
        "    if 0 in Keys():\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert "unsupported_membership_protocol" not in result.degraded_passes


def test_scan_file_truth_tests_nonboolean_contains_true_and_negated_false(
    tmp_path: Path,
) -> None:
    target = tmp_path / "custom_contains_truth_results.py"
    target.write_text(
        "class Result:\n"
        "    def __init__(self, value: bool) -> None:\n"
        "        self.value = value\n\n"
        "    def __bool__(self) -> bool:\n"
        "        return self.value\n\n"
        "class Keys:\n"
        "    def __init__(self, value: bool) -> None:\n"
        "        self.value = value\n\n"
        "    def __contains__(self, item: object) -> Result:\n"
        "        return Result(self.value)\n\n"
        "def true_target() -> int:\n"
        "    if 0 in Keys(True):\n"
        "        return 10 // 0\n"
        "    return 1\n\n"
        "def negated_false_target() -> int:\n"
        "    if 0 not in Keys(False):\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert sum(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues) == 2
    assert "unsupported_membership_protocol" not in result.degraded_passes


def test_scan_file_truth_tests_nonboolean_contains_len_result(tmp_path: Path) -> None:
    target = tmp_path / "custom_contains_len_result.py"
    target.write_text(
        "class EmptyResult:\n"
        "    def __len__(self) -> int:\n"
        "        return 0\n\n"
        "class Keys:\n"
        "    def __contains__(self, item: object) -> EmptyResult:\n"
        "        return EmptyResult()\n\n"
        "def target() -> int:\n"
        "    if 0 in Keys():\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert "unsupported_membership_protocol" not in result.degraded_passes


def test_scan_file_reports_invalid_membership_bool_contract(tmp_path: Path) -> None:
    target = tmp_path / "custom_contains_invalid_bool_result.py"
    target.write_text(
        "class BadResult:\n"
        "    def __bool__(self) -> int:\n"
        "        return 1\n\n"
        "class Keys:\n"
        "    def __contains__(self, item: object) -> BadResult:\n"
        "        return BadResult()\n\n"
        "def target() -> bool:\n"
        "    return 0 in Keys()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and "__bool__ should return bool" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_forks_symbolic_membership_len_into_truth_and_error_paths(
    tmp_path: Path,
) -> None:
    target = tmp_path / "custom_contains_symbolic_len.py"
    target.write_text(
        "class Result:\n"
        "    def __init__(self, size: int) -> None:\n"
        "        self.size = size\n\n"
        "    def __len__(self) -> int:\n"
        "        return self.size\n\n"
        "class Keys:\n"
        "    def __init__(self, size: int) -> None:\n"
        "        self.size = size\n\n"
        "    def __contains__(self, item: object) -> Result:\n"
        "        return Result(self.size)\n\n"
        "def target(size: int) -> int:\n"
        "    if 0 in Keys(size):\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert any(issue.get("kind") == "VALUE_ERROR" for issue in result.issues)
    assert "unsupported_membership_protocol" not in result.degraded_passes


def test_scan_file_executes_path_proven_nonnegative_membership_length(tmp_path: Path) -> None:
    target = tmp_path / "custom_contains_guarded_symbolic_len.py"
    target.write_text(
        "class Result:\n"
        "    def __init__(self, size: int) -> None:\n"
        "        self.size = size\n\n"
        "    def __len__(self) -> int:\n"
        "        return self.size\n\n"
        "class Keys:\n"
        "    def __init__(self, size: int) -> None:\n"
        "        self.size = size\n\n"
        "    def __contains__(self, item: object) -> Result:\n"
        "        return Result(self.size)\n\n"
        "def target(size: int) -> int:\n"
        "    if size < 0:\n"
        "        return 1\n"
        "    if 0 in Keys(size):\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert "unsupported_membership_protocol" not in result.degraded_passes
