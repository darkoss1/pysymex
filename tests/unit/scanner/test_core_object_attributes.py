"""Tests for scanner object attribute semantics."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def test_scan_file_reports_user_object_attribute_missing_on_feasible_path(
    tmp_path: Path,
) -> None:
    """User-object attributes assigned on only one branch must not be silently invented."""
    target = tmp_path / "object_attribute_missing.py"
    target.write_text(
        "class Record:\n"
        "    pass\n\n"
        "def target(flag: bool) -> int:\n"
        "    record = Record()\n"
        "    if flag:\n"
        "        record.extra = 5\n"
        "    return record.extra\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 8
        for issue in result.issues
    )


def test_scan_file_does_not_report_user_object_attribute_set_on_all_paths(
    tmp_path: Path,
) -> None:
    """Alias writes on both branches should make the attribute read safe."""
    target = tmp_path / "object_attribute_all_paths.py"
    target.write_text(
        "class Record:\n"
        "    pass\n\n"
        "def target(flag: bool) -> int:\n"
        "    left = Record()\n"
        "    right = left\n"
        "    if flag:\n"
        "        left.extra = 1\n"
        "    else:\n"
        "        right.extra = 2\n"
        "    return right.extra\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 11
        for issue in result.issues
    )


def test_scan_file_does_not_report_constructor_initialized_attribute(
    tmp_path: Path,
) -> None:
    """Straight-line __init__ assignments should initialize instance attributes."""
    target = tmp_path / "object_attribute_init_const.py"
    target.write_text(
        "class Record:\n"
        "    def __init__(self) -> None:\n"
        "        self.ready = 1\n\n"
        "def target() -> int:\n"
        "    record = Record()\n"
        "    return record.ready\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 7
        for issue in result.issues
    )


def test_scan_file_binds_private_constructor_class_for_getattr(
    tmp_path: Path,
) -> None:
    """Private helper classes have normal CPython class semantics during scans."""
    target = tmp_path / "private_object_getattr.py"
    target.write_text(
        "class _Record:\n"
        "    def __init__(self) -> None:\n"
        "        self.ready = 1\n\n"
        "def target() -> int:\n"
        "    record = _Record()\n"
        "    return getattr(record, 'ready')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 7
        for issue in result.issues
    )


def test_scan_file_reports_constructor_parameter_attribute_zero_division(
    tmp_path: Path,
) -> None:
    """Constructor parameter assignments should preserve downstream bug detection."""
    target = tmp_path / "object_attribute_init_param.py"
    target.write_text(
        "class Record:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.ready = value\n\n"
        "def target(value: int) -> int:\n"
        "    record = Record(value)\n"
        "    return 10 // record.ready\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 7
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") in {"ATTRIBUTE_ERROR", "TYPE_ERROR"}
        and issue.get("function_name") == "target"
        and issue.get("line") == 7
        for issue in result.issues
    )


def test_scan_file_executes_constructor_when_init_replay_is_partial(
    tmp_path: Path,
) -> None:
    """Complex constructor fields should fall back to full ``__init__`` execution."""
    target = tmp_path / "object_attribute_complex_init.py"
    target.write_text(
        "class Record:\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.ready = value\n"
        "        self.items = [value, value + 1]\n\n"
        "def target(value: int) -> int:\n"
        "    record = Record(value)\n"
        "    return 10 // record.items[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 8
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") in {"ATTRIBUTE_ERROR", "TYPE_ERROR"}
        and issue.get("function_name") == "target"
        and issue.get("line") == 8
        for issue in result.issues
    )


def test_scan_file_does_not_report_attribute_initialized_in_constructor_branches(
    tmp_path: Path,
) -> None:
    """Both constructor branches assigning an attribute should make the read safe."""
    target = tmp_path / "object_attribute_init_branches.py"
    target.write_text(
        "class Record:\n"
        "    def __init__(self, flag: bool) -> None:\n"
        "        if flag:\n"
        "            self.ready = 1\n"
        "        else:\n"
        "            self.ready = 2\n\n"
        "def target(flag: bool) -> int:\n"
        "    record = Record(flag)\n"
        "    return record.ready\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 10
        for issue in result.issues
    )


def test_scan_file_reports_constructor_branch_zero_division_without_attr_noise(
    tmp_path: Path,
) -> None:
    """Conditional constructor values should keep branch-dependent zero feasible."""
    target = tmp_path / "object_attribute_init_branch_zero.py"
    target.write_text(
        "class Record:\n"
        "    def __init__(self, flag: bool) -> None:\n"
        "        if flag:\n"
        "            self.ready = 0\n"
        "        else:\n"
        "            self.ready = 2\n\n"
        "def target(flag: bool) -> int:\n"
        "    record = Record(flag)\n"
        "    return 10 // record.ready\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 10
        for issue in result.issues
    ), result.issues
    assert not any(
        issue.get("kind") in {"ATTRIBUTE_ERROR", "TYPE_ERROR"}
        and issue.get("function_name") == "target"
        and issue.get("line") == 10
        for issue in result.issues
    )


def test_scan_file_does_not_report_builtin_setattr_on_dynamic_user_object(
    tmp_path: Path,
) -> None:
    """setattr() should mutate known dynamic user objects before later attribute reads."""
    target = tmp_path / "builtin_setattr_dynamic_object.py"
    target.write_text(
        "class Record:\n"
        "    pass\n\n"
        "def target(seed: int) -> int:\n"
        "    record = Record()\n"
        "    setattr(record, 'extra', seed + 1)\n"
        "    return record.extra\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") in {6, 7}
        for issue in result.issues
    )


def test_scan_file_does_not_report_attribute_after_hasattr_guard(
    tmp_path: Path,
) -> None:
    """A true hasattr branch proves the guarded attribute read is valid."""
    target = tmp_path / "hasattr_guarded_attribute.py"
    target.write_text(
        "class Record:\n"
        "    pass\n\n"
        "def target(record: Record) -> int:\n"
        "    if hasattr(record, 'score'):\n"
        "        return record.score\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 6
        for issue in result.issues
    )


def test_scan_file_reports_deleted_dynamic_user_object_attribute(
    tmp_path: Path,
) -> None:
    """Deleting a dynamic instance attribute should make a later read fail."""
    target = tmp_path / "deleted_dynamic_object_attribute.py"
    target.write_text(
        "class Record:\n"
        "    pass\n\n"
        "def target(seed: int) -> int:\n"
        "    record = Record()\n"
        "    record.extra = seed\n"
        "    del record.extra\n"
        "    return record.extra\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 8
        for issue in result.issues
    )
