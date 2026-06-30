from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_reports_non_none_init_return(tmp_path: Path) -> None:
    target = tmp_path / "invalid_init_return.py"
    target.write_text(
        "class Record:\n"
        "    def __init__(self) -> None:\n"
        "        return 1\n\n"
        "def target() -> Record:\n"
        "    return Record()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and "__init__() should return None" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_allows_none_init_return(tmp_path: Path) -> None:
    target = tmp_path / "valid_init_return.py"
    target.write_text(
        "class Record:\n"
        "    def __init__(self) -> None:\n"
        "        return None\n\n"
        "def target() -> Record:\n"
        "    return Record()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "TYPE_ERROR"
        and "__init__() should return None" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_executes_custom_new_returning_non_instance_without_init(
    tmp_path: Path,
) -> None:
    target = tmp_path / "custom_new_non_instance.py"
    target.write_text(
        "class Record:\n"
        "    def __new__(cls) -> int:\n"
        "        return 1\n\n"
        "    def __init__(self) -> None:\n"
        "        10 // 0\n\n"
        "def target() -> int:\n"
        "    return 10 // Record()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_construction_protocol" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_custom_new_returning_foreign_instance_skips_init(tmp_path: Path) -> None:
    target = tmp_path / "custom_new_foreign_instance.py"
    target.write_text(
        "class Other:\n"
        "    def __init__(self) -> None:\n"
        "        self.denominator = 1\n\n"
        "class Record:\n"
        "    def __new__(cls) -> Other:\n"
        "        return Other()\n\n"
        "    def __init__(self) -> None:\n"
        "        10 // 0\n\n"
        "def target() -> int:\n"
        "    return 10 // Record().denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_construction_protocol" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_custom_new_returning_same_instance_executes_init(tmp_path: Path) -> None:
    target = tmp_path / "custom_new_same_instance.py"
    target.write_text(
        "class Record:\n"
        "    def __new__(cls, existing: 'Record') -> 'Record':\n"
        "        return existing\n\n"
        "    def __init__(self, existing: 'Record') -> None:\n"
        "        self.denominator = 1\n\n"
        "def target(existing: Record) -> int:\n"
        "    return 10 // Record(existing).denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_construction_protocol" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_custom_new_same_instance_init_preserves_bug_path(tmp_path: Path) -> None:
    target = tmp_path / "custom_new_same_instance_bug.py"
    target.write_text(
        "class Record:\n"
        "    def __new__(cls, existing: 'Record') -> 'Record':\n"
        "        return existing\n\n"
        "    def __init__(self, existing: 'Record') -> None:\n"
        "        self.denominator = 0\n\n"
        "def target(existing: Record) -> int:\n"
        "    return 10 // Record(existing).denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_construction_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_custom_new_same_instance_executes_init_contract(tmp_path: Path) -> None:
    target = tmp_path / "custom_new_same_instance_invalid_init.py"
    target.write_text(
        "class Record:\n"
        "    def __new__(cls, existing: 'Record') -> 'Record':\n"
        "        return existing\n\n"
        "    def __init__(self, existing: 'Record') -> None:\n"
        "        return 1\n\n"
        "def target(existing: Record) -> Record:\n"
        "    return Record(existing)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_construction_protocol" not in result.degraded_passes
    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and "__init__() should return None" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_custom_new_with_object_allocation_executes_init(
    tmp_path: Path,
) -> None:
    target = tmp_path / "custom_new_object_allocation.py"
    target.write_text(
        "class Record:\n"
        "    def __new__(cls) -> 'Record':\n"
        "        return object.__new__(cls)\n\n"
        "    def __init__(self) -> None:\n"
        "        self.denominator = 1\n\n"
        "def target() -> int:\n"
        "    return 10 // Record().denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unmodeled_call_abstraction" not in result.degraded_passes
    assert "unsupported_construction_protocol" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_custom_new_object_allocation_preserves_init_bug_path(tmp_path: Path) -> None:
    target = tmp_path / "custom_new_object_allocation_bug.py"
    target.write_text(
        "class Record:\n"
        "    def __new__(cls) -> 'Record':\n"
        "        return object.__new__(cls)\n\n"
        "    def __init__(self) -> None:\n"
        "        self.denominator = 0\n\n"
        "def target() -> int:\n"
        "    return 10 // Record().denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unmodeled_call_abstraction" not in result.degraded_passes
    assert "unsupported_construction_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_custom_new_subclass_result_executes_effective_init(tmp_path: Path) -> None:
    target = tmp_path / "custom_new_subclass_effective_init.py"
    target.write_text(
        "class Base:\n"
        "    def __new__(cls, value: int) -> 'Child':\n"
        "        return Child(0)\n\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.denominator = 0\n\n"
        "class Child(Base):\n"
        "    def __new__(cls, value: int) -> 'Child':\n"
        "        return object.__new__(cls)\n\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.denominator = value\n\n"
        "def target() -> int:\n"
        "    return 10 // Base(1).denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_construction_protocol" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_custom_new_subclass_result_preserves_effective_init_bug(
    tmp_path: Path,
) -> None:
    target = tmp_path / "custom_new_subclass_effective_init_bug.py"
    target.write_text(
        "class Base:\n"
        "    def __new__(cls, value: int) -> 'Child':\n"
        "        return Child(1)\n\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.denominator = 1\n\n"
        "class Child(Base):\n"
        "    def __new__(cls, value: int) -> 'Child':\n"
        "        return object.__new__(cls)\n\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.denominator = value\n\n"
        "def target() -> int:\n"
        "    return 10 // Base(0).denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_construction_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_custom_new_unresolved_subclass_relationship_degrades(tmp_path: Path) -> None:
    target = tmp_path / "custom_new_unresolved_subclass.py"
    target.write_text(
        "class Base:\n"
        "    def __new__(cls, value: int) -> 'Child':\n"
        "        return Child(0)\n\n"
        "class Child(Base if True else object):\n"
        "    def __new__(cls, value: int) -> 'Child':\n"
        "        return object.__new__(cls)\n\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.denominator = value\n\n"
        "def target() -> int:\n"
        "    return 10 // Base(1).denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_construction_protocol" in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_direct_object_new_allows_explicit_attribute_initialization(
    tmp_path: Path,
) -> None:
    target = tmp_path / "direct_object_new_attribute.py"
    target.write_text(
        "class Record:\n"
        "    def __init__(self) -> None:\n"
        "        self.denominator = 0\n\n"
        "def target() -> int:\n"
        "    obj = object.__new__(Record)\n"
        "    obj.denominator = 1\n"
        "    return 10 // obj.denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unmodeled_call_abstraction" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_direct_object_new_preserves_explicit_attribute_bug(tmp_path: Path) -> None:
    target = tmp_path / "direct_object_new_attribute_bug.py"
    target.write_text(
        "class Record:\n"
        "    def __init__(self) -> None:\n"
        "        self.denominator = 1\n\n"
        "def target() -> int:\n"
        "    obj = object.__new__(Record)\n"
        "    obj.denominator = 0\n"
        "    return 10 // obj.denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unmodeled_call_abstraction" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_direct_object_new_skips_init_effects(tmp_path: Path) -> None:
    target = tmp_path / "direct_object_new_skips_init.py"
    target.write_text(
        "class Record:\n"
        "    def __init__(self) -> None:\n"
        "        self.denominator = 1\n\n"
        "def target() -> int:\n"
        "    obj = object.__new__(Record)\n"
        "    return 10 // obj.denominator\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unmodeled_call_abstraction" not in result.degraded_passes
    assert any(issue.get("kind") == "ATTRIBUTE_ERROR" for issue in result.issues)
