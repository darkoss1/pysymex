"""Scanner regressions for bounded descriptor ``__set_name__`` state."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_executes_descriptor_with_synthesized_set_name(tmp_path: Path) -> None:
    target = tmp_path / "descriptor_set_name_setter.py"
    target.write_text(
        "class Value:\n"
        "    def __set_name__(self, owner, name) -> None:\n"
        "        self.name = name\n\n"
        "    def __set__(self, obj, value: int) -> None:\n"
        "        if self.name == 'value':\n"
        "            10 // value\n\n"
        "class Record:\n"
        "    value = Value()\n\n"
        "def target(value: int) -> None:\n"
        "    Record().value = value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(issue.get("kind") == "ATTRIBUTE_ERROR" for issue in result.issues)


def test_scan_file_executes_set_name_getter_and_setter_for_augmented_assignment(
    tmp_path: Path,
) -> None:
    target = tmp_path / "descriptor_set_name_augmented_assignment.py"
    target.write_text(
        "class Validated:\n"
        "    def __set_name__(self, owner, name) -> None:\n"
        "        self.name = name\n\n"
        "    def __get__(self, obj, owner) -> int:\n"
        "        return 1 if self.name == 'balance' else 2\n\n"
        "    def __set__(self, obj, value: int) -> None:\n"
        "        if self.name == 'balance':\n"
        "            10 // value\n\n"
        "class Account:\n"
        "    balance = Validated()\n\n"
        "def target(amount: int) -> None:\n"
        "    account = Account()\n"
        "    account.balance -= amount\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_executes_direct_owner_capture_in_set_name_descriptor(tmp_path: Path) -> None:
    target = tmp_path / "descriptor_set_name_owner.py"
    target.write_text(
        "class Value:\n"
        "    def __set_name__(self, owner, name) -> None:\n"
        "        self.owner = owner\n\n"
        "    def __get__(self, obj, owner) -> int:\n"
        "        return self.owner.zero\n\n"
        "class Record:\n"
        "    zero = 0\n"
        "    value = Value()\n\n"
        "def target() -> int:\n"
        "    return 10 // Record().value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" not in result.degraded_passes
    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(issue.get("kind") == "ATTRIBUTE_ERROR" for issue in result.issues)


def test_scan_file_degrades_computed_owner_state_in_set_name_descriptor(tmp_path: Path) -> None:
    target = tmp_path / "descriptor_set_name_computed_owner.py"
    target.write_text(
        "class Value:\n"
        "    def __set_name__(self, owner, name) -> None:\n"
        "        self.result = owner.zero\n\n"
        "    def __get__(self, obj, owner) -> int:\n"
        "        return self.result\n\n"
        "class Record:\n"
        "    zero = 0\n"
        "    value = Value()\n\n"
        "def target() -> int:\n"
        "    return 10 // Record().value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_degrades_computed_descriptor_constructor_state(tmp_path: Path) -> None:
    target = tmp_path / "descriptor_computed_constructor_state.py"
    target.write_text(
        "class Value:\n"
        "    def __init__(self, result: int) -> None:\n"
        "        self.result = result + 0\n\n"
        "    def __get__(self, obj, owner) -> int:\n"
        "        return self.result\n\n"
        "class Record:\n"
        "    value = Value(0)\n\n"
        "def target() -> int:\n"
        "    return 10 // Record().value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_descriptor_protocol" in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
