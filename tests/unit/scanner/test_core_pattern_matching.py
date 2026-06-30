"""Scanner regressions for bounded structural pattern matching."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def _issue_kinds_on_target_line(result: object, line: int) -> set[object]:
    issues = getattr(result, "issues")
    return {issue.get("kind") for issue in issues if issue.get("line") == line}


def test_scan_file_preserves_literal_tuple_pattern_zero_value(tmp_path: Path) -> None:
    target = tmp_path / "tuple_pattern_zero.py"
    target.write_text(
        "def target() -> int:\n"
        "    payload = ('fallback', 0)\n"
        "    match payload:\n"
        "        case ('fallback', value):\n"
        "            return 10 // value\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _issue_kinds_on_target_line(result, 5) == {"DIVISION_BY_ZERO"}


def test_scan_file_preserves_or_tuple_pattern_zero_value(tmp_path: Path) -> None:
    target = tmp_path / "or_tuple_pattern_zero.py"
    target.write_text(
        "def target() -> int:\n"
        "    payload = ('fallback', 0)\n"
        "    match payload:\n"
        "        case ('zero', value) | ('fallback', value):\n"
        "            return 10 // value\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _issue_kinds_on_target_line(result, 5) == {"DIVISION_BY_ZERO"}


def test_scan_file_retains_mapping_pattern_capture_type(tmp_path: Path) -> None:
    target = tmp_path / "mapping_pattern_zero.py"
    target.write_text(
        "def target() -> int:\n"
        "    payload = {'rate': 0}\n"
        "    match payload:\n"
        "        case {'rate': rate}:\n"
        "            return 10 // rate\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _issue_kinds_on_target_line(result, 5) == {"DIVISION_BY_ZERO"}


def test_scan_file_retains_class_pattern_capture_type(tmp_path: Path) -> None:
    target = tmp_path / "class_pattern_zero.py"
    target.write_text(
        "class Token:\n"
        "    __match_args__ = ('value',)\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "def target() -> int:\n"
        "    token = Token(0)\n"
        "    match token:\n"
        "        case Token(value):\n"
        "            return 10 // value\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _issue_kinds_on_target_line(result, 10) == {"DIVISION_BY_ZERO"}


def test_scan_file_match_class_property_value_error_propagates(
    tmp_path: Path,
) -> None:
    target = tmp_path / "class_pattern_property_value_error.py"
    target.write_text(
        "class Token:\n"
        "    __match_args__ = ('payload',)\n"
        "    @property\n"
        "    def payload(self) -> object:\n"
        "        raise ValueError('payload failed')\n\n"
        "def target() -> int:\n"
        "    token = Token()\n"
        "    match token:\n"
        "        case Token(payload):\n"
        "            return len(payload)\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert any(
        issue.get("kind") == "VALUE_ERROR"
        and "payload failed" in str(issue.get("message", ""))
        and issue.get("function_name") == "target"
        for issue in result.issues
    )
    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)


def test_scan_file_match_class_property_attribute_error_is_no_match(
    tmp_path: Path,
) -> None:
    target = tmp_path / "class_pattern_property_attribute_error.py"
    target.write_text(
        "class Token:\n"
        "    __match_args__ = ('payload',)\n"
        "    @property\n"
        "    def payload(self) -> object:\n"
        "        raise AttributeError('payload hidden')\n\n"
        "def target() -> int:\n"
        "    token = Token()\n"
        "    match token:\n"
        "        case Token(payload):\n"
        "            return len(payload)\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not any(
        issue.get("kind") in {"TYPE_ERROR", "UNHANDLED_EXCEPTION"}
        and issue.get("function") == "target"
        for issue in result.issues
    )


def test_scan_file_match_class_descriptor_callable_reports_attribute_error(
    tmp_path: Path,
) -> None:
    target = tmp_path / "class_pattern_descriptor_callable.py"
    target.write_text(
        "class ReaderDescriptor:\n"
        "    def __get__(self, instance: object, owner: type | None = None):\n"
        "        def read(name: str) -> int:\n"
        "            if name == 'missing':\n"
        "                raise AttributeError(name)\n"
        "            return 7\n"
        "        return read\n\n"
        "class Packet:\n"
        "    __match_args__ = ('payload', 'reader')\n"
        "    reader = ReaderDescriptor()\n"
        "    @property\n"
        "    def payload(self) -> tuple[int, int]:\n"
        "        return (1, 2)\n\n"
        "def target(mode: int) -> int:\n"
        "    packet = Packet()\n"
        "    match packet:\n"
        "        case Packet((left, right), reader) if left < right:\n"
        "            if mode == 7:\n"
        "                return reader('missing')\n"
        "            return reader('present')\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("line") == 5
        and issue.get("function_name") == "target"
        for issue in result.issues
    )
    assert "unmodeled_call_abstraction" not in result.degraded_passes
    assert "unsupported_vm_state" not in result.degraded_passes
