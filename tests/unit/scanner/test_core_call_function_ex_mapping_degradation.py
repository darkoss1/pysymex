"""Scanner regressions for unsupported modeled mapping-unpack protocols."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.core.classes.mapping_protocol.extraction import (
    UNSUPPORTED_MAPPING_PROTOCOL,
)
from pysymex._internal.scanner.file import scan_file


def test_scan_file_degrades_unrecognized_modeled_mapping_protocol(tmp_path: Path) -> None:
    target = tmp_path / "dict_unpack_unrecognized_mapping_protocol.py"
    target.write_text(
        "class DynamicItemMap:\n"
        "    def keys(self):\n"
        "        return ['a']\n"
        "    def __getitem__(self, key):\n"
        "        return len(key)\n\n"
        "class DynamicLookupMap:\n"
        "    def __getattr__(self, name):\n"
        "        if name == 'keys':\n"
        "            return lambda: ['a']\n"
        "        raise AttributeError(name)\n"
        "    def __getitem__(self, key):\n"
        "        return 1\n\n"
        "def dict_unpack_dynamic_item() -> dict:\n"
        "    return {**DynamicItemMap()}\n\n"
        "def dict_unpack_dynamic_lookup() -> dict:\n"
        "    return {**DynamicLookupMap()}\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert UNSUPPORTED_MAPPING_PROTOCOL in result.degraded_passes
    assert not any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") in {"dict_unpack_dynamic_item", "dict_unpack_dynamic_lookup"}
        for issue in result.issues
    )


def test_scan_file_suppresses_range_warning_after_mapping_protocol_degradation(
    tmp_path: Path,
) -> None:
    target = tmp_path / "dict_unpack_degraded_range_warning.py"
    target.write_text(
        "class DynamicItemMap:\n"
        "    def keys(self):\n"
        "        return []\n"
        "    def __getitem__(self, key):\n"
        "        return len(key)\n\n"
        "def target() -> int:\n"
        "    data = {**DynamicItemMap()}\n"
        "    denom = 0\n"
        "    if data:\n"
        "        return 1 // denom\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert UNSUPPORTED_MAPPING_PROTOCOL in result.degraded_passes
    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and str(issue.get("message", "")).startswith("[Value Range]")
        for issue in result.issues
    )
