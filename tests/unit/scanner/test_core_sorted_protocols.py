from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_sorted_local_objects_with_exact_lt_attribute(tmp_path: Path) -> None:
    target = tmp_path / "sorted_dunder_lt_attribute.py"
    target.write_text(
        "def target() -> int:\n"
        "    class Item:\n"
        "        def __init__(self, value: int):\n"
        "            self.value = value\n"
        "\n"
        "        def __lt__(self, other):\n"
        "            return self.value < other.value\n"
        "\n"
        "    values = sorted([Item(2), Item(1)])\n"
        "    result = values[0].value\n"
        "    assert result == 1\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind")
        in {
            "INDEX_ERROR",
            "ATTRIBUTE_ERROR",
            "TYPE_ERROR",
            "ASSERTION_ERROR",
            "NAME_ERROR",
            "UNBOUND_VARIABLE",
            "UNHANDLED_EXCEPTION",
        }
        for issue in result.issues
    )
    assert result.degraded_passes == []
