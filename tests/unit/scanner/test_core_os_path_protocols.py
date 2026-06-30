"""Scanner regressions for stdlib os.path protocol precision."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_os_path_join_literals_without_null_dereference(tmp_path: Path) -> None:
    target = tmp_path / "os_path_join_literals.py"
    target.write_text(
        "def target() -> str:\n"
        "    import os\n"
        "\n"
        '    result = os.path.join("a", "b")\n'
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"NULL_DEREFERENCE", "TYPE_ERROR", "ATTRIBUTE_ERROR", "NAME_ERROR"}
        for issue in result.issues
    )
    assert "unmodeled_call_abstraction" not in result.degraded_passes
