"""Scanner regressions for sandboxed stdlib import precision."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def test_scan_file_sandbox_dynamic_import_os_getcwd_without_null_dereference(
    tmp_path: Path,
) -> None:
    target = tmp_path / "sandbox_dynamic_import_os.py"
    target.write_text(
        "def target() -> object:\n    module = __import__('os')\n    return module.getcwd()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=True)

    assert not any(issue.get("kind") == "NULL_DEREFERENCE" for issue in result.issues)
    assert "unmodeled_call_abstraction" not in result.degraded_passes


def test_scan_file_sandbox_static_import_os_getcwd_without_degradation(tmp_path: Path) -> None:
    target = tmp_path / "sandbox_static_import_os.py"
    target.write_text(
        "import os\n\ndef target() -> str:\n    return os.getcwd()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=True)

    assert result.issues == []
    assert "unmodeled_call_abstraction" not in result.degraded_passes
