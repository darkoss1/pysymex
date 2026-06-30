from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_max_depth_controls_depth_pruning(tmp_path: Path) -> None:
    target = tmp_path / "depth_case.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    total = 0\n"
        "    total += value + 1\n"
        "    total += value + 2\n"
        "    total += value + 3\n"
        "    total += value + 4\n"
        "    return total\n",
        encoding="utf-8",
    )

    shallow = scan_file(
        target,
        use_sandbox=False,
        trace_enabled=False,
        no_cache=True,
        max_paths=20,
        timeout=5,
        max_depth=2,
        max_iterations=200,
    )
    deep = scan_file(
        target,
        use_sandbox=False,
        trace_enabled=False,
        no_cache=True,
        max_paths=20,
        timeout=5,
        max_depth=200,
        max_iterations=200,
    )

    assert "resource_limit_depth" in shallow.degraded_passes
    assert "resource_limit_depth" not in deep.degraded_passes
    assert deep.error is None
