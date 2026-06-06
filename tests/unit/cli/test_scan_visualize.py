from __future__ import annotations

import argparse
from pathlib import Path
from unittest.mock import patch

from pysymex.cli.scan.symbolic import handle_symbolic_scan
from pysymex.scanner.types import ScanResult


def test_visualize_symbolic_scan_forwards_canonical_scan_policy(tmp_path: Path) -> None:
    target = tmp_path / "sample.py"
    target.write_text("def f(value: int) -> int:\n    return value\n", encoding="utf-8")
    args = argparse.Namespace(
        path=str(target),
        format="json",
        output=None,
        verbose=False,
        recursive=False,
        visualize=True,
        stats=False,
        reproduce=False,
        max_paths=29,
        timeout=4.0,
        auto=True,
        no_sandbox=True,
        deterministic=False,
        seed=17,
        no_cache=True,
        max_iterations=13,
        trace=False,
        trace_output_dir=".pysymex/traces",
        trace_verbosity="full",
    )
    observed: dict[str, object] = {}

    def fake_realtime(path: Path, **kwargs: object) -> list[ScanResult]:
        observed["path"] = path
        observed.update(kwargs)
        return [ScanResult(file_path=str(path), timestamp="now")]

    with (
        patch("pysymex.reporting.realtime.run_realtime_scan", side_effect=fake_realtime),
        patch("pysymex.cli.scan.symbolic.emit_cli_output"),
    ):
        return_code = handle_symbolic_scan(args, target, 0.0)

    assert return_code == 0
    assert observed["path"] == target
    assert observed["max_paths"] == 29
    assert observed["timeout"] == 4.0
    assert observed["auto_tune"] is True
    assert observed["use_sandbox"] is False
    assert observed["deterministic_mode"] is True
    assert observed["random_seed"] == 17
    assert observed["no_cache"] is True
    assert observed["max_iterations"] == 13
    assert observed["trace_enabled"] is False
    assert observed["trace_verbosity"] == "full"
