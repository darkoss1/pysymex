from __future__ import annotations

import argparse
from pathlib import Path
from unittest.mock import patch

from pysymex._internal.cli.commands.scan.symbolic import handle_symbolic_scan
from pysymex._internal.scanner.types import ScanResult


def test_visualize_symbolic_scan_forwards_canonical_scan_policy(tmp_path: Path) -> None:
    target = tmp_path / "sample.py"
    target.write_text("def f(value: int) -> int:\n    return value\n", encoding="utf-8")
    args = argparse.Namespace(
        path=str(target),
        format="json",
        output=None,
        verbose=False,
        visualize=True,
        stats=False,
        reproduce=False,
        max_paths=29,
        max_depth=77,
        timeout=4.0,
        auto=True,
        no_sandbox=True,
        no_cache=True,
        detect_overflow=True,
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
        patch(
            "pysymex._internal.reporting.realtime.scan.run_realtime_scan", side_effect=fake_realtime
        ),
        patch("pysymex._internal.cli.commands.scan.symbolic.emit_cli_output"),
    ):
        return_code = handle_symbolic_scan(args, target, 0.0)

    assert return_code == 0
    assert observed["path"] == target
    assert observed["max_paths"] == 29
    assert observed["max_depth"] == 77
    assert observed["timeout"] == 4.0
    assert observed["auto_tune"] is True
    assert observed["use_sandbox"] is False
    assert observed["no_cache"] is True
    assert observed["detect_overflow"] is True
    assert observed["max_iterations"] == 13
    assert observed["trace_enabled"] is False
    assert observed["trace_verbosity"] == "full"
    assert callable(observed["open_url"])
    assert callable(observed["message_sink"])
