from __future__ import annotations

import argparse
from pathlib import Path
from unittest.mock import patch

from pysymex._internal.cli.commands.scan.symbolic import handle_symbolic_scan
from pysymex._internal.scanner.types import ScanResult


def test_symbolic_cli_returns_failure_for_error_result(tmp_path: Path) -> None:
    """Symbolic scan errors must produce a nonzero CLI result."""
    target = tmp_path / "broken.py"
    target.write_text("x = 1\n", encoding="utf-8")
    args = argparse.Namespace(
        verbose=False,
        visualize=False,
        max_paths=10,
        timeout=5.0,
        workers=1,
        auto=False,
        no_cache=False,
        max_iterations=0,
        trace=False,
        trace_output_dir=".pysymex/traces",
        trace_verbosity="delta_only",
        format="json",
        stats=False,
        reproduce=False,
        output=None,
    )
    failed_result = ScanResult(file_path=str(target), timestamp="now", error="Syntax Error")

    with (
        patch(
            "pysymex._internal.cli.commands.scan.symbolic.call_with_supported_kwargs",
            return_value=failed_result,
        ),
        patch("pysymex._internal.cli.commands.scan.symbolic.emit_cli_output"),
    ):
        assert handle_symbolic_scan(args, target, 0.0) == 1


def test_symbolic_cli_returns_success_for_degraded_no_issue_result(tmp_path: Path) -> None:
    target = tmp_path / "degraded.py"
    target.write_text("x = 1\n", encoding="utf-8")
    args = argparse.Namespace(
        verbose=False,
        visualize=False,
        max_paths=10,
        timeout=5.0,
        workers=1,
        auto=False,
        no_cache=False,
        max_iterations=0,
        trace=False,
        trace_output_dir=".pysymex/traces",
        trace_verbosity="delta_only",
        format="json",
        stats=False,
        reproduce=False,
        output=None,
    )
    degraded_result = ScanResult(
        file_path=str(target),
        timestamp="now",
        degraded_passes=["solver_unknown_detector_query"],
    )

    with (
        patch(
            "pysymex._internal.cli.commands.scan.symbolic.call_with_supported_kwargs",
            return_value=degraded_result,
        ),
        patch("pysymex._internal.cli.commands.scan.symbolic.emit_cli_output"),
    ):
        assert handle_symbolic_scan(args, target, 0.0) == 0
