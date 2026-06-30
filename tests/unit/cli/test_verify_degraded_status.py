from __future__ import annotations

import argparse
from pathlib import Path
from unittest.mock import patch

from pysymex._internal.cli.commands.verify import cmd_verify
from pysymex._internal.execution.executors.verified.types import VerifiedExecutionResult


def test_verify_command_returns_failure_for_degraded_analysis(tmp_path: Path) -> None:
    target = tmp_path / "verify.py"
    target.write_text("def checked() -> int:\n    return 1\n", encoding="utf-8")
    args = argparse.Namespace(
        file=target,
        function="checked",
        _sandbox_dispatch=True,
        verbose=False,
        format="json",
        output=None,
    )
    result = VerifiedExecutionResult(degraded_passes=["solver_unknown_detector_query"])

    with (
        patch(
            "pysymex._internal.cli.commands.verify.load_function_for_cli", return_value=lambda: 1
        ),
        patch("pysymex._internal.cli.commands.verify._run_verified_execution", return_value=result),
        patch("pysymex._internal.cli.commands.verify.emit_cli_output"),
    ):
        assert cmd_verify(args) == 1
