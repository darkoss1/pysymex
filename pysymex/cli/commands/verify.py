# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Contract verification CLI command."""

from __future__ import annotations

import argparse
import time
from collections.abc import Callable
from typing import cast

from pysymex.cli.commands.shared import (
    VerifiedConfigFactory,
    VerifiedExecutionResultProtocol,
    VerifiedExecutorFactory,
    emit_preview_warning,
    load_function_for_cli,
    run_cli_command_sandboxed,
)
from pysymex.cli.output import emit_cli_output, print_cli_error
from pysymex.logger import get_logger
from pysymex.pathing import normalize_input_path

_Namespace = argparse.Namespace
logger = get_logger(__name__)


def cmd_verify(args: _Namespace) -> int:
    """Execute verify command for contracts.

    Uses VerifiedExecutor for symbolic execution with full contract verification
    (preconditions, postconditions, invariants, termination).
    """
    filepath = normalize_input_path(str(args.file))
    if not filepath.exists():
        logger.warning("Verify command target not found: %s", filepath)
        print_cli_error(f"File not found: {filepath}")
        return 1

    emit_preview_warning(
        args,
        "Contract verification is in preview; results may be incomplete or inaccurate.",
    )

    # Only dispatch to sandbox path if sandbox is enabled and not already dispatched
    if not getattr(args, "_sandbox_dispatch", False):
        return run_cli_command_sandboxed("verify", args)

    try:
        from pysymex.execution.executors.verified.executor import VerifiedExecutor
        from pysymex.execution.executors.verified.types import VerifiedExecutionConfig
    except ImportError:
        logger.warning("VerifiedExecutor unavailable for verify command", exc_info=True)
        print_cli_error("VerifiedExecutor not available")
        return 1

    try:
        start_time = time.time()
        logger.verbose("Verify command started file=%s function=%s", filepath, args.function)

        results: list[VerifiedExecutionResultProtocol] = []
        execution_failed = False
        if args.function:
            func = load_function_for_cli(
                filepath,
                str(args.function),
            )
            result = _run_verified_execution(
                func,
                args,
                cast(VerifiedExecutorFactory, VerifiedExecutor),
                cast(VerifiedConfigFactory, VerifiedExecutionConfig),
            )
            if result is None:
                execution_failed = True
            else:
                results.append(result)
        else:
            print_cli_error("Sandboxed verify requires --function.")
            return 1

        total_findings = sum(
            len(result.issues) + len(result.contract_issues) + len(result.arithmetic_issues)
            for result in results
        )
        analysis_degraded = any(result.degraded_passes for result in results)
        duration = time.time() - start_time

        from pysymex.cli.formatters import get_formatter

        formatter = get_formatter(str(getattr(args, "format", "text")))
        output = formatter.format_verify(results, total_findings, duration)
        emit_cli_output(
            output,
            output_path=getattr(args, "output", None),
            verbose=bool(getattr(args, "verbose", False)),
        )
        return 1 if execution_failed or total_findings > 0 or analysis_degraded else 0

    except Exception as e:
        logger.warning("Verify command failed for %s", filepath, exc_info=True)
        print_cli_error(f"verifying {filepath}: {e}")
        return 1


def _run_verified_execution(
    func: Callable[..., object],
    args: _Namespace,
    executor_cls: VerifiedExecutorFactory,
    config_cls: VerifiedConfigFactory | None,
) -> VerifiedExecutionResultProtocol | None:
    """Run :class:`VerifiedExecutor` on *func*.

    Called internally by :func:`cmd_verify` to perform symbolic-execution verification.

    Args:
        func: The Python function to verify.
        args: Parsed CLI namespace (used for ``verbose``).
        executor_cls: The ``VerifiedExecutor`` class.
        config_cls: The ``VerifiedExecutionConfig`` class.

    Returns:
        Verification result, or ``None`` when verification could not run.
    """
    try:
        if config_cls is None:
            logger.warning("Verified execution skipped for %s; config class missing", func.__name__)
            return None

        symbolic_args: dict[str, str] = {}
        if getattr(args, "args", None):
            for arg in args.args:
                if ":" in arg:
                    name, type_hint = arg.split(":", 1)
                    symbolic_args[name.strip()] = type_hint.strip()

        config = config_cls(
            check_preconditions=True,
            check_postconditions=True,
            check_termination=True,
            check_division_safety=True,
            verbose=getattr(args, "verbose", False),
            max_paths=200,
            max_iterations=2000,
            symbolic_args=symbolic_args,
        )
        executor = executor_cls(config)
        return executor.execute_function(func, symbolic_args=symbolic_args)
    except Exception as e:
        logger.warning("Verified execution failed for %s", func.__name__, exc_info=True)
        if getattr(args, "verbose", False):
            print_cli_error(f"VerifiedExecutor failed for {func.__name__}: {e}")
        return None


__all__ = ["cmd_verify"]
