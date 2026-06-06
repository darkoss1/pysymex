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

"""Benchmark CLI command."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path
from typing import cast

from pysymex.cli.output import print_cli_error
from pysymex.logger import get_logger

_Namespace = argparse.Namespace
logger = get_logger(__name__)


def cmd_benchmark(args: _Namespace) -> int:
    """Execute the ``benchmark`` sub-command.

    Runs the built-in benchmark suite and writes results in the
    requested format.

    Args:
        args: Parsed CLI namespace with benchmark filtering and output options.

    Returns:
        ``0`` on success, ``1`` if regressions are detected.
    """
    from pysymex.benchmarks import run_benchmarks

    output_path = Path(args.output) if args.output else None
    baseline_path = Path(args.baseline) if args.baseline else None
    run_benchmarks_fn = cast("Callable[..., int]", run_benchmarks)
    logger.verbose(
        "Benchmark command started output=%s baseline=%s format=%s iterations=%s",
        output_path,
        baseline_path,
        args.format,
        args.iterations,
    )
    try:
        return run_benchmarks_fn(
            output_path=output_path,
            baseline_path=baseline_path,
            format=args.format,
            iterations=args.iterations,
            case_name=getattr(args, "case", None),
            mode=getattr(args, "mode", None),
            category=getattr(args, "category", None),
            warmup=getattr(args, "warmup", 1),
            list_cases=getattr(args, "list", False),
            threshold_percent=getattr(args, "threshold", 10.0),
        )
    except Exception as e:
        logger.warning("Benchmark command failed", exc_info=True)
        print_cli_error(f"running benchmarks: {e}")
        return 1


__all__ = ["cmd_benchmark"]
