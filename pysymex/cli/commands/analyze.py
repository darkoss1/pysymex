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

"""Analyze CLI command."""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Callable

from pysymex.cli.output import emit_cli_output, print_cli_error
from pysymex.logger import get_logger
from pysymex.pathing import normalize_input_path

_Namespace = argparse.Namespace
logger = get_logger(__name__)


def cmd_analyze(args: _Namespace) -> int:
    """Execute the ``analyze`` sub-command for a single function.

    Args:
        args: Parsed CLI namespace with ``file``, ``function``,
            ``args``, ``format``, ``output``, ``max_paths``,
            ``timeout``, ``verbose``, and ``stats`` attributes.

    Returns:
        ``1`` if issues were found, ``0`` otherwise.
    """
    from pysymex.api import analyze_file
    from pysymex.cli.reporter import ConsoleScanReporter
    from pysymex.reporting.formatters import format_result

    filepath = normalize_input_path(str(args.file))
    if not filepath.exists():
        logger.warning("Analyze command target not found: %s", filepath)
        print_cli_error(f"File not found: {filepath}")
        return 1
    symbolic_args: dict[str, str] = {}
    if args.args:
        for arg in args.args:
            if ":" in arg:
                name, type_hint = arg.split(":", 1)
                symbolic_args[name.strip()] = type_hint.strip()

    show_stats = getattr(args, "stats", False)
    stats_stop: Callable[[], None] | None = None
    reporter = ConsoleScanReporter(show_stats=show_stats) if args.verbose else None

    if show_stats:
        from pysymex.stats import (
            enable_console_sink,
            start as stats_start,
            stop as imported_stats_stop,
        )

        enable_console_sink()
        stats_stop = imported_stats_stop
        stats_start()

    if args.verbose:
        print(f"[SCAN] Analyzing {args.function}() in {filepath}")
    logger.verbose("Analyze command started file=%s function=%s", filepath, args.function)
    try:
        result = asyncio.run(
            analyze_file(
                filepath=filepath,
                function_name=args.function,
                symbolic_args=symbolic_args,
                max_paths=args.max_paths,
                timeout=args.timeout,
                verbose=args.verbose,
                reporter=reporter,
                sandbox=True,
            )
        )
        output = format_result(result, args.format)
        if stats_stop is not None:
            stats_stop()
        emit_cli_output(output, output_path=args.output, verbose=args.verbose)
        return 1 if result.has_issues() else 0
    except (ValueError, TypeError, SyntaxError, OSError) as e:
        logger.warning("Analyze command failed for %s", filepath, exc_info=True)
        if stats_stop is not None:
            stats_stop()
        print_cli_error(f"analyzing {filepath}: {e}")
        return 1


__all__ = ["cmd_analyze"]
