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

"""Command line parser construction and entry point functions."""

from __future__ import annotations

import argparse
import sys

from pysymex.tracing.analyzer.cli.context import add_system_context_arguments
from pysymex.tracing.analyzer.cli.deep import add_deep_arguments
from pysymex.tracing.analyzer.cli.issues import add_issue_arguments
from pysymex.tracing.analyzer.cli.keyframes import add_keyframe_arguments
from pysymex.tracing.analyzer.cli.output import add_output_arguments
from pysymex.tracing.analyzer.cli.parsing import (
    parse_confidence_range,
    parse_path_id_list,
    parse_pc_range,
    parse_seq_range,
)
from pysymex.tracing.analyzer.cli.routing import add_routing_arguments
from pysymex.tracing.analyzer.cli.solve import add_solve_arguments
from pysymex.tracing.analyzer.cli.step import add_step_arguments
from pysymex.tracing.analyzer.manual import print_ai_manual
from pysymex.tracing.analyzer.stream import run


def build_parser() -> argparse.ArgumentParser:
    """Construct and return the fully-configured CLI :class:`ArgumentParser`.

    Every argument includes a `help` string written for both human and LLM
    consumers, explaining *which event type* the flag targets, *what field*
    it tests, and *when* to use it for engine diagnostics.
    """
    parser = argparse.ArgumentParser(
        prog="pysymex-trace-analyze",
        description=(
            "Streaming Omni-Filter CLI for pysymex JSONL execution trace files.\n\n"
            "Processes the trace file line-by-line (O(1) memory for all modes except "
            "--tail N) and applies a composable filter pipeline. Only lines matching "
            "ALL active filters are emitted to stdout.\n\n"
            "Run --ai-manual to print a full Markdown reference for LLM agents."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "input",
        nargs="?",
        default="-",
        metavar="TRACE_FILE",
        help=(
            "Path to the .jsonl trace file produced by pysymex ExecutionTracer, "
            "or '-' (default) to read from stdin. The file is processed one line "
            "at a time so files of any size are supported."
        ),
    )

    parser.add_argument(
        "--ai-manual",
        action="store_true",
        default=False,
        help=(
            "Print a richly formatted Markdown document designed as a "
            "Prompt/Context for LLM agents (Gemini, GPT-4o, Claude, etc.). "
            "Includes a complete filter reference table and 8 Diagnostic Recipes "
            "for common pysymex engine bug classes. "
            "Bypasses all other flags and exits immediately after printing."
        ),
    )

    add_routing_arguments(parser)
    add_step_arguments(parser)
    add_keyframe_arguments(parser)
    add_solve_arguments(parser)
    add_issue_arguments(parser)
    add_system_context_arguments(parser)
    add_deep_arguments(parser)
    add_output_arguments(parser)

    return parser


def main(argv: list[str] | None = None) -> None:
    """CLI entry point.  Registered as ``pysymex-trace-analyze`` console script.

    Args:
        argv: Argument vector.  ``None`` means ``sys.argv[1:]``.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.ai_manual:
        print_ai_manual()
        sys.exit(0)

    sys.exit(run(args))


__all__ = [
    "parse_confidence_range",
    "parse_path_id_list",
    "parse_pc_range",
    "parse_seq_range",
    "build_parser",
    "main",
]
