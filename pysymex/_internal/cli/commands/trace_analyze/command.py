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

"""Trace analyzer CLI command parser and runtime handler."""

from __future__ import annotations

import argparse
import collections
import sys
from typing import TYPE_CHECKING, cast

from pysymex._internal.cli.commands.trace_analyze.context import add_system_context_arguments
from pysymex._internal.cli.commands.trace_analyze.deep import add_deep_arguments
from pysymex._internal.cli.commands.trace_analyze.issues import add_issue_arguments
from pysymex._internal.cli.commands.trace_analyze.keyframes import add_keyframe_arguments
from pysymex._internal.cli.commands.trace_analyze.output import add_output_arguments
from pysymex._internal.cli.commands.trace_analyze.routing import RoutingArguments
from pysymex._internal.cli.commands.trace_analyze.solve import SolveArguments
from pysymex._internal.cli.commands.trace_analyze.step import StepArguments
from pysymex._internal.cli.output import CliOutput
from pysymex._internal.tracing.analyzer.pipeline.builder import build_pipeline
from pysymex._internal.tracing.analyzer.stream.output import SummaryAccumulator, TraceEventFormat
from pysymex._internal.tracing.analyzer.stream.reader import TraceEvents

if TYPE_CHECKING:
    from pysymex._internal.cli.commands.registry import Subparsers
    from pysymex._internal.tracing.analyzer.pipeline.criteria import TraceFilterCriteria

_DESCRIPTION = (
    "Streaming filter CLI for PySyMex JSONL execution traces.\n\n"
    "Processes a trace one line at a time. All modes use O(1) memory except\n"
    "--tail N, which buffers the selected tail. Only events matching every\n"
    "active filter are emitted to stdout.\n\n"
    "Run --ai-manual to print the full Markdown trace-analyzer reference."
)


def add_trace_analyze_parser(subparsers: Subparsers) -> None:
    """Register the ``trace-analyze`` sub-command parser."""
    parser = subparsers.add_parser(
        "trace-analyze",
        prog="pysymex trace-analyze",
        usage="pysymex trace-analyze [options] [TRACE_FILE]",
        help="Filter and summarize JSONL execution traces",
        description=_DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_arguments(parser)


def build_parser() -> argparse.ArgumentParser:
    """Construct and return a standalone trace-analyzer argument parser.

    Every argument includes a help string explaining which event type the
    flag targets, what field it tests, and when to use it for diagnostics.
    """
    from pysymex._internal.cli.parser.builder import PysymexArgumentParser

    parser = PysymexArgumentParser(
        prog="pysymex trace-analyze",
        usage="pysymex trace-analyze [options] [TRACE_FILE]",
        description=_DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_arguments(parser)
    return parser


def _add_arguments(parser: argparse.ArgumentParser) -> None:
    """Register trace-analyzer options on *parser*."""
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
            "Print the full Markdown trace-analyzer reference. Includes a "
            "complete filter table and diagnostic recipes for common PySyMex "
            "engine issue classes. "
            "Bypasses all other flags and exits immediately after printing."
        ),
    )

    RoutingArguments.add(parser)
    StepArguments.add(parser)
    add_keyframe_arguments(parser)
    SolveArguments.add(parser)
    add_issue_arguments(parser)
    add_system_context_arguments(parser)
    add_deep_arguments(parser)
    add_output_arguments(parser)


def run_trace_analyze_command(args: argparse.Namespace) -> int:
    """Execute the ``trace-analyze`` sub-command."""
    if args.ai_manual:
        from pysymex._internal.tracing.analyzer.manual.text.content import AI_MANUAL

        CliOutput.safe_print(AI_MANUAL.rstrip())
        return 0
    return _run_stream(args)


def _run_stream(args: argparse.Namespace) -> int:
    """Execute the streaming filter loop for trace analyzer CLI arguments."""
    filter_config = cast("TraceFilterCriteria", args)
    pipeline = build_pipeline(filter_config)
    any_field_needle = filter_config.any_field_contains

    output_format: str = args.format
    fields: list[str] | None = (
        [f.strip() for f in args.fields.split(",") if f.strip()]
        if getattr(args, "fields", None)
        else None
    )
    head_limit: int | None = getattr(args, "head", None)
    tail_n: int | None = getattr(args, "tail", None)
    count_only: bool = getattr(args, "count", False)

    tail_buf: collections.deque[str] | None = (
        collections.deque(maxlen=tail_n) if tail_n is not None else None
    )

    summary = SummaryAccumulator() if output_format == "summary" else None
    matched = 0

    try:
        events = (
            TraceEvents.from_lines(
                sys.stdin,
                source="-",
                on_malformed_line=_warn_malformed_trace_line,
            )
            if args.input == "-"
            else TraceEvents.from_path(args.input, on_malformed_line=_warn_malformed_trace_line)
        )
        for raw_line, event in events:
            if any_field_needle is not None and any_field_needle not in raw_line:
                continue

            if not pipeline.matches(event):
                continue

            if output_format == "pretty":
                rendered = TraceEventFormat.pretty(event)
            elif fields is not None:
                rendered = TraceEventFormat.fields(event, fields)
            else:
                rendered = raw_line

            matched += 1

            if summary is not None:
                summary.record(event)
            elif count_only:
                _ = matched
            elif tail_buf is not None:
                tail_buf.append(rendered)
            else:
                CliOutput.safe_print(rendered.rstrip())

            if head_limit is not None and matched >= head_limit:
                break

    except BrokenPipeError:
        return 0
    except FileNotFoundError as exc:
        from pysymex._internal.logging.root import get_logger

        get_logger(__name__).error("Trace input not found: %s", exc)
        CliOutput.error(str(exc))
        return 1
    except KeyboardInterrupt:
        return 130

    if tail_buf is not None and not count_only and summary is None:
        for line in tail_buf:
            CliOutput.safe_print(line.rstrip())

    if count_only:
        CliOutput.safe_print(str(matched))
    elif summary is not None:
        CliOutput.safe_print(summary.render().rstrip())

    return 0


def _warn_malformed_trace_line(exc: object) -> None:
    CliOutput.warning(f"skipping malformed trace line: {exc}")
