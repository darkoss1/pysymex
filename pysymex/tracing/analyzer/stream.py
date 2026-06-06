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

"""Streaming event reader, summary accumulator, and execution run loop."""

from __future__ import annotations

import argparse
import collections
import json
import sys
from collections.abc import Generator, Iterator

from pysymex.logger import get_logger
from pysymex.tracing.analyzer.pipeline import build_pipeline
from pysymex.tracing.analyzer.stream_output import (
    SummaryAccumulator,
    format_fields,
    format_pretty,
)

logger = get_logger(__name__)


def stream_events(
    path: str,
) -> Generator[tuple[str, dict[str, object]], None, None]:
    """Yield ``(raw_line, parsed_event)`` tuples from a JSONL trace file.

    The file is read one line at a time, ensuring O(1) heap allocation
    regardless of trace file size.  Blank lines are silently skipped.
    Lines that are not valid JSON emit a warning to *stderr* and are
    **skipped** — the stream never terminates on corrupt input.

    Args:
        path: Filesystem path to the ``.jsonl`` trace file, or ``"-"``
              to read from ``sys.stdin``.

    Yields:
        ``(raw_line, parsed_event)`` where *raw_line* is the untransformed
        UTF-8 string (used when ``--format jsonl`` re-emits the line
        unchanged) and *parsed_event* is the decoded JSON dict.
    """
    handle: Iterator[str]
    is_gz = str(path).endswith(".gz")

    if path == "-":
        handle = sys.stdin
    elif is_gz:
        import gzip

        handle = gzip.open(path, "rt", encoding="utf-8")
    else:
        handle = open(path, encoding="utf-8")

    try:
        for raw in handle:
            raw = raw.rstrip("\n\r")
            raw = raw.removeprefix("\ufeff")
            if not raw:
                continue
            try:
                event: dict[str, object] = json.loads(raw)
            except json.JSONDecodeError as exc:
                logger.warning("Skipping malformed trace line in %s: %s", path, exc)
                print(
                    f"[pysymex-trace-analyze] WARNING: skipping malformed line: {exc}",
                    file=sys.stderr,
                )
                continue
            yield raw, event
    finally:
        if path != "-":
            try:
                close_fn = getattr(handle, "close", None)
                if callable(close_fn):
                    close_fn()
            except Exception:
                logger.debug("Failed to close trace input stream %s", path, exc_info=True)


def run(args: argparse.Namespace) -> int:
    """Execute the streaming filter loop.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Unix exit code (0 = success, 1 = error).
    """
    pipeline = build_pipeline(args)
    any_field_needle: str | None = getattr(args, "any_field_contains", None)

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
        for raw_line, event in stream_events(args.input):
            if any_field_needle is not None and any_field_needle not in raw_line:
                continue

            if not pipeline.matches(event):
                continue

            if output_format == "pretty":
                rendered = format_pretty(event)
            elif fields is not None:
                rendered = format_fields(event, fields)
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
                print(rendered)
                if head_limit is not None and matched >= head_limit:
                    break

    except BrokenPipeError:
        return 0
    except FileNotFoundError as exc:
        logger.error("Trace input not found: %s", exc)
        print(f"[pysymex-trace-analyze] ERROR: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130

    if tail_buf is not None and not count_only and summary is None:
        for line in tail_buf:
            print(line)

    if count_only:
        print(matched)
    elif summary is not None:
        print(summary.render())

    return 0
