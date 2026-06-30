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

"""Output-control arguments for the trace analyzer CLI."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.cli.commands.validation import positive_int

if TYPE_CHECKING:
    import argparse


def add_output_arguments(parser: argparse.ArgumentParser) -> None:
    """Add CLI arguments for output control.

    Adds options to configure the output format (JSONL, pretty-printed, or Markdown summary),
    limit the output size (using head or tail), output the total match count only, or extract
    specific top-level fields to reduce log verbosity.

    Args:
        parser: The ArgumentParser instance to which arguments will be added.

    """
    out_grp = parser.add_argument_group("Output Control")
    out_grp.add_argument(
        "--format",
        choices=["jsonl", "pretty", "summary"],
        metavar="FORMAT",
        default="jsonl",
        help=(
            "Output format for matched events.  "
            "jsonl (default): one JSON object per line, identical to input - "
            "suitable for piping to other tools.  "
            "pretty: two-space-indented JSON for human reading.  "
            "summary: print a Markdown table of per-event-type counts, "
            "first/last seq, solver outcomes, diagnostic uncertainty sites, "
            "fallback labels, and latency aggregates when available.  "
            "Use summary for compact review output."
        ),
    )
    out_grp.add_argument(
        "--head",
        type=positive_int,
        default=None,
        metavar="N",
        help=(
            "Stop after emitting the first N matched events.  "
            "O(1) memory - the stream is terminated early.  "
            "Use for fast sampling of the beginning of a trace."
        ),
    )
    out_grp.add_argument(
        "--tail",
        type=positive_int,
        default=None,
        metavar="N",
        help=(
            "Emit only the last N matched events after consuming the full stream.  "
            "NOTE: this buffers up to N rendered lines in memory (O(N)).  "
            "Use for sampling the end of a trace (where bugs often appear).  "
            "Mutually exclusive with streaming use cases: the full file must "
            "be consumed before output is emitted."
        ),
    )
    out_grp.add_argument(
        "--count",
        action="store_true",
        default=False,
        help=(
            "Print only the integer count of matched events, then exit.  "
            "No events are emitted.  Use for fast quantification before "
            "deciding which filter combination to use for full retrieval."
        ),
    )
    out_grp.add_argument(
        "--fields",
        type=str,
        default=None,
        metavar="F1,F2,...",
        help=(
            "Emit only the specified comma-separated top-level field names "
            "for each matched event.  "
            "Use to reduce high-volume trace output: "
            "--fields event_type,seq,path_id,severity,message.  "
            "Fields not present in a particular event type are silently omitted."
        ),
    )
