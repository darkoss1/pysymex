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

"""Common event routing arguments for the trace analyzer CLI."""

from __future__ import annotations

import argparse

from pysymex.tracing.analyzer.cli.parsing import (
    parse_path_id_list,
    parse_pc_range,
    parse_seq_range,
)


def add_routing_arguments(parser: argparse.ArgumentParser) -> None:
    """Add CLI arguments for routing trace events.

    Adds options to filter trace events based on common routing fields such as event type,
    sequence numbers (exact or ranges), path IDs (single or comma-separated lists), and
    program counters (exact or ranges).

    Args:
        parser: The ArgumentParser instance to which arguments will be added.
    """
    routing = parser.add_argument_group(
        "Event Routing",
        "Filters that match on fields common to all event types.",
    )
    routing.add_argument(
        "--event-type",
        "-e",
        dest="event_type",
        action="append",
        metavar="TYPE",
        choices=[
            "step",
            "keyframe",
            "solve",
            "detector_query",
            "path_feasibility",
            "scheduler",
            "fallback",
            "issue",
            "system_context",
        ],
        help=(
            "Keep only events of TYPE. Repeatable: "
            "`-e step -e solve` keeps both step and solve events. "
            "Values: step, keyframe, solve, detector_query, path_feasibility, "
            "scheduler, fallback, issue, system_context. "
            "Use `--event-type keyframe` to focus on fork/prune/issue snapshots "
            "without the high-volume delta noise."
        ),
    )
    routing.add_argument(
        "--seq",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep the single event whose seq == N. Useful for pinpointing an "
            "exact event from a seq number seen in a summary or issue report."
        ),
    )
    routing.add_argument(
        "--seq-range",
        type=parse_seq_range,
        default=None,
        metavar="START:END",
        help=(
            "Keep events with seq in the inclusive range [START, END].  "
            "Use this to isolate a time window around a known bad event "
            "(e.g. --seq-range 1000:1050 to see the 50 events around seq 1025)."
        ),
    )
    routing.add_argument(
        "--path-id",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep only events belonging to execution path N.  "
            "path_id is assigned at fork time and is stable for the lifetime of "
            "the path.  Use this to replay the full history of a single path."
        ),
    )
    routing.add_argument(
        "--path-id-list",
        type=parse_path_id_list,
        default=None,
        metavar="N,N,...",
        help=(
            "Keep events for any of the comma-separated path IDs.  "
            "Use this when you want to compare two sibling paths produced by a fork."
        ),
    )
    routing.add_argument(
        "--pc",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep only events at program counter N.  "
            "pc is the bytecode offset of the instruction being executed.  "
            "Use this to find all events associated with a specific bytecode instruction."
        ),
    )
    routing.add_argument(
        "--pc-range",
        type=parse_pc_range,
        default=None,
        metavar="START:END",
        help=(
            "Keep events at PC in the inclusive range [START, END].  "
            "Use to focus on a specific function body or loop."
        ),
    )


__all__ = ["add_routing_arguments"]
