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

"""System-context event arguments for the trace analyzer CLI."""

from __future__ import annotations

import argparse


def add_system_context_arguments(parser: argparse.ArgumentParser) -> None:
    """Add CLI arguments for filtering system context metadata events.

    Adds options to filter trace events based on the static analysis-session metadata
    (e.g., target function name, source file path, pysymex version, and Z3 version).

    Args:
        parser: The ArgumentParser instance to which arguments will be added.
    """
    ctx_grp = parser.add_argument_group(
        "SystemContextEvent Filters (event_type=system_context)",
        "Filters on the static analysis-session metadata event (first line of every trace).",
    )
    ctx_grp.add_argument(
        "--function-name",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Keep system_context events whose function_name contains NAME.  "
            "Useful when querying a concatenated multi-analysis trace file."
        ),
    )
    ctx_grp.add_argument(
        "--source-file",
        type=str,
        default=None,
        metavar="PATH",
        help=(
            "Keep system_context events for a specific source file "
            "(substring match on source_file).  "
            "Use to filter a multi-trace log to a specific module."
        ),
    )
    ctx_grp.add_argument(
        "--pysymex-version",
        type=str,
        default=None,
        metavar="VER",
        help=(
            "Keep system_context events for an exact pysymex version string.  "
            "Use to separate traces from different versions of the engine in "
            "a benchmark or regression run."
        ),
    )
    ctx_grp.add_argument(
        "--z3-version",
        type=str,
        default=None,
        metavar="VER",
        help=(
            "Keep system_context events for an exact Z3 version string.  "
            "Use to isolate version-specific solver behavior in benchmarks."
        ),
    )


__all__ = ["add_system_context_arguments"]
