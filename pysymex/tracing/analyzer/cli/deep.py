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

"""Deep semantic arguments for the trace analyzer CLI."""

from __future__ import annotations

import argparse


def add_deep_arguments(parser: argparse.ArgumentParser) -> None:
    """Add CLI arguments for deep/semantic cross-event trace filtering.

    Adds options to perform complex recursive searches across fields (such as
    locating variable names in variables/memory/Z3 models or searching for sub-expressions
    within SMT-LIB constraint sets).

    Args:
        parser: The ArgumentParser instance to which arguments will be added.
    """
    deep_grp = parser.add_argument_group(
        "Deep / Semantic Filters (cross-event)",
        (
            "Slower recursive searches across multiple fields.  Add these "
            "after cheap routing filters to minimize work per line."
        ),
    )
    deep_grp.add_argument(
        "--touches-var",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Keep any event where the string NAME appears in ANY of: "
            "stack elements, local_vars keys/values, global_vars keys/values, "
            "mem_diff keys/values, model_excerpt keys/values, z3_model "
            "keys/values, initial_symbolic_args keys/values.  "
            "This is the most powerful filter for tracking a symbolic variable "
            "through its entire lifetime across all event types.  "
            "Tip: combine with --path-id to restrict the search to one path."
        ),
    )
    deep_grp.add_argument(
        "--constraint-contains",
        type=str,
        default=None,
        metavar="TEXT",
        help=(
            "Keep any event where TEXT appears in ANY constraint SMT-LIB string: "
            "constraint_added.smtlib (step), path_constraints[*].smtlib (keyframe), "
            "constraint_excerpt[*].smtlib (detector_query), "
            "query_constraint_excerpt[*].smtlib (path_feasibility), "
            "or constraints_at_issue[*].smtlib (issue).  "
            "Use to find where a specific sub-expression first enters the "
            "constraint set and where it drives infeasibility or bug detection."
        ),
    )
    deep_grp.add_argument(
        "--any-field-contains",
        type=str,
        default=None,
        metavar="TEXT",
        help=(
            "Keep any event whose raw JSON line string contains TEXT.  "
            "This is the fastest full-text search option because it operates "
            "on the raw string before JSON parsing.  "
            "Use when you don't know which field a value might appear in.  "
            "Tip: quote values containing spaces: --any-field-contains '\"x\"'."
        ),
    )


__all__ = ["add_deep_arguments"]
