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

"""Issue event arguments for the trace analyzer CLI."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.cli.commands.trace_analyze.parsing import parse_confidence_range
from pysymex._internal.cli.commands.validation import non_negative_int

if TYPE_CHECKING:
    import argparse


def add_issue_arguments(parser: argparse.ArgumentParser) -> None:
    """Add CLI arguments for filtering issue events.

    Adds options to filter trace events representing detected bugs (such as
    severity levels, detector names, issue kinds, message contents, Z3 models,
    confidence ranges, source lines, and SMT constraints at the time of issue).

    Args:
        parser: The ArgumentParser instance to which arguments will be added.

    """
    issue_grp = parser.add_argument_group(
        "IssueEvent Filters (event_type=issue)",
        "Filters on detected-bug events emitted by analysis detectors.",
    )
    issue_grp.add_argument(
        "--severity",
        action="append",
        metavar="LEVEL",
        help=(
            "Keep issues at the given severity level.  "
            "Repeatable: --severity HIGH --severity CRITICAL.  "
            "Values: HIGH, MEDIUM, LOW, CRITICAL (case-insensitive).  "
            "Use --severity CRITICAL to focus on the most impactful findings."
        ),
    )
    issue_grp.add_argument(
        "--detector",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Keep issues from detectors whose detector_name contains NAME "
            "(case-sensitive substring match).  "
            "Example: --detector null-deref to see all null-dereference findings."
        ),
    )
    issue_grp.add_argument(
        "--issue-kind",
        type=str,
        default=None,
        metavar="KIND",
        help=(
            "Keep issues whose issue_kind field contains KIND (substring).  "
            "issue_kind is the canonical enum string (e.g. NULL_DEREF, "
            "INTEGER_OVERFLOW, DIVISION_BY_ZERO).  "
            "Use --issue-kind OVERFLOW to find all overflow variants."
        ),
    )
    issue_grp.add_argument(
        "--message-contains",
        type=str,
        default=None,
        metavar="TEXT",
        help=(
            "Keep issues whose human-readable message contains TEXT.  "
            "The message is written for human review; use this for quick "
            "keyword filtering without knowing the exact detector name."
        ),
    )
    issue_grp.add_argument(
        "--has-z3-model",
        action="store_true",
        default=False,
        help=(
            "Keep issues that have a concrete Z3 counterexample model (z3_model "
            "is not null).  A present z3_model means there is a definite "
            "exploitable input - these are the highest-confidence findings."
        ),
    )
    issue_grp.add_argument(
        "--z3-model-var",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Keep issues whose z3_model dict contains key NAME.  "
            "Use to find all bugs where a specific input variable (e.g. 'n', "
            "'user_id') appears in the triggering counterexample."
        ),
    )
    issue_grp.add_argument(
        "--confidence",
        type=parse_confidence_range,
        default=None,
        metavar="MIN:MAX",
        help=(
            "Keep issues whose confidence score is in [MIN, MAX].  "
            "Higher confidence (0.8-1.0) means the engine is highly certain "
            "it found a real bug.  Low confidence (0.1-0.5) usually indicates "
            "theoretical edge cases involving unconstrained parameters.  "
            "Use --confidence 0.8:1.0 to see only the most reliable findings."
        ),
    )
    issue_grp.add_argument(
        "--issue-source-line",
        type=non_negative_int,
        default=None,
        metavar="N",
        help=(
            "Keep issues detected at source line N (source_line field).  "
            "Use to find all detectors that fired at a particular location."
        ),
    )
    issue_grp.add_argument(
        "--constraint-at-issue-contains",
        type=str,
        default=None,
        metavar="TEXT",
        help=(
            "Keep issues where at least one constraint in constraints_at_issue "
            "has a SMT-LIB string containing TEXT.  "
            "Use to find bugs whose path-at-detection includes a specific "
            "expression, e.g. a known unsafe comparison."
        ),
    )
