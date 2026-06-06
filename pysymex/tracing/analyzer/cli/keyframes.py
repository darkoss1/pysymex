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

"""Keyframe event arguments for the trace analyzer CLI."""

from __future__ import annotations

import argparse


def add_keyframe_arguments(parser: argparse.ArgumentParser) -> None:
    """Add CLI arguments for filtering keyframe events.

    Adds options to filter trace events representing engine state snapshots (including
    trigger type, call depth, parent path ID, prune reasons, variables in scope,
    accumulated path constraints, and stack contents).

    Args:
        parser: The ArgumentParser instance to which arguments will be added.
    """
    kf_grp = parser.add_argument_group(
        "KeyframeEvent Filters (event_type=keyframe)",
        "Filters on full-state snapshot events emitted at fork, prune, and issue time.",
    )
    kf_grp.add_argument(
        "--trigger",
        type=str,
        default=None,
        choices=["fork", "prune", "issue"],
        help=(
            "Keep keyframes triggered by a specific engine event.  "
            "fork: path split (state space branching).  "
            "prune: path terminated (infeasible, resource limit, duplicate).  "
            "issue: bug detected.  "
            "Use --trigger fork to study path explosion; "
            "--trigger prune to audit path termination decisions."
        ),
    )
    kf_grp.add_argument(
        "--depth",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep keyframes at exactly call/loop depth N.  "
            "depth tracks nesting level of the current execution frame.  "
            "Use for targeted depth-budget analysis."
        ),
    )
    kf_grp.add_argument(
        "--depth-min",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep keyframes at depth >= N.  "
            "Use --depth-min 50 to find deep paths which are the primary "
            "driver of path explosion in recursive or loop-heavy functions."
        ),
    )
    kf_grp.add_argument(
        "--depth-max",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep keyframes at depth <= N.  "
            "Use to restrict analysis to a shallow portion of the call stack, "
            "e.g. to test whether top-level branches are being explored."
        ),
    )
    kf_grp.add_argument(
        "--parent-path-id",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep keyframes whose parent execution path ID is N.  "
            "Use to find all children of a specific fork and reconstruct "
            "the local fork tree topology."
        ),
    )
    kf_grp.add_argument(
        "--has-child-fork",
        action="store_true",
        default=False,
        help=(
            "Keep fork keyframes that produced at least one child path "
            "(child_path_ids is non-empty).  This always should be true for "
            "trigger=fork, but can be used to verify the tree is well-formed."
        ),
    )
    kf_grp.add_argument(
        "--prune-reason",
        type=str,
        default=None,
        metavar="TEXT",
        help=(
            "Keep prune keyframes whose prune_reason string contains TEXT.  "
            "Known reasons: 'infeasible', 'duplicate_state', 'resource_limit', "
            "'depth_limit', 'loop_bound'.  "
            "Use --prune-reason infeasible to audit false-unsat decisions."
        ),
    )
    kf_grp.add_argument(
        "--stack-contains",
        type=str,
        default=None,
        metavar="TEXT",
        help=(
            "Keep keyframes where at least one element of the symbolic stack "
            "(as a string) contains TEXT.  "
            "Use to find states where a specific symbolic expression is on the "
            "top of the stack, e.g. a function return value."
        ),
    )
    kf_grp.add_argument(
        "--local-var-name",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Keep keyframes where the local variable NAME is present in "
            "local_vars.  Use to find all states where a variable is in scope."
        ),
    )
    kf_grp.add_argument(
        "--global-var-name",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Keep keyframes where the global variable NAME is present in "
            "global_vars.  Only populated in FULL and DELTA_ONLY verbosity modes."
        ),
    )
    kf_grp.add_argument(
        "--constraint-smtlib-contains",
        type=str,
        default=None,
        metavar="TEXT",
        help=(
            "Keep keyframes where at least one path constraint's SMT-LIB "
            "string contains TEXT.  "
            "Use to find states where a specific sub-expression has been "
            "constrained, e.g. --constraint-smtlib-contains 'bvslt' to find "
            "states with signed integer comparison constraints."
        ),
    )
    kf_grp.add_argument(
        "--num-path-constraints-min",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep keyframes with at least N accumulated path constraints.  "
            "Use with --trigger prune to find infeasible paths that had very "
            "complex constraint sets — candidates for over-approximation bugs."
        ),
    )
    kf_grp.add_argument(
        "--num-path-constraints-max",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep keyframes with at most N accumulated path constraints.  "
            "Use to study early-path behavior before constraints accumulate."
        ),
    )


__all__ = ["add_keyframe_arguments"]
