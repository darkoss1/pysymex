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

"""Step-delta event arguments for the trace analyzer CLI."""

from __future__ import annotations

import argparse


def add_step_arguments(parser: argparse.ArgumentParser) -> None:
    """Add CLI arguments for filtering step-delta events.

    Adds options to filter trace events representing instruction-level execution steps
    (including opcode name, source line, stack push/pop changes, variable additions/modifications/removals,
    memory writes, and path constraint additions).

    Args:
        parser: The ArgumentParser instance to which arguments will be added.
    """
    step_grp = parser.add_argument_group(
        "StepDeltaEvent Filters (event_type=step)",
        "Filters on incremental instruction-level diff events.",
    )
    step_grp.add_argument(
        "--opcode",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Keep step events for a specific Python bytecode opcode name "
            "(e.g. LOAD_ATTR, BINARY_OP, CALL, POP_JUMP_IF_FALSE).  "
            "Case-insensitive.  Use this to count how many times a given "
            "instruction executes on a path, or to find where attribute "
            "accesses on a symbolic object start diverging."
        ),
    )
    step_grp.add_argument(
        "--source-line",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Keep step events that map to source line N.  "
            "Requires FULL or DELTA_ONLY verbosity (source_line is None in QUIET mode).  "
            "Use to correlate a bytecode offset back to the Python source."
        ),
    )
    step_grp.add_argument(
        "--step-latency-min",
        type=float,
        default=None,
        metavar="MS",
        help=(
            "Keep step events whose measured instruction dispatch latency is >= MS. "
            "Use this to find slow opcodes or source lines in VM execution."
        ),
    )
    step_grp.add_argument(
        "--step-latency-max",
        type=float,
        default=None,
        metavar="MS",
        help=(
            "Keep step events whose measured instruction dispatch latency is <= MS. "
            "Use this with --opcode or --source-line to compare hot path costs."
        ),
    )
    step_grp.add_argument(
        "--has-stack-push",
        action="store_true",
        default=False,
        help=(
            "Keep step events where at least one symbolic value was pushed "
            "onto the stack (stack_diff.pushed is non-empty).  "
            "Use to trace where new symbolic expressions are introduced."
        ),
    )
    step_grp.add_argument(
        "--has-stack-pop",
        action="store_true",
        default=False,
        help=(
            "Keep step events where at least one value was popped from the stack "
            "(stack_diff.popped > 0).  Useful for spotting unbalanced stack operations."
        ),
    )
    step_grp.add_argument(
        "--has-var-modified",
        action="store_true",
        default=False,
        help=(
            "Keep step events that modified at least one existing local variable "
            "(var_diff.modified is non-empty).  "
            "Use to find where a known variable's symbolic value changes."
        ),
    )
    step_grp.add_argument(
        "--var-modified-name",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Keep step events that modified the local variable NAME "
            "(exact key match in var_diff.modified).  "
            "Use to trace the full mutation history of a specific variable."
        ),
    )
    step_grp.add_argument(
        "--has-var-added",
        action="store_true",
        default=False,
        help=(
            "Keep step events that introduced a new local variable (var_diff.added is non-empty)."
        ),
    )
    step_grp.add_argument(
        "--var-added-name",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Keep step events where the specific local variable NAME was "
            "first introduced (key in var_diff.added).  "
            "Use to find where a symbolic variable enters scope."
        ),
    )
    step_grp.add_argument(
        "--has-var-removed",
        action="store_true",
        default=False,
        help=(
            "Keep step events that deleted a local variable "
            "(var_diff.removed is non-empty, e.g. from a `del` statement)."
        ),
    )
    step_grp.add_argument(
        "--var-removed-name",
        type=str,
        default=None,
        metavar="NAME",
        help=(
            "Keep step events that deleted the specific local variable NAME "
            "(exact match in var_diff.removed list)."
        ),
    )
    step_grp.add_argument(
        "--has-mem-write",
        action="store_true",
        default=False,
        help=(
            "Keep step events that wrote to the symbolic memory model "
            "(mem_diff is non-empty).  "
            "NOTE: mem_diff is only populated when TracerConfig.verbosity=FULL.  "
            "Use to detect unexpected writes to symbolic addresses."
        ),
    )
    step_grp.add_argument(
        "--has-constraint-added",
        action="store_true",
        default=False,
        help=(
            "Keep step events where a new path constraint was added "
            "(constraint_added is not null).  "
            "A new constraint means a conditional branch was taken.  "
            "Use to measure constraint accumulation rate on a path."
        ),
    )
    step_grp.add_argument(
        "--constraint-causality-contains",
        type=str,
        default=None,
        metavar="TEXT",
        help=(
            "Keep step events where the causality annotation of the newly added "
            "constraint contains TEXT.  "
            "causality encodes 'OPCODE at PC=N' — e.g. use "
            "'POP_JUMP_IF_FALSE' to find all taken conditional branches."
        ),
    )


__all__ = ["add_step_arguments"]
