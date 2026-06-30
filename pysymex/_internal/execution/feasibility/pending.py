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

"""Pending path-constraint policy for execution feasibility checks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.solver.constraints.literals import exact_bool_literal

if TYPE_CHECKING:
    import z3

    from pysymex._internal.core.state.record import VMState


def should_check_pending_constraints(*, state: VMState, lazy_eval_threshold: int) -> bool:
    """Return whether a path has enough pending constraints to force a solver check."""
    return (
        state.pending_constraint_count > 0
        and state.pending_constraint_count >= lazy_eval_threshold
        and len(state.path_constraints) != state.last_inconclusive_feasibility_len
    )


def record_pending_constraints_checked(state: VMState) -> None:
    """Record that pending path constraints have been checked by the solver boundary."""
    state.pending_constraint_count = 0


def normalize_pending_suffix(
    constraints: list[z3.BoolRef],
    known_prefix_len: int,
) -> tuple[list[z3.BoolRef], int, bool | None]:
    """Strip exact Boolean tautologies from pending constraints before SAT checks."""
    prefix = constraints[:known_prefix_len]
    suffix = constraints[known_prefix_len:]
    if not suffix:
        return constraints, known_prefix_len, True

    query_suffix: list[z3.BoolRef] = []
    for constraint in suffix:
        literal = exact_bool_literal(constraint)
        if literal is False:
            return constraints, known_prefix_len, False
        if literal is not True:
            query_suffix.append(constraint)
    if not query_suffix:
        return prefix, len(prefix), True
    return [*prefix, *query_suffix], len(prefix), None
