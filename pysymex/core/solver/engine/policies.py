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

"""Caller-facing solver policy predicates."""

from __future__ import annotations

from collections.abc import Iterable

import z3

from pysymex.core.solver.engine.queries import check_sat_result


def path_may_be_feasible(
    constraints: Iterable[z3.BoolRef],
    *,
    known_sat_prefix_len: int | None = None,
) -> bool:
    """Return whether constraints are not established UNSAT.

    Exploration code uses this optimistic predicate: both SAT and UNKNOWN
    return ``True`` so feasible paths are not pruned on inconclusive solver
    answers. Call :func:`~pysymex.core.solver.engine.queries.check_sat_result`
    when UNKNOWN must not be treated as feasible.
    """
    result = check_sat_result(
        constraints,
        known_sat_prefix_len=known_sat_prefix_len,
    )
    return not result.is_unsat


__all__ = ["path_may_be_feasible"]
