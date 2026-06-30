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

"""Invocation-scoped path feasibility oracle for core semantic helpers."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Generator, Iterable

    import z3


class PathFeasibilityOracle(Protocol):
    """Decide whether a constraint set has not been proven infeasible."""

    def __call__(
        self,
        constraints: Iterable[z3.BoolRef],
        *,
        known_sat_prefix_len: int | None = None,
    ) -> bool: ...


_path_feasibility_oracle: ContextVar[PathFeasibilityOracle | None] = ContextVar(
    "path_feasibility_oracle",
    default=None,
)


@contextmanager
def bind_path_feasibility_oracle(
    oracle: PathFeasibilityOracle,
) -> Generator[None]:
    """Bind the execution-owned feasibility oracle for one semantic operation scope."""
    token = _path_feasibility_oracle.set(oracle)
    try:
        yield
    finally:
        _path_feasibility_oracle.reset(token)


def path_may_be_feasible(
    constraints: Iterable[z3.BoolRef],
    *,
    known_sat_prefix_len: int | None = None,
) -> bool:
    """Query the bound oracle, conservatively preserving unknown paths.

    Direct semantic-helper calls outside the execution dispatcher have no solver
    runtime. Such calls must not claim that a path is infeasible, so they return
    ``True``.
    """
    oracle = _path_feasibility_oracle.get()
    if oracle is None:
        return True
    return oracle(constraints, known_sat_prefix_len=known_sat_prefix_len)
