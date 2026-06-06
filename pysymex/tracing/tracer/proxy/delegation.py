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

"""Delegating methods for the tracing solver proxy."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.core.solver.engine.results import SolverResult

if TYPE_CHECKING:
    from pysymex.typing import SolverProtocol


class SolverDelegationMixin:
    """Delegate non-instrumented solver operations to the wrapped solver."""

    def _inner_solver(self) -> SolverProtocol:
        """Retrieve the underlying solver instance wrapped by this proxy.

        Accesses the raw solver object bypassing dynamic attribute delegation.

        Returns:
            The inner SolverProtocol instance that receives delegated solver commands.
        """
        return object.__getattribute__(self, "_inner")

    def push(self) -> None:
        """Push a new backtracking level on the inner solver context.

        Saves the current state of the solver constraints stack.
        """
        self._inner_solver().push()

    def pop(self) -> None:
        """Pop a backtracking level from the inner solver context.

        Restores the solver state to the previous push checkpoint.
        """
        self._inner_solver().pop()

    def add(self, *constraints: z3.BoolRef) -> None:
        """Add constraints to the inner solver context.

        Passes the symbolic boolean expressions to the wrapped solver.

        Args:
            *constraints: Z3 boolean expressions to restrict the search space.
        """
        self._inner_solver().add(*constraints)

    def reset(self) -> None:
        """Reset the inner solver context.

        Clears all registered constraints and checkpoints.
        """
        self._inner_solver().reset()

    def get_model(self, constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
        """Delegate model extraction to the wrapped solver."""
        return self._inner_solver().get_model(constraints)

    def check_sat_cached(self, constraints: list[z3.BoolRef]) -> SolverResult:
        """Delegate model-producing structured SAT checks to the wrapped solver."""
        return self._inner_solver().check_sat_cached(constraints)

    def get_stats(self) -> dict[str, object]:
        """Retrieve statistics metadata from the underlying solver.

        Returns:
            A dictionary containing metrics (e.g., memory usage, conflict count).
        """
        return self._inner_solver().get_stats()

    def constraint_optimizer(self) -> object:
        """Retrieve the constraint optimizer from the underlying solver.

        Returns:
            The constraint optimizer instance of the underlying solver.
        """
        return self._inner_solver().constraint_optimizer()

    def set_deadline(self, deadline_time: float | None) -> None:
        """Delegate deadline setting to the inner solver."""
        self._inner_solver().set_deadline(deadline_time)

    def __getattr__(self, name: str) -> object:
        """Delegate every other attribute look-up to the inner solver."""
        return getattr(self._inner_solver(), name)

    def __setattr__(self, name: str, value: object) -> None:
        """Delegate attribute writes to the inner solver."""
        setattr(self._inner_solver(), name, value)
