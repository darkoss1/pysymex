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

"""Typed SAT/UNSAT/UNKNOWN outcomes returned by the solver engine."""

from __future__ import annotations

from dataclasses import dataclass

import z3


@dataclass(frozen=True, slots=True)
class SolverResult:
    """Outcome of checking the currently encoded Z3 constraints.

    The three flags are intended to represent mutually exclusive solver
    outcomes. ``UNKNOWN`` also represents engine-preserved inconclusive
    states such as deadlines, malformed constraint input, or Z3 failures.
    """

    is_sat: bool
    is_unsat: bool
    is_unknown: bool
    model: z3.ModelRef | None = None

    @staticmethod
    def sat(model: z3.ModelRef | None) -> SolverResult:
        """Create a result for an encoded constraint set established SAT.

        Args:
            model: Optional Z3 witness for the encoded constraints.

        Notes:
            A model is evidence for the active encoding, not by itself a
            statement that all Python runtime behavior was modeled precisely.
        """
        return SolverResult(is_sat=True, is_unsat=False, is_unknown=False, model=model)

    @staticmethod
    def unsat() -> SolverResult:
        """Create a result for an encoded constraint set established UNSAT."""
        return SolverResult(is_sat=False, is_unsat=True, is_unknown=False)

    @staticmethod
    def unknown() -> SolverResult:
        """Create an inconclusive result that must not be treated as proof."""
        return SolverResult(is_sat=False, is_unsat=False, is_unknown=True)
