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

"""Ground quantified constraints for solver queries.

Enumerates bounded domains and builds trigger patterns for Z3 E-matching. Used while
assembling formulas; final satisfiability checks run in
:class:`~pysymex.contracts.quantifiers.verification.QuantifierVerifier`.
"""

from __future__ import annotations

import z3

from pysymex.contracts.quantifiers.types import Quantifier, QuantifierKind
from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.solver.engine.incremental import IncrementalSolver


class QuantifierInstantiator:
    """Instantiates quantifiers with concrete values.

    For bounded quantifiers, enumerates all instances up to
    ``max_instantiations``. For unbounded quantifiers, relies on Z3 E-matching triggers.

    Attributes:
        max_instantiations: Upper limit on enumerated instances to prevent path explosion.
    """

    def __init__(self, max_instantiations: int = 100) -> None:
        """Initialize the quantifier instantiator.

        Args:
            max_instantiations: The maximum number of concrete values generated
                to instantiate bounded quantifiers. Defaults to 100.
        """
        self.max_instantiations = max_instantiations

    def instantiate_bounded(
        self,
        quantifier: Quantifier,
        solver: IncrementalSolver | None = None,
    ) -> list[z3.BoolRef]:
        """Instantiate a bounded quantifier by enumerating its integer range.

        Evaluates the upper and lower bounds of the quantifier. If the range
        size is within ``max_instantiations``, generates a Z3 constraint for
        each concrete integer in the range.

        Args:
            quantifier: The quantified expression to instantiate.
            solver: The incremental solver to query for concrete bounds,
                or ``None`` to use a default temporary solver.

        Returns:
            A list of instantiated Z3 boolean formulas.
        """
        if quantifier.kind not in (QuantifierKind.FORALL, QuantifierKind.EXISTS):
            return []
        active_solver = solver or IncrementalSolver(timeout_ms=1000)
        instances: list[z3.BoolRef] = []
        for var, bound in zip(quantifier.variables, quantifier.bounds, strict=False):
            if bound.lower is not None and bound.upper is not None:
                try:
                    lower = self._get_concrete_value(bound.lower, active_solver)
                    upper = self._get_concrete_value(bound.upper, active_solver)
                    if lower is None or upper is None:
                        continue
                    start = lower if bound.lower_inclusive else lower + 1
                    stop = upper + 1 if bound.upper_inclusive else upper
                    range_size = max(0, stop - start)
                    if range_size > self.max_instantiations:
                        continue
                    if var.z3_var is None:
                        continue
                    for i in range(start, stop):
                        instance = z3.substitute(quantifier.body, (var.z3_var, get_int_val(i)))
                        instances.append(instance)
                except z3.Z3Exception:
                    continue
        return instances

    def _get_concrete_value(
        self,
        expr: z3.ExprRef,
        solver: IncrementalSolver,
    ) -> int | None:
        """Resolve a Z3 expression to a concrete integer value if possible.

        Args:
            expr: The Z3 expression to evaluate.
            solver: The active solver query context.

        Returns:
            The concrete integer value, or ``None`` if it cannot be resolved.

        Side Effects:
            Pushes and pops solver state constraints.
        """
        if z3.is_int_value(expr):
            return expr.as_long()
        solver.push()
        v = z3.Int("__bound")
        solver.add(v == expr)
        check_result = solver.check()
        if check_result.is_sat and check_result.model is not None:
            result = check_result.model.eval(v)
            solver.pop()
            if z3.is_int_value(result):
                return result.as_long()
        solver.pop()
        return None

    def add_triggers(
        self,
        quantifier: Quantifier,
        triggers: list[z3.ExprRef],
    ) -> z3.BoolRef:
        """Add E-matching pattern triggers to a quantified formula.

        Triggers guide the solver's heuristic instantiation decisions.

        Args:
            quantifier: The quantifier structure.
            triggers: List of Z3 sub-expressions to use as triggering patterns.

        Returns:
            A Z3 quantified formula enclosing the specified trigger patterns.
        """
        z3_expr = quantifier.to_z3()
        if not triggers:
            return z3_expr
        z3_vars = [v.z3_var for v in quantifier.variables]
        if quantifier.kind == QuantifierKind.FORALL:
            return z3.ForAll(
                z3_vars,
                z3.Implies(
                    z3.And(
                        *[
                            b.to_constraint(v.z3_var)
                            for v, b in zip(quantifier.variables, quantifier.bounds, strict=False)
                        ]
                    ),
                    quantifier.body,
                ),
                patterns=[z3.MultiPattern(*triggers)],
            )
        return z3_expr


__all__ = ["QuantifierInstantiator"]
