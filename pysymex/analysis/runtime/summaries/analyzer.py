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

"""Analysis helpers over registered function summaries."""

from __future__ import annotations

import z3

from pysymex.analysis.runtime.summaries.instantiation import instantiate_summary
from pysymex.analysis.runtime.summaries.registry import SUMMARY_REGISTRY, SummaryRegistry
from pysymex.analysis.runtime.summaries.types import (
    PreconditionCheckResult,
    PreconditionCheckStatus,
)
from pysymex.core.solver.engine.queries import (
    check_sat_result,
    get_model,
)


class SummaryAnalyzer:
    """
    Analyzes function summaries for various properties.
    """

    def __init__(self, registry: SummaryRegistry | None = None) -> None:
        self.registry = registry or SUMMARY_REGISTRY

    def is_pure(self, name: str) -> bool:
        """Check if function is pure."""
        summary = self.registry.get(name)
        if summary:
            return summary.is_pure
        return False

    def may_modify_globals(self, name: str) -> bool:
        """Check if function may modify global state."""
        summary = self.registry.get(name)
        if summary:
            return summary.modifies_globals()
        return True

    def get_called_functions(self, name: str) -> set[str]:
        """Get all functions called by this function."""
        summary = self.registry.get(name)
        if summary:
            return {call.callee for call in summary.calls}
        return set()

    def get_transitive_calls(self, name: str, visited: set[str] | None = None) -> set[str]:
        """Get all functions transitively called."""
        if visited is None:
            visited = set[str]()
        if name in visited:
            return set()
        visited.add(name)
        result: set[str] = set()
        direct_calls = self.get_called_functions(name)
        result.update(direct_calls)
        for callee in direct_calls:
            result.update(self.get_transitive_calls(callee, visited))
        return result

    def check_preconditions(
        self,
        name: str,
        args: list[z3.ExprRef],
        path_constraints: list[z3.BoolRef],
        kwargs: dict[str, z3.ExprRef] | None = None,
    ) -> tuple[bool, dict[str, object] | None]:
        """
        Check if preconditions are satisfied.
        Returns (satisfied, counterexample or None).
        """
        result = self.check_preconditions_result(name, args, path_constraints, kwargs)
        return (result.is_satisfied, result.counterexample)

    def check_preconditions_result(
        self,
        name: str,
        args: list[z3.ExprRef],
        path_constraints: list[z3.BoolRef],
        kwargs: dict[str, z3.ExprRef] | None = None,
    ) -> PreconditionCheckResult:
        """Check preconditions without collapsing solver UNKNOWN into a failed tuple."""
        summary = self.registry.get(name)
        if not summary or not summary.preconditions:
            return PreconditionCheckResult(PreconditionCheckStatus.SATISFIED)
        kw = kwargs or {}
        pre, _, _ = instantiate_summary(summary, args, kw)
        violation_constraints = [*path_constraints, z3.Not(pre)]
        result = check_sat_result(violation_constraints)
        if result.is_unsat:
            return PreconditionCheckResult(PreconditionCheckStatus.SATISFIED)
        if result.is_unknown:
            return PreconditionCheckResult(
                PreconditionCheckStatus.UNKNOWN,
                reason="Precondition check inconclusive: solver returned unknown",
            )
        model = result.model if result.model is not None else get_model(violation_constraints)
        if model is not None:
            counterexample: dict[str, object] = {str(d.name()): model[d] for d in model.decls()}
            return PreconditionCheckResult(
                PreconditionCheckStatus.VIOLATED,
                counterexample=counterexample,
            )
        return PreconditionCheckResult(
            PreconditionCheckStatus.UNKNOWN,
            reason="Precondition violation is satisfiable but no counterexample model was available",
        )
