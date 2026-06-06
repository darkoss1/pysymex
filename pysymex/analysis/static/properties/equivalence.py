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

"""Check implementation equivalence and refinement between function pairs."""

from __future__ import annotations

from collections.abc import Callable

import z3

from pysymex.analysis.static.properties.solver_queries import check_violation_query
from pysymex.analysis.static.properties.types import PropertyKind, PropertyProof, PropertySpec
from pysymex.core.solver.engine.incremental import IncrementalSolver


class EquivalenceChecker:
    """Proves equivalence between different implementations."""

    def __init__(self, timeout_ms: int = 10000) -> None:
        self.timeout_ms = timeout_ms
        self.solver = IncrementalSolver(timeout_ms=timeout_ms)

    def check_equivalent(
        self,
        impl1: Callable[..., z3.ExprRef],
        impl2: Callable[..., z3.ExprRef],
        args: list[z3.ExprRef],
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Check if two implementations are equivalent for all inputs."""
        spec = PropertySpec(
            kind=PropertyKind.EQUIVALENCE,
            name="Implementation Equivalence",
            description="impl1(*args) == impl2(*args)",
        )
        return check_violation_query(
            self.solver,
            spec,
            {f"arg{i}": arg for i, arg in enumerate(args)},
            lambda: (impl1(*args) != impl2(*args),),
            constraints,
        )

    def check_refinement(
        self,
        spec_impl: Callable[..., z3.BoolRef],
        actual_impl: Callable[..., z3.BoolRef],
        args: list[z3.ExprRef],
        constraints: list[z3.BoolRef] | None = None,
    ) -> PropertyProof:
        """Check if actual implementation refines (implies) spec."""
        spec = PropertySpec(
            kind=PropertyKind.REFINEMENT,
            name="Refinement Check",
            description="actual => spec",
        )
        return check_violation_query(
            self.solver,
            spec,
            {f"arg{i}": arg for i, arg in enumerate(args)},
            lambda: (actual_impl(*args), z3.Not(spec_impl(*args))),
            constraints,
        )
