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

"""Generate candidate loop invariants from induction variables and loop bounds."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.analysis.static.loops.types import (
    LoopInfo,
    LoopInvariantProof,
    LoopInvariantProofStatus,
)
from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState

logger = get_logger(__name__)


class LoopInvariantGenerator:
    """Generates loop invariants for verification."""

    @staticmethod
    def _get_z3_int(value: object) -> z3.ArithRef | None:
        z3_int = getattr(value, "z3_int", None)
        return z3_int if isinstance(z3_int, z3.ArithRef) else None

    def generate_invariants(self, loop: LoopInfo, state: VMState) -> list[z3.BoolRef]:
        """Generate candidate invariants for a loop."""
        invariants: list[z3.BoolRef] = []
        for name, iv in loop.induction_vars.items():
            sym_var = state.locals.get(name)
            z3_int = self._get_z3_int(sym_var)
            if z3_int is not None:
                if iv.direction >= 0:
                    invariants.append(z3_int >= iv.initial)
                else:
                    invariants.append(z3_int <= iv.initial)
                if loop.bound is not None:
                    final = iv.final_value(loop.bound.upper)
                    if iv.direction > 0:
                        invariants.append(z3_int <= final)
                    else:
                        invariants.append(z3_int >= final)
        for constraint in state.path_constraints:
            invariants.append(constraint)
        return invariants

    def verify_invariant(self, invariant: z3.BoolRef, loop: LoopInfo, state: VMState) -> bool:
        """Verify that an invariant holds."""
        return self.verify_invariant_result(invariant, loop, state).is_proven

    def verify_invariant_result(
        self, invariant: z3.BoolRef, loop: LoopInfo, state: VMState
    ) -> LoopInvariantProof:
        """Verify an invariant while preserving SAT/UNSAT/UNKNOWN solver status."""
        from pysymex.core.solver.engine.queries import check_sat_result, get_model

        _ = loop
        constraints = [*list(state.path_constraints), z3.Not(invariant)]
        result = check_sat_result(constraints)
        if result.is_unsat:
            return LoopInvariantProof(LoopInvariantProofStatus.PROVEN)
        if result.is_unknown:
            return LoopInvariantProof(
                LoopInvariantProofStatus.UNKNOWN,
                reason="Loop invariant proof inconclusive: solver returned unknown",
            )
        model = result.model if result.model is not None else get_model(constraints)
        if model is not None:
            counterexample: dict[str, object] = {str(d.name()): model[d] for d in model.decls()}
            return LoopInvariantProof(
                LoopInvariantProofStatus.DISPROVEN,
                counterexample=counterexample,
            )
        logger.debug("Loop invariant violation was SAT but no model was available")
        return LoopInvariantProof(
            LoopInvariantProofStatus.UNKNOWN,
            reason="Loop invariant violation is satisfiable but no counterexample model was available",
        )


__all__ = ["LoopInvariantGenerator"]
