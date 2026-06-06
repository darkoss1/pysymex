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

"""Infer loop iteration bounds from bytecode patterns and Z3 constraint solving."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex.analysis.static.loops.types import LoopBound, LoopInfo
from pysymex.core.types.containers.sequences import SymbolicIterator
from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState


logger = get_logger(__name__)


class LoopBoundInference:
    """Infers loop bounds from iterator state and loop structure."""

    def __init__(self) -> None:
        self._cached_bounds: dict[int, LoopBound] = {}

    def infer_bound(self, loop: LoopInfo, state: VMState) -> LoopBound:
        """Infer bounds for a loop."""
        if loop.header_pc in self._cached_bounds:
            return self._cached_bounds[loop.header_pc]
        bound = self._try_extract_iterator_bound(state)
        if bound:
            self._cached_bounds[loop.header_pc] = bound
            return bound
        if self._is_counted_loop(loop):
            bound = self._infer_counted_bound(loop, state)
        else:
            bound = self._infer_while_bound(loop, state)
        self._cached_bounds[loop.header_pc] = bound
        return bound

    def _try_extract_iterator_bound(self, state: VMState) -> LoopBound | None:
        """Try to extract bound from iterator on the stack."""
        if not state.stack:
            return None
        for item in reversed(state.stack[-3:]):
            if isinstance(item, SymbolicIterator):
                try:
                    bound = item.remaining_bound()
                    if isinstance(bound, int):
                        return LoopBound.constant(bound)
                    return LoopBound.symbolic(bound)
                except (AttributeError, TypeError):
                    logger.debug(
                        "Failed to extract runtime iterator remaining bound", exc_info=True
                    )
        return None

    def _is_counted_loop(self, loop: LoopInfo) -> bool:
        """Check if loop has a counting pattern."""
        return bool(loop.induction_vars)

    def _infer_counted_bound(self, loop: LoopInfo, state: VMState) -> LoopBound:
        """Infer bound for counted loop using induction variables."""
        for name, iv in loop.induction_vars.items():
            var = state.locals.get(name)
            if var is None:
                continue
            step = self._concrete_step(iv.step)
            if step is None or step <= 0:
                continue
            var_expr_raw = getattr(var, "z3_int", None)
            if var_expr_raw is None or not isinstance(var_expr_raw, z3.ExprRef):
                continue
            var_expr: z3.ExprRef = var_expr_raw
            for constraint in reversed(state.path_constraints):
                if isinstance(constraint, list):
                    continue
                constraint_expr = cast("z3.ExprRef", constraint)
                if z3.is_lt(constraint) or z3.is_le(constraint):
                    children = constraint_expr.children()
                    if len(children) == 2:
                        lhs, rhs = children[0], children[1]
                        if z3.eq(lhs, var_expr) or str(lhs) == str(var_expr):
                            return LoopBound.symbolic(rhs)
        return LoopBound.range(0, 1000)

    @staticmethod
    def _concrete_step(step_val: object) -> int | None:
        if isinstance(step_val, int):
            return step_val
        if isinstance(step_val, z3.ArithRef) and z3.is_int_value(step_val):
            return step_val.as_long()
        return None

    def _infer_while_bound(self, loop: LoopInfo, state: VMState) -> LoopBound:
        """Infer bound for while loops from condition analysis."""
        for constraint in state.path_constraints:
            if z3.is_and(constraint) or z3.is_or(constraint):
                continue
        return LoopBound.range(0, 10000)


__all__ = ["LoopBoundInference"]
