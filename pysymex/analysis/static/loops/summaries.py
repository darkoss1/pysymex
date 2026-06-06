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

"""Compute closed-form loop summaries for fast-path symbolic execution."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.analysis.static.loops.types import LoopInfo, LoopSummary
from pysymex.core.solver.constraints.hashing import get_int_val

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState


class LoopSummarizer:
    """Summarizes loop effects for closed-form computation."""

    def summarize(self, loop: LoopInfo, state: VMState) -> LoopSummary | None:
        """Attempt to create a closed-form summary of loop effects."""
        if not loop.bound or not loop.bound.is_finite:
            return None
        if not loop.induction_vars:
            return None
        iterations = loop.bound.exact if loop.bound.exact is not None else loop.bound.upper
        effects: dict[str, z3.ExprRef] = {}
        for name, iv in loop.induction_vars.items():
            effects[name] = iv.final_value(iterations)
        effects.update(self._detect_accumulator_effects(loop, state, iterations))
        return LoopSummary(
            iterations=iterations,
            variable_effects=effects,
            memory_effects={},
            invariants_verified=bool(loop.invariants),
            can_summarize=True,
        )

    def _detect_accumulator_effects(
        self,
        loop: LoopInfo,
        state: VMState,
        iterations: z3.ExprRef | int,
    ) -> dict[str, z3.ExprRef]:
        """Detect accumulator patterns like sum += iv."""
        effects: dict[str, z3.ExprRef] = {}
        instructions = getattr(state, "current_instructions", None)
        if not instructions:
            return effects
        iv_names = set(loop.induction_vars.keys())
        for i in range(len(instructions) - 3):
            instr1 = instructions[i]
            if getattr(instr1, "offset", -1) not in loop.body_pcs:
                continue
            if instr1.opname not in ("LOAD_FAST", "LOAD_NAME") or not isinstance(
                instr1.argval, str
            ):
                continue
            acc_name = instr1.argval
            instr2 = instructions[i + 1]
            if instr2.opname not in ("LOAD_FAST", "LOAD_NAME") or instr2.argval not in iv_names:
                continue
            instr3 = instructions[i + 2]
            if instr3.opname != "BINARY_OP" or getattr(instr3, "argrepr", "") not in ("+", "+="):
                continue
            instr4 = instructions[i + 3]
            if instr4.opname not in ("STORE_FAST", "STORE_NAME") or instr4.argval != acc_name:
                continue
            self._record_accumulator_effect(
                effects, loop, state, acc_name, str(instr2.argval), iterations
            )
        return effects

    @staticmethod
    def _record_accumulator_effect(
        effects: dict[str, z3.ExprRef],
        loop: LoopInfo,
        state: VMState,
        acc_name: str,
        iv_name: str,
        iterations: z3.ExprRef | int,
    ) -> None:
        iv = loop.induction_vars[iv_name]
        acc_val = state.locals.get(acc_name)
        if acc_val is None:
            return
        acc_initial = getattr(acc_val, "z3_int", acc_val)
        if not isinstance(acc_initial, z3.ExprRef):
            return
        n = get_int_val(iterations) if isinstance(iterations, int) else iterations
        sum_n = (n * (n - get_int_val(1))) / get_int_val(2)
        effects[acc_name] = acc_initial + (n * iv.initial) + (sum_n * iv.step)

    def apply_summary(self, summary: LoopSummary, state: VMState) -> VMState:
        """Apply loop summary to state, skipping iteration."""
        new_state = state.copy()
        for name, final_value in summary.variable_effects.items():
            if name in new_state.locals:
                from pysymex.core.types.scalars.values import SymbolicValue

                new_state.locals[name] = SymbolicValue.from_z3(final_value, name)
        for addr, effects in summary.memory_effects.items():
            mem_obj = new_state.memory.get(addr)
            if isinstance(mem_obj, dict):
                from pysymex.core.types.scalars.values import SymbolicValue as SV

                for attr, value in effects.items():
                    mem_obj[attr] = SV.from_z3(value, f"mem_{addr}_{attr}")
        return new_state


__all__ = ["LoopSummarizer"]
