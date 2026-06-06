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

"""Detect induction variables from bytecode store/load patterns within a loop."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING

import z3

from pysymex.analysis.static.loops.types import InductionVariable, LoopInfo
from pysymex.core.constants import Z3_ZERO
from pysymex.core.solver.constraints.hashing import get_int_val

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState


class InductionVariableDetector:
    """Detects induction variables in loop bodies."""

    def __init__(self) -> None:
        self._detected: dict[str, InductionVariable] = {}

    @staticmethod
    def _coerce_z3_int(value: object) -> z3.ArithRef:
        if isinstance(value, z3.ArithRef):
            return value
        z3_int = getattr(value, "z3_int", None)
        if isinstance(z3_int, z3.ArithRef):
            return z3_int
        if isinstance(value, (int, float)):
            return get_int_val(int(value))
        return Z3_ZERO

    def detect(
        self,
        loop: LoopInfo,
        instructions: list[dis.Instruction],
        state: VMState,
    ) -> dict[str, InductionVariable]:
        """Detect induction variables in loop body."""
        self._detected = {}
        body_instructions = [instr for instr in instructions if instr.offset in loop.body_pcs]
        stores: dict[str, list[tuple[int, dis.Instruction]]] = {}
        loads: dict[str, list[tuple[int, dis.Instruction]]] = {}
        for i, instr in enumerate(body_instructions):
            if instr.opname in ("STORE_FAST", "STORE_NAME"):
                name = str(instr.argval)
                stores.setdefault(name, []).append((i, instr))
            elif instr.opname in ("LOAD_FAST", "LOAD_NAME"):
                name = str(instr.argval)
                loads.setdefault(name, []).append((i, instr))
        modified_vars = set(stores.keys()) & set(loads.keys())
        for name in modified_vars:
            iv = self._analyze_modification_pattern(
                name, stores[name], loads[name], body_instructions, state
            )
            if iv:
                self._detected[name] = iv
        return self._detected

    def _analyze_modification_pattern(
        self,
        name: str,
        stores: list[tuple[int, dis.Instruction]],
        loads: list[tuple[int, dis.Instruction]],
        instructions: list[dis.Instruction],
        state: VMState,
    ) -> InductionVariable | None:
        """Analyze if variable follows induction pattern."""
        _ = loads
        for store_idx, _store_instr in stores:
            if store_idx < 3:
                continue
            prev_instrs: list[dis.Instruction | None] = [
                instructions[store_idx - 3] if store_idx >= 3 else None,
                instructions[store_idx - 2] if store_idx >= 2 else None,
                instructions[store_idx - 1] if store_idx >= 1 else None,
            ]
            if self._matches_binary_update(prev_instrs, name):
                step_instr = prev_instrs[1]
                if step_instr is None:
                    continue
                step_val = step_instr.argval
                if isinstance(step_val, (int, float)):
                    return InductionVariable(
                        name=name,
                        initial=self._coerce_z3_int(state.locals.get(name)),
                        step=get_int_val(int(step_val)),
                        direction=1 if step_val > 0 else -1,
                    )
            if self._matches_increment(prev_instrs, name):
                return InductionVariable(
                    name=name,
                    initial=self._coerce_z3_int(state.locals.get(name)),
                    step=get_int_val(1),
                    direction=1,
                )
        return None

    @staticmethod
    def _matches_binary_update(prev_instrs: list[dis.Instruction | None], name: str) -> bool:
        return (
            prev_instrs[0] is not None
            and prev_instrs[0].opname in ("LOAD_FAST", "LOAD_NAME")
            and prev_instrs[0].argval == name
            and prev_instrs[1] is not None
            and prev_instrs[1].opname == "LOAD_CONST"
            and prev_instrs[2] is not None
            and prev_instrs[2].opname == "BINARY_OP"
        )

    @staticmethod
    def _matches_increment(prev_instrs: list[dis.Instruction | None], name: str) -> bool:
        return (
            prev_instrs[0] is not None
            and prev_instrs[0].opname in ("LOAD_FAST", "LOAD_NAME")
            and prev_instrs[0].argval == name
            and prev_instrs[1] is not None
            and prev_instrs[1].opname == "LOAD_CONST"
            and prev_instrs[1].argval == 1
            and prev_instrs[2] is not None
            and "ADD" in prev_instrs[2].opname
        )


__all__ = ["InductionVariableDetector"]
