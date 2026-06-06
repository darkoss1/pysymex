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

"""None/null data-flow analysis."""

from __future__ import annotations

import dis

from pysymex.analysis.static.control.models import BasicBlock, ControlFlowGraph
from pysymex.analysis.static.dataflow.bytecode import (
    DELETE_OPS,
    LOAD_OPS,
    STORE_OPS,
    instruction_int_arg,
)
from pysymex.analysis.static.dataflow.framework import DataFlowAnalysis
from pysymex.analysis.static.dataflow.types import NullInfo, NullState


class NullAnalysis(DataFlowAnalysis[NullInfo]):
    """Null/None pointer analysis."""

    def __init__(self, cfg: ControlFlowGraph) -> None:
        """Initialize the NullAnalysis with a ControlFlowGraph.

        Args:
            cfg: The control flow graph to perform null/None analysis on.
        """
        super().__init__(cfg)
        self.narrowing_conditions: dict[int, dict[str, NullState]] = {}

    def initial_value(self) -> NullInfo:
        """Return the initial value for the null analysis (empty NullInfo).

        Returns:
            An empty NullInfo representing unknown nullness.
        """
        return NullInfo()

    def boundary_value(self) -> NullInfo:
        """Return the boundary value at the start/entry of the CFG (empty NullInfo).

        Returns:
            An empty NullInfo representing unknown nullness.
        """
        return NullInfo()

    def transfer(self, block: BasicBlock, in_fact: NullInfo) -> NullInfo:
        """Transfer function for null analysis."""
        info = in_fact.copy()
        stack: list[NullState] = []

        for instr in block.instructions:
            self._process_instruction(info, instr, stack)

        for var_name, state in self.narrowing_conditions.get(block.id, {}).items():
            info.set_state(var_name, state)
        return info

    def _process_instruction(
        self,
        info: NullInfo,
        instr: dis.Instruction,
        stack: list[NullState],
    ) -> None:
        """Process a single instruction for nullness flow."""

        def push(state: NullState) -> None:
            stack.append(state)

        def pop() -> NullState:
            return stack.pop() if stack else NullState.UNKNOWN

        op = instr.opname
        if op == "LOAD_CONST":
            push(
                NullState.DEFINITELY_NULL if instr.argval is None else NullState.DEFINITELY_NOT_NULL
            )
        elif op in LOAD_OPS:
            push(info.get_state(str(instr.argval)))
        elif op == "LOAD_FAST_LOAD_FAST":
            arg1, arg2 = instr.argval
            push(info.get_state(str(arg1)))
            push(info.get_state(str(arg2)))
        elif op in STORE_OPS:
            info.set_state(str(instr.argval), pop())
        elif op in DELETE_OPS:
            info.clear_state(str(instr.argval))
        elif op == "DUP_TOP":
            val = pop()
            push(val)
            push(val)
        elif op == "DUP_TOP_TWO":
            val1 = pop()
            val2 = pop()
            push(val2)
            push(val1)
            push(val2)
            push(val1)
        elif op == "ROT_TWO":
            val1 = pop()
            val2 = pop()
            push(val1)
            push(val2)
        elif op == "ROT_THREE":
            val1 = pop()
            val2 = pop()
            val3 = pop()
            push(val1)
            push(val3)
            push(val2)
        elif op == "SWAP":
            idx = int(instr.argval) if instr.argval else 1
            if len(stack) >= idx:
                stack[-1], stack[-idx] = stack[-idx], stack[-1]
        elif op == "COPY":
            idx = int(instr.argval) if instr.argval else 1
            push(stack[-idx] if len(stack) >= idx else NullState.UNKNOWN)
        elif op == "UNPACK_SEQUENCE":
            pop()
            count = int(instr.argval) if instr.argval is not None else 0
            for _ in range(count):
                push(NullState.UNKNOWN)
        elif op == "POP_TOP":
            pop()
        elif "BINARY_" in op or "INPLACE_" in op or "COMPARE_OP" in op:
            pop()
            pop()
            push(NullState.DEFINITELY_NOT_NULL)
        elif "UNARY_" in op:
            pop()
            push(NullState.DEFINITELY_NOT_NULL)
        elif op.startswith("BUILD_"):
            self._process_build_instruction(op, instr.argval, stack)
        elif op.startswith("CALL"):
            stack.clear()
            push(NullState.MAYBE_NULL)
        else:
            stack.clear()

    @staticmethod
    def _process_build_instruction(op: str, argval: object, stack: list[NullState]) -> None:
        """Process build collection opcodes to update the simulated null state stack.

        Args:
            op: The collection building opcode.
            argval: The instruction argument indicating elements to build.
            stack: The simulated nullness stack of variables/expression states.
        """
        count = instruction_int_arg(argval) if argval is not None else 0
        if op == "BUILD_MAP":
            count *= 2
        elif op == "BUILD_CONST_KEY_MAP":
            count += 1
        for _ in range(count):
            stack.pop() if stack else NullState.UNKNOWN
        stack.append(NullState.DEFINITELY_NOT_NULL)

    def meet(self, facts: list[NullInfo]) -> NullInfo:
        """Join null infos."""
        if not facts:
            return NullInfo()
        result = facts[0]
        for info in facts[1:]:
            result = result.join(info)
        return result

    def is_definitely_null(self, var_name: str, pc: int) -> bool:
        """Check if variable is definitely null at PC."""
        return self._state_at_pc(var_name, pc) == NullState.DEFINITELY_NULL

    def is_definitely_not_null(self, var_name: str, pc: int) -> bool:
        """Check if variable is definitely not null at PC."""
        return self._state_at_pc(var_name, pc) == NullState.DEFINITELY_NOT_NULL

    def may_be_null(self, var_name: str, pc: int) -> bool:
        """Check if variable may be null at PC."""
        state = self._state_at_pc(var_name, pc)
        return state in {
            NullState.DEFINITELY_NULL,
            NullState.MAYBE_NULL,
            NullState.UNKNOWN,
        }

    def _state_at_pc(self, var_name: str, pc: int) -> NullState:
        """Replay block-local transfer up to PC and return a variable's nullness."""
        block = self.cfg.get_block_at_pc(pc)
        if not block:
            return NullState.UNKNOWN
        info = self.get_in(block.id).copy()
        stack: list[NullState] = []
        for instr in block.instructions:
            if instr.offset >= pc:
                break
            self._process_instruction(info, instr, stack)
        return info.get_state(var_name)


__all__ = ["NullAnalysis"]
