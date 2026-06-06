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

"""Bytecode transfer functions mapping instructions to range-state updates."""

from __future__ import annotations

import dis
import types

from pysymex.core.bytecode import get_starts_line
from pysymex.analysis.static.dataflow.bytecode import (
    is_counted_call_instruction,
    is_splat_call_instruction,
)
from pysymex.analysis.static.control.models import BasicBlock
from pysymex.analysis.domains.ranges.domain import Range
from pysymex.analysis.domains.ranges.state import RangeState
from pysymex.analysis.domains.ranges.operations import (
    transfer_binary_op,
    transfer_binary_subscr,
    transfer_build_map,
    transfer_build_sequence,
    transfer_call,
    transfer_load_const,
)
from pysymex.analysis.domains.ranges.warnings import RangeWarning


class RangeTransferMixin:
    def _transfer_block(
        self,
        block: BasicBlock,
        in_state: RangeState,
        code: types.CodeType,
        file_path: str,
        pc_to_line: dict[int, int] | None = None,
    ) -> tuple[RangeState, list[RangeWarning]]:
        """Transfer function for a block."""
        state = in_state.copy()
        block_warnings: list[RangeWarning] = []
        current_line = 0
        if block.instructions and pc_to_line:
            current_line = pc_to_line.get(block.instructions[0].offset, 0)

        for instr in block.instructions:
            if pc_to_line and instr.offset in pc_to_line:
                current_line = pc_to_line[instr.offset]
            else:
                line = get_starts_line(instr)
                if line is not None:
                    current_line = line
            block_warnings.extend(self._transfer_instruction(instr, state, current_line, file_path))
        return state, block_warnings

    def _transfer_instruction(
        self,
        instr: dis.Instruction,
        state: RangeState,
        line: int,
        file_path: str,
    ) -> list[RangeWarning]:
        """Transfer function for an instruction."""
        warnings: list[RangeWarning] = []
        opname = instr.opname
        arg = instr.argval
        if opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"}:
            state.push(state.get(arg))
        elif opname == "LOAD_FAST_AND_CLEAR":
            state.push(state.get(arg))
            state.set(arg, Range.full())
        elif opname == "LOAD_CONST":
            transfer_load_const(arg, state)
        elif opname in {"STORE_FAST", "STORE_NAME", "STORE_GLOBAL", "STORE_DEREF"}:
            if state.stack:
                state.set(arg, state.pop())
        elif opname == "BINARY_OP":
            warnings.extend(transfer_binary_op(instr, state, line))
        elif opname == "UNARY_NEGATIVE":
            if state.stack:
                state.push(state.pop().neg())
        elif opname == "UNARY_POSITIVE":
            pass
        elif opname == "COMPARE_OP":
            if len(state.stack) >= 2:
                state.pop()
                state.pop()
            state.push(Range.between(0, 1))
        elif opname == "BINARY_SUBSCR":
            transfer_binary_subscr(state)
        elif opname in {"BUILD_LIST", "BUILD_TUPLE", "BUILD_SET"}:
            transfer_build_sequence(arg, state)
        elif opname == "BUILD_MAP":
            transfer_build_map(arg, state)
        elif is_counted_call_instruction(instr) or is_splat_call_instruction(instr):
            transfer_call(instr, state)
        elif opname == "GET_ITER":
            pass
        elif opname == "FOR_ITER":
            if state.stack:
                state.push(state.peek())
        elif opname == "LIST_APPEND":
            if state.stack:
                state.pop()
        elif opname == "END_FOR":
            if state.stack:
                state.pop()
        elif opname == "POP_TOP":
            if state.stack:
                state.pop()
        elif opname == "SWAP":
            index = int(instr.argval) if isinstance(instr.argval, int) else 1
            if index > 0 and len(state.stack) >= index:
                state.stack[-1], state.stack[-index] = state.stack[-index], state.stack[-1]
        elif opname == "DUP_TOP":
            if state.stack:
                state.push(state.peek())
        elif opname == "ROT_TWO":
            if len(state.stack) >= 2:
                a = state.pop()
                b = state.pop()
                state.push(a)
                state.push(b)
        elif opname == "RETURN_VALUE":
            if state.stack:
                state.pop()
        elif opname == "LOAD_ATTR":
            if state.stack:
                state.pop()
            state.push(Range.at_least(0) if arg == "__len__" else Range.full())
        elif opname == "STORE_ATTR" and len(state.stack) >= 2:
            state.pop()
            state.pop()
        return warnings


__all__ = ["RangeTransferMixin"]
