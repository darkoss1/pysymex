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

"""Opcode-specific transfer helpers for range analysis (binary ops, comparisons)."""

from __future__ import annotations

import dis

from pysymex.analysis.static.dataflow.bytecode import (
    counted_call_arg_count,
    counted_call_metadata_count,
    is_counted_call_instruction,
    is_splat_call_instruction,
    splat_call_payload_count,
)
from pysymex.analysis.domains.ranges.domain import Range
from pysymex.analysis.domains.ranges.state import RangeState
from pysymex.analysis.domains.ranges.warnings import RangeWarning


def arg_count(arg: object) -> int:
    return arg if isinstance(arg, int) else 0


def transfer_load_const(arg: object, state: RangeState) -> None:
    if isinstance(arg, int):
        state.push(Range.exact(arg))
    elif isinstance(arg, (float, complex)):
        state.push(Range(None, None, is_numeric=True))
    else:
        state.push(Range(None, None, is_numeric=False))


def transfer_binary_op(instr: dis.Instruction, state: RangeState, line: int) -> list[RangeWarning]:
    warnings: list[RangeWarning] = []
    if len(state.stack) < 2:
        return warnings
    right = state.pop()
    left = state.pop()
    op_name = instr.argrepr or ""
    if "+" in op_name:
        state.push(left.add(right))
    elif "-" in op_name:
        state.push(left.sub(right))
    elif "*" in op_name and "**" not in op_name:
        state.push(left.mul(right))
    elif "//" in op_name or "/" in op_name:
        result, may_div_zero = left.div(right)
        warnings.extend(division_warning(may_div_zero, right, left, instr.offset, line))
        state.push(result)
    elif "%" in op_name:
        result, may_div_zero = left.mod(right)
        warnings.extend(modulo_warning(may_div_zero, right, left, instr.offset, line))
        state.push(result)
    else:
        state.push(Range.full())
    return warnings


def division_warning(
    may_div_zero: bool, right: Range, left: Range, pc: int, line: int
) -> list[RangeWarning]:
    has_bound = right.low is not None or right.high is not None
    if (
        may_div_zero
        and has_bound
        and not right.must_be_non_zero()
        and right.is_numeric
        and left.is_numeric
    ):
        return [
            RangeWarning(
                line=line,
                pc=pc,
                kind="DIVISION_BY_ZERO",
                message=f"Possible division by zero (divisor range: {right})",
                range_info=right,
            )
        ]
    return []


def modulo_warning(
    may_div_zero: bool, right: Range, left: Range, pc: int, line: int
) -> list[RangeWarning]:
    has_bound = right.low is not None or right.high is not None
    if (
        may_div_zero
        and has_bound
        and not right.must_be_non_zero()
        and right.is_numeric
        and left.is_numeric
    ):
        return [
            RangeWarning(
                line=line,
                pc=pc,
                kind="MODULO_BY_ZERO",
                message=f"Possible modulo by zero (divisor range: {right})",
                range_info=right,
            )
        ]
    return []


def transfer_binary_subscr(state: RangeState) -> None:
    if len(state.stack) >= 2:
        state.pop()
        if state.stack:
            state.pop()
        state.push(Range.full())


def transfer_build_sequence(arg: object, state: RangeState) -> None:
    count = arg_count(arg)
    for _ in range(count):
        if state.stack:
            state.pop()
    state.push(Range.exact(count))


def transfer_build_map(arg: object, state: RangeState) -> None:
    count = arg_count(arg)
    for _ in range(count * 2):
        if state.stack:
            state.pop()
    state.push(Range.exact(count))


def transfer_call(instr: dis.Instruction, state: RangeState) -> None:
    if is_counted_call_instruction(instr):
        for _ in range(counted_call_metadata_count(instr)):
            if state.stack:
                state.pop()
        for _ in range(counted_call_arg_count(instr)):
            if state.stack:
                state.pop()
    elif is_splat_call_instruction(instr):
        for _ in range(splat_call_payload_count(instr)):
            if state.stack:
                state.pop()
    if state.stack:
        state.pop()
    state.push(Range.full())


__all__ = [
    "transfer_binary_op",
    "transfer_binary_subscr",
    "transfer_build_map",
    "transfer_build_sequence",
    "transfer_call",
    "transfer_load_const",
]
