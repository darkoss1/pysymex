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

"""Opcode and call-target classification for division-by-zero detection."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.calls import extract_argc, resolve_call_target_name
from pysymex._internal.analysis.detectors.runtime.division.evidence import (
    pure_check_division_by_zero,
)
from pysymex._internal.core.bytecode import DIRECT_CALL_OPCODES, resolve_binary_op_symbol
from pysymex._internal.core.outcome import IssueKind

if TYPE_CHECKING:
    import dis

    from pysymex._internal.analysis.detectors.detector.types import IsSatFn, Issue
    from pysymex._internal.core.state.record import VMState

DIVISION_RELEVANT_OPCODES = frozenset(
    (
        "BINARY_OP",
        "BINARY_TRUE_DIVIDE",
        "BINARY_FLOOR_DIVIDE",
        "BINARY_MODULO",
        *DIRECT_CALL_OPCODES,
    ),
)
DIVISION_OPS = frozenset(("BINARY_TRUE_DIVIDE", "BINARY_FLOOR_DIVIDE", "BINARY_MODULO"))
DIVISION_CALL_SUFFIXES = (".truediv", ".floordiv", ".mod", ".modulo")
BINARY_OP_DIVISION_SYMBOLS = frozenset(("/", "//", "%", "/=", "//=", "%="))
BINARY_OP_DIVISION_ARGS = frozenset((2, 6, 11, 15, 19, 24))


def check_division_by_zero(
    state: VMState,
    instruction: dis.Instruction,
    solver_check: IsSatFn,
) -> Issue | None:
    """Inspect one instruction for zero-divisor evidence."""
    if instruction.opname in DIRECT_CALL_OPCODES:
        return _check_division_call(state, instruction, solver_check)

    op_info = binary_division_operation(instruction)
    if op_info is None:
        return None
    is_truediv, issue_kind = op_info

    if len(state.stack) < 2:
        return None

    dividend = state.stack[-2]
    if isinstance(dividend, str) or type(dividend).__name__ == "SymbolicString":
        return None

    return pure_check_division_by_zero(
        state.stack[-1],
        state.stack[-2],
        list(state.path_constraints),
        state.pc,
        is_satisfiable_fn=solver_check,
        is_truediv=is_truediv,
        issue_kind=issue_kind,
        last_inconclusive_feasibility_len=state.last_inconclusive_feasibility_len,
    )


def _check_division_call(
    state: VMState,
    instruction: dis.Instruction,
    solver_check: IsSatFn,
) -> Issue | None:
    """Inspect binary division/modulo call indirection for zero-divisor evidence."""
    argc = extract_argc(instruction)
    if argc != 2 or len(state.stack) < argc + 1:
        return None
    target_name = resolve_call_target_name(state, argc)
    if target_name is None:
        return None

    lowered_target = target_name.lower()
    if not lowered_target.endswith(DIVISION_CALL_SUFFIXES):
        return None

    issue_kind = (
        IssueKind.MODULO_BY_ZERO
        if lowered_target.endswith((".mod", ".modulo"))
        else IssueKind.DIVISION_BY_ZERO
    )
    return pure_check_division_by_zero(
        state.stack[-1],
        state.stack[-2],
        list(state.path_constraints),
        state.pc,
        is_satisfiable_fn=solver_check,
        is_truediv=lowered_target.endswith(".truediv"),
        issue_kind=issue_kind,
        last_inconclusive_feasibility_len=state.last_inconclusive_feasibility_len,
    )


def binary_division_operation(
    instruction: dis.Instruction,
) -> tuple[bool, IssueKind] | None:
    """Return true-division status and issue kind for division-like binary opcodes."""
    issue_kind = IssueKind.DIVISION_BY_ZERO
    is_truediv = False
    if instruction.opname == "BINARY_OP":
        op_symbol = resolve_binary_op_symbol(instruction)
        if (
            op_symbol not in BINARY_OP_DIVISION_SYMBOLS
            and instruction.arg not in BINARY_OP_DIVISION_ARGS
            and op_symbol not in {"/", "/="}
        ):
            return None
        if op_symbol in {"/", "/="} or instruction.arg == 11:
            is_truediv = True
        if op_symbol in {"%", "%="} or instruction.arg in {6, 19}:
            issue_kind = IssueKind.MODULO_BY_ZERO
        return is_truediv, issue_kind

    if instruction.opname not in DIVISION_OPS:
        return None
    if instruction.opname == "BINARY_TRUE_DIVIDE":
        is_truediv = True
    if instruction.opname == "BINARY_MODULO":
        issue_kind = IssueKind.MODULO_BY_ZERO
    return is_truediv, issue_kind
