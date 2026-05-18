# pysymex: Python Symbolic Execution & Formal Verification
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

from __future__ import annotations

import dis
import z3
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.core.state import VMState

from pysymex.core.types.havoc import is_havoc
from pysymex.core.solver.engine import get_model
from pysymex.core.types import (
    SymbolicString,
    SymbolicValue,
)
from pysymex.analysis.detectors.base import Detector, Issue, IssueKind, IsSatFn
from pysymex.analysis.detectors.runtime.overflow import resolve_binary_op_symbol

_NON_STRING_OPS = frozenset({"-", "/", "%", "**", "//", "<<", ">>", "&", "|", "^", "@"})
_INTERNAL_SYMBOLIC_ATTR_PREFIXES = ("self.", "cls.")


def _is_internal_symbolic_attr(value: object) -> bool:
    return isinstance(value, SymbolicValue) and value.name.startswith(
        _INTERNAL_SYMBOLIC_ATTR_PREFIXES
    )


def _is_havoc_derived_symbolic(value: object) -> bool:
    if not isinstance(value, SymbolicValue):
        return False
    return "havoc" in value.name


def _can_be_str_static(value: object) -> bool | None:
    """Return static string possibility when it is known without Z3."""
    if isinstance(value, SymbolicString):
        return True
    if isinstance(value, SymbolicValue):
        if value.affinity_type == "str":
            return True
        if value.affinity_type in {"bool", "float", "int"}:
            return False
        return None
    if isinstance(value, str):
        return True
    return False


def _can_be_str_expr(value: object) -> z3.BoolRef:
    """Return a symbolic boolean for whether a value can be a string."""
    if isinstance(value, SymbolicString):
        return z3.BoolVal(True)
    if isinstance(value, SymbolicValue):
        if value.affinity_type == "str":
            return z3.BoolVal(True)
        return value.is_str
    if isinstance(value, str):
        return z3.BoolVal(True)
    return z3.BoolVal(False)


def _can_be_non_str_expr(value: object) -> z3.BoolRef:
    """Return a symbolic boolean for whether a value can be a non-string."""
    if isinstance(value, SymbolicString):
        return z3.BoolVal(False)
    if isinstance(value, SymbolicValue):
        if value.affinity_type == "str":
            return z3.BoolVal(False)
        return z3.Not(value.is_str)
    if isinstance(value, str):
        return z3.BoolVal(False)
    return z3.BoolVal(True)


def _can_be_int_like_expr(value: object) -> z3.BoolRef:
    """Return a symbolic boolean for whether a value can be int-like."""
    if isinstance(value, SymbolicString):
        return z3.BoolVal(False)
    if isinstance(value, SymbolicValue):
        if value.affinity_type in {"int", "bool"}:
            return z3.BoolVal(True)
        return z3.Or(value.is_int, value.is_bool)
    if isinstance(value, bool):
        return z3.BoolVal(True)
    if isinstance(value, int):
        return z3.BoolVal(True)
    return z3.BoolVal(False)


class TypeErrorDetector(Detector):
    """Detects type errors in binary operations (e.g. string + int)."""

    name = "type-error"
    description = "Detects type mismatches"
    issue_kind = IssueKind.TYPE_ERROR
    relevant_opcodes = frozenset({"BINARY_OP"})

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Check binary-op type mismatches for string vs numeric operations."""
        if instruction.opname != "BINARY_OP":
            return None
        if len(state.stack) < 2:
            return None

        op_symbol = resolve_binary_op_symbol(instruction)
        if not op_symbol:
            return None
        op = op_symbol[:-1] if op_symbol.endswith("=") else op_symbol

        left = state.stack[-2]
        right = state.stack[-1]
        if is_havoc(left) or is_havoc(right):
            return None
        if _is_havoc_derived_symbolic(left) or _is_havoc_derived_symbolic(right):
            return None
        if _is_internal_symbolic_attr(left) or _is_internal_symbolic_attr(right):
            return None
        left_str_static = _can_be_str_static(left)
        right_str_static = _can_be_str_static(right)

        if left_str_static is False and right_str_static is False:
            return None

        left_can_str = _can_be_str_expr(left)
        right_can_str = _can_be_str_expr(right)
        left_can_non_str = _can_be_non_str_expr(left)
        right_can_non_str = _can_be_non_str_expr(right)

        if op == "+":
            mismatch_expr = z3.simplify(
                z3.Or(
                    z3.And(left_can_str, right_can_non_str),
                    z3.And(right_can_str, left_can_non_str),
                )
            )
            if z3.is_false(mismatch_expr):
                return None
            concat_mismatch_constraint = [
                *state.path_constraints,
                mismatch_expr,
            ]
            if _solver_check(concat_mismatch_constraint):
                confidence = 1.0
                if is_havoc(left) or is_havoc(right):
                    confidence = 0.5
                return Issue(
                    kind=IssueKind.TYPE_ERROR,
                    message="Cannot concatenate 'str' with non-'str' operand",
                    constraints=concat_mismatch_constraint,
                    model=get_model(concat_mismatch_constraint),
                    pc=state.pc,
                    confidence=confidence,
                )

        if op in _NON_STRING_OPS:
            str_operand_expr = z3.simplify(z3.Or(left_can_str, right_can_str))
            if z3.is_false(str_operand_expr):
                return None
            unsupported_str_constraint = [
                *state.path_constraints,
                str_operand_expr,
            ]
            if _solver_check(unsupported_str_constraint):
                confidence = 1.0
                if is_havoc(left) or is_havoc(right):
                    confidence = 0.5
                return Issue(
                    kind=IssueKind.TYPE_ERROR,
                    message=f"Unsupported operand type(s) for {op} involving 'str'",
                    constraints=unsupported_str_constraint,
                    model=get_model(unsupported_str_constraint),
                    pc=state.pc,
                    confidence=confidence,
                )

        if op == "*":
            left_can_int_like = _can_be_int_like_expr(left)
            right_can_int_like = _can_be_int_like_expr(right)
            bad_repeat_expr = z3.simplify(
                z3.Or(
                    z3.And(left_can_str, z3.Not(right_can_int_like)),
                    z3.And(right_can_str, z3.Not(left_can_int_like)),
                )
            )
            if z3.is_false(bad_repeat_expr):
                return None
            bad_repeat_constraint = [
                *state.path_constraints,
                bad_repeat_expr,
            ]
            if _solver_check(bad_repeat_constraint):
                confidence = 1.0
                if is_havoc(left) or is_havoc(right):
                    confidence = 0.5
                return Issue(
                    kind=IssueKind.TYPE_ERROR,
                    message="Can't multiply sequence by non-int operand",
                    constraints=bad_repeat_constraint,
                    model=get_model(bad_repeat_constraint),
                    pc=state.pc,
                    confidence=confidence,
                )
        return None
