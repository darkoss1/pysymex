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

"""Type Error detector module.

Detects runtime TypeError exceptions such as unsupported binary operators or invalid calls.

Bug Class Detected:
    Type Error.

Required Evidence:
    Satisfiable path constraints where operator types are incompatible.

Issue Kinds:
    IssueKind.TYPE_ERROR
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.bytecode import resolve_binary_op_symbol
from pysymex._internal.core.outcome import IssueKind

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState

from pysymex._internal.analysis.detectors.detector.contract import Detector
from pysymex._internal.analysis.detectors.detector.types import IsSatFn, Issue
from pysymex._internal.analysis.detectors.feasibility import get_model_if_satisfiable_result
from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.havoc import is_havoc
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue

_NON_STRING_OPS = frozenset(("-", "/", "%", "**", "//", "<<", ">>", "&", "|", "^", "@"))
_INTERNAL_SYMBOLIC_ATTR_PREFIXES = ("self.", "cls.")


def _is_internal_symbolic_attr(value: object) -> bool:
    """Check if the value is an internal symbolic attribute (e.g. self.attr).

    Args:
        value (object): The value to check.

    Returns:
        bool: True if it starts with internal attribute prefixes, False otherwise.

    """
    return isinstance(value, SymbolicValue) and value.name.startswith(
        _INTERNAL_SYMBOLIC_ATTR_PREFIXES,
    )


def _is_havoc_derived_symbolic(value: object) -> bool:
    """Check if the value is a symbolic value derived from havoc.

    Args:
        value (object): The value to check.

    Returns:
        bool: True if 'havoc' is in the symbol name, False otherwise.

    """
    if not isinstance(value, SymbolicValue):
        return False
    return "havoc" in value.name


def _can_be_str_static(value: object) -> bool | None:
    """Return static string possibility when it is known without Z3."""
    if isinstance(value, SymbolicString):
        return True
    if isinstance(value, SymbolicValue):
        if z3.is_true(value.is_str):
            return True
        if z3.is_false(value.is_str):
            return False
        if value.affinity_type == "str":
            return True
        if value.affinity_type in {"bool", "float", "int"}:
            return False
        return None
    return bool(isinstance(value, str))


def _can_be_str_expr(value: object) -> z3.BoolRef:
    """Return a symbolic boolean for whether a value can be a string."""
    if isinstance(value, SymbolicString):
        return Z3_TRUE
    if isinstance(value, SymbolicValue):
        if value.affinity_type == "str":
            return Z3_TRUE
        return value.is_str
    if isinstance(value, str):
        return Z3_TRUE
    return Z3_FALSE


def _can_be_non_str_expr(value: object) -> z3.BoolRef:
    """Return a symbolic boolean for whether a value can be a non-string."""
    if isinstance(value, SymbolicString):
        return Z3_FALSE
    if isinstance(value, SymbolicValue):
        if value.affinity_type == "str":
            return Z3_FALSE
        return z3.Not(value.is_str)
    if isinstance(value, str):
        return Z3_FALSE
    return Z3_TRUE


def _can_be_int_like_expr(value: object) -> z3.BoolRef:
    """Return a symbolic boolean for whether a value can be int-like."""
    if isinstance(value, SymbolicString):
        return Z3_FALSE
    if isinstance(value, SymbolicValue):
        if value.affinity_type in {"int", "bool"}:
            return Z3_TRUE
        return z3.Or(value.is_int, value.is_bool)
    if isinstance(value, bool):
        return Z3_TRUE
    if isinstance(value, int):
        return Z3_TRUE
    return Z3_FALSE


class TypeErrorDetector(Detector):
    """Detects type errors in binary operations (e.g. string + int)."""

    name = "type-error"
    description = "Detects type mismatches"
    issue_kind = IssueKind.TYPE_ERROR
    relevant_opcodes = frozenset(("BINARY_OP",))

    def check(
        self,
        state: VMState,
        instruction: dis.Instruction,
        _solver_check: IsSatFn,
    ) -> Issue | None:
        """Check binary-op type mismatches for string vs numeric operations."""
        return _check_type_error(state, instruction, _solver_check)


def _check_type_error(
    state: VMState,
    instruction: dis.Instruction,
    solver_check: IsSatFn,
) -> Issue | None:
    """Check binary-op type mismatches for string-like operands."""
    if instruction.opname != "BINARY_OP":
        return None

    op = _normalized_binary_op(instruction)
    if op is None:
        return None

    operands = _binary_operands(state)
    if operands is None:
        return None
    left, right = operands

    if _skip_type_operand(left) or _skip_type_operand(right):
        return None
    if _both_operands_definitely_non_string(left, right):
        return None

    return _binary_type_issue(state, solver_check, op, left, right)


def _normalized_binary_op(instruction: dis.Instruction) -> str | None:
    """Return the normalized BINARY_OP symbol without in-place suffix."""
    op_symbol = resolve_binary_op_symbol(instruction)
    if not op_symbol:
        return None
    if op_symbol.endswith("="):
        return op_symbol[:-1]
    return op_symbol


def _binary_operands(state: VMState) -> tuple[object, object] | None:
    """Return the left and right stack operands for a binary operation."""
    if len(state.stack) < 2:
        return None
    return state.stack[-2], state.stack[-1]


def _skip_type_operand(value: object) -> bool:
    """Return whether an operand lacks definite TypeError evidence."""
    return is_havoc(value) or _is_havoc_derived_symbolic(value) or _is_internal_symbolic_attr(value)


def _both_operands_definitely_non_string(left: object, right: object) -> bool:
    """Return whether neither operand can be string-like under static evidence."""
    return _can_be_str_static(left) is False and _can_be_str_static(right) is False


def _binary_type_issue(
    state: VMState,
    solver_check: IsSatFn,
    op: str,
    left: object,
    right: object,
) -> Issue | None:
    """Route a supported binary operator to its TypeError evidence check."""
    if op == "+":
        return _string_concat_mismatch_issue(state, solver_check, left, right)
    if op in _NON_STRING_OPS:
        return _unsupported_string_operator_issue(state, solver_check, op, left, right)
    if op == "*":
        return _bad_string_repeat_issue(state, solver_check, left, right)
    return None


def _string_concat_mismatch_issue(
    state: VMState,
    solver_check: IsSatFn,
    left: object,
    right: object,
) -> Issue | None:
    """Return an issue for feasible string concatenation mismatches."""
    mismatch_expr = simplify_expr(
        z3.Or(
            z3.And(_can_be_str_expr(left), _can_be_non_str_expr(right)),
            z3.And(_can_be_str_expr(right), _can_be_non_str_expr(left)),
        ),
    )
    return _issue_from_type_constraint(
        state,
        solver_check,
        mismatch_expr,
        "Cannot concatenate 'str' with non-'str' operand",
        left,
        right,
    )


def _unsupported_string_operator_issue(
    state: VMState,
    solver_check: IsSatFn,
    op: str,
    left: object,
    right: object,
) -> Issue | None:
    """Return an issue for feasible non-string operators involving strings."""
    str_operand_expr = simplify_expr(z3.Or(_can_be_str_expr(left), _can_be_str_expr(right)))
    return _issue_from_type_constraint(
        state,
        solver_check,
        str_operand_expr,
        f"Unsupported operand type(s) for {op} involving 'str'",
        left,
        right,
    )


def _bad_string_repeat_issue(
    state: VMState,
    solver_check: IsSatFn,
    left: object,
    right: object,
) -> Issue | None:
    """Return an issue for feasible sequence multiplication by non-int values."""
    bad_repeat_expr = simplify_expr(
        z3.Or(
            z3.And(_can_be_str_expr(left), z3.Not(_can_be_int_like_expr(right))),
            z3.And(_can_be_str_expr(right), z3.Not(_can_be_int_like_expr(left))),
        ),
    )
    return _issue_from_type_constraint(
        state,
        solver_check,
        bad_repeat_expr,
        "Can't multiply sequence by non-int operand",
        left,
        right,
    )


def _issue_from_type_constraint(
    state: VMState,
    solver_check: IsSatFn,
    type_constraint: z3.BoolRef,
    message: str,
    left: object,
    right: object,
) -> Issue | None:
    """Return a TypeError issue when the type constraint is satisfiable."""
    if z3.is_false(type_constraint):
        return None

    constraints = [*state.path_constraints, type_constraint]
    model = get_model_if_satisfiable_result(constraints, solver_check).model
    if model is None:
        return None

    confidence = 0.5 if is_havoc(left) or is_havoc(right) else 1.0
    return Issue(
        kind=IssueKind.TYPE_ERROR,
        message=message,
        constraints=constraints,
        model=model,
        pc=state.pc,
        confidence=confidence,
    )
