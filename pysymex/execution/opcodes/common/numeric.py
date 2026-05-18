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

"""numeric opcode helpers for versioned arithmetic handlers."""

from __future__ import annotations

import dis
from dataclasses import dataclass
from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol, cast

import z3

from pysymex.core.solver.constraints import quick_contradiction_check
from pysymex.core.solver.engine import is_satisfiable
from pysymex.core.types.scalars import (
    Z3_FALSE,
    Z3_TRUE,
    SymbolicString,
    SymbolicValue,
    py_floor_div,
)
from pysymex.execution.dispatcher import OpcodeResult
from pysymex.core.exceptions import SymbolicException

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher


class _EnhancedMethodProtocol(Protocol):
    def get_call_args(
        self,
        args: tuple[object, ...],
        kwargs: dict[str, object],
    ) -> tuple[tuple[object, ...], dict[str, object]]: ...


SYMBOLIC_POWER_ABSTRACTION = "symbolic_power_abstraction"
SYMBOLIC_SHIFT_ABSTRACTION = "symbolic_shift_abstraction"
SYMBOLIC_BITWISE_ABSTRACTION = "symbolic_bitwise_abstraction"
_MAX_EXACT_SYMBOLIC_EXPONENT = 8

_BINARY_OP_SYMBOL_BY_ARG: dict[int, str] = {
    0: "+",
    1: "&",
    2: "//",
    3: "<<",
    4: "@",
    5: "*",
    6: "%",
    7: "|",
    8: "**",
    9: ">>",
    10: "-",
    11: "/",
    12: "^",
    13: "+=",
    14: "&=",
    15: "//=",
    16: "<<=",
    17: "@=",
    18: "*=",
    19: "%=",
    20: "|=",
    21: "**=",
    22: ">>=",
    23: "-=",
    24: "/=",
    25: "^=",
}


@dataclass(frozen=True, slots=True)
class IntInterval:
    """Represents discovered integer bounds for a symbolic expression."""

    lower: int | None = None
    upper: int | None = None

    def contains_non_negative_small_range(self) -> bool:
        """Return whether the interval is fully bounded inside ``0..8``."""
        if self.lower is None or self.upper is None:
            return False
        return 0 <= self.lower <= self.upper <= _MAX_EXACT_SYMBOLIC_EXPONENT


@dataclass(frozen=True, slots=True)
class _ModeledException(SymbolicException):
    @property
    def name(self) -> str:
        return str(self.exc_type)


def resolve_binary_op_symbol(instr: dis.Instruction) -> str:
    """Resolve a text operator symbol for ``BINARY_OP`` instructions."""
    if instr.argrepr:
        return instr.argrepr.strip()
    if isinstance(instr.argval, str):
        return instr.argval.strip()
    if isinstance(instr.arg, int):
        return _BINARY_OP_SYMBOL_BY_ARG.get(instr.arg, "")
    return ""


def check_division_by_zero(
    right: object,
    state: VMState,
    op: str,
    left: object,
) -> bool:
    """Return whether the current path allows a division-like zero divisor."""
    _ = (op, left)
    if isinstance(right, SymbolicValue):
        return _path_is_sat([*state.path_constraints.to_list(), right.z3_int == z3.IntVal(0)])
    return isinstance(right, (int, float, bool)) and right == 0


def check_negative_shift(
    right: object,
    state: VMState,
    op: str,
    left: object,
) -> bool:
    """Return whether the current path allows a negative shift count."""
    _ = (op, left)
    if isinstance(right, SymbolicValue):
        return _path_is_sat([*state.path_constraints.to_list(), right.z3_int < z3.IntVal(0)])
    return isinstance(right, int) and right < 0


_BINARY_DUNDER_BY_OP: dict[str, str] = {
    "+": "__add__",
    "-": "__sub__",
    "*": "__mul__",
    "/": "__truediv__",
    "//": "__floordiv__",
    "%": "__mod__",
    "**": "__pow__",
    "<<": "__lshift__",
    ">>": "__rshift__",
    "&": "__and__",
    "|": "__or__",
    "^": "__xor__",
}


def handle_numeric_binary_op(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher | None = None,
) -> OpcodeResult:
    """Execute Python-faithful numeric ``BINARY_OP`` semantics."""
    op_symbol = resolve_binary_op_symbol(instr)
    if not op_symbol:
        return _push_havoc_result(state, f"binop_havoc_{state.pc}")
    base_op = op_symbol[:-1] if op_symbol.endswith("=") else op_symbol
    if base_op not in {"+", "-", "*", "/", "//", "%", "**", "<<", ">>", "&", "|", "^"}:
        return _push_havoc_result(state, f"binop_havoc_{state.pc}")

    right = state.pop()
    left = state.pop()

    dunder_result = _try_binary_dunder_call(state, ctx, left, right, base_op)
    if dunder_result is not None:
        return dunder_result

    if isinstance(left, SymbolicString) or isinstance(right, SymbolicString):
        return _push_havoc_result(state, f"binop_{base_op}_{state.pc}")

    left_value = SymbolicValue.from_const(left)
    right_value = SymbolicValue.from_const(right)

    if base_op in {"+", "-", "*", "/", "//", "%"}:
        return _handle_standard_numeric_op(instr, state, ctx, left_value, right_value, base_op)
    if base_op == "**":
        return _handle_power_op(state, left_value, right_value)
    if base_op in {"<<", ">>"}:
        return _handle_shift_op(state, left_value, right_value, base_op)
    return _handle_bitwise_op(state, left_value, right_value, base_op)


def _try_binary_dunder_call(
    state: VMState,
    ctx: OpcodeDispatcher | None,
    left: object,
    right: object,
    op_symbol: str,
) -> OpcodeResult | None:
    if ctx is None:
        return None
    method_name = _BINARY_DUNDER_BY_OP.get(op_symbol)
    if method_name is None:
        return None
    method = _lookup_enhanced_method(left, method_name)
    if method is None:
        return None

    from pysymex.execution.opcodes.common.functions import perform_interprocedural_call

    return perform_interprocedural_call(state, ctx, method, [cast("StackValue", right)], {})


def _lookup_enhanced_method(value: object, method_name: str) -> _EnhancedMethodProtocol | None:
    try:
        enhanced = object.__getattribute__(value, "_enhanced_object")
    except AttributeError:
        return None
    get_attribute = getattr(enhanced, "get_attribute", None)
    if not callable(get_attribute):
        return None
    typed_get_attribute = cast(
        "Callable[[str, object | None], tuple[object, bool]]",
        get_attribute,
    )
    method, found = typed_get_attribute(method_name, value)
    if not found:
        return None
    if hasattr(method, "get_call_args") and callable(getattr(method, "get_call_args", None)):
        return cast("_EnhancedMethodProtocol", method)
    return None


def handle_unary_invert(state: VMState) -> OpcodeResult:
    """Execute Python-faithful unary invert semantics."""
    value = state.pop()
    symbolic = SymbolicValue.from_const(value)
    result = symbolic.__invert__()
    state = state.push(result)
    return OpcodeResult.continue_with(state.advance_pc())


def _handle_standard_numeric_op(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher | None,
    left: SymbolicValue,
    right: SymbolicValue,
    op_symbol: str,
) -> OpcodeResult:
    """Delegate arithmetic to ``SymbolicValue`` for faithful typing semantics."""
    if op_symbol in {"/", "//", "%"}:
        zero_condition = _division_by_zero_condition(right)
        constraints = state.path_constraints.to_list()
        zero_feasible = _path_is_sat([*constraints, zero_condition])
        if zero_feasible:
            nonzero_condition = z3.Not(zero_condition)
            states: list[VMState] = []
            if _path_is_sat([*constraints, nonzero_condition]):
                success_state = state.fork().add_constraint(nonzero_condition)
                success_result = _continue_standard_numeric_op(
                    success_state,
                    left,
                    right,
                    op_symbol,
                )
                states.extend(success_result.new_states)

            handler_state = _jump_to_modeled_exception_handler(
                state.fork().add_constraint(zero_condition),
                ctx,
                instr,
                "ZeroDivisionError",
            )
            if handler_state is not None:
                states.append(handler_state)

            if states:
                return OpcodeResult.branch(states)
            return OpcodeResult.terminate()

    return _continue_standard_numeric_op(state, left, right, op_symbol)


def _continue_standard_numeric_op(
    state: VMState,
    left: SymbolicValue,
    right: SymbolicValue,
    op_symbol: str,
) -> OpcodeResult:
    try:
        if op_symbol == "+":
            result = left + right
        elif op_symbol == "-":
            result = left - right
        elif op_symbol == "*":
            result = left * right
        elif op_symbol == "/":
            result = left / right
        elif op_symbol == "//":
            result = left // right
        else:
            result = left % right
    except ZeroDivisionError:
        return OpcodeResult.terminate()
    state = state.push(result)
    return OpcodeResult.continue_with(state.advance_pc())


def _division_by_zero_condition(right: SymbolicValue) -> z3.BoolRef:
    return z3.Or(
        z3.And(right.is_int, right.z3_int == z3.IntVal(0)),
        z3.And(right.is_float, z3.fpIsZero(right.z3_float)),
    )


def _jump_to_modeled_exception_handler(
    state: VMState,
    ctx: OpcodeDispatcher | None,
    instr: dis.Instruction,
    exception_name: str,
) -> VMState | None:
    if ctx is None:
        return None

    from pysymex.execution.opcodes.common.exceptions import jump_to_exception_handler

    exc: StackValue = _ModeledException(exception_name)
    return jump_to_exception_handler(state, ctx, instr.offset, exc)


def _handle_power_op(state: VMState, left: SymbolicValue, right: SymbolicValue) -> OpcodeResult:
    """Execute exponentiation with bounded exactness and explicit abstraction."""
    concrete_exponent = _extract_concrete_int(right)
    if concrete_exponent is not None:
        try:
            result = left**right
        except ZeroDivisionError:
            return OpcodeResult.terminate()
        state = state.push(result)
        return OpcodeResult.continue_with(state.advance_pc())

    interval = _extract_interval(state.path_constraints.to_list(), right.z3_int)
    if interval.contains_non_negative_small_range() and _is_int_like(left):
        assert interval.lower is not None
        assert interval.upper is not None
        result = _make_int_value(
            name=f"pow_{state.pc}",
            expr=_piecewise_exact_power(left.z3_int, right.z3_int, interval.lower, interval.upper),
        )
        state = state.push(result)
        return OpcodeResult.continue_with(state.advance_pc())

    abstract = _fresh_symbolic_int(f"pow_{state.pc}")
    state = state.push(abstract)
    return OpcodeResult.continue_with(
        state.advance_pc(),
        degraded_passes=[SYMBOLIC_POWER_ABSTRACTION],
    )


def _handle_shift_op(
    state: VMState,
    left: SymbolicValue,
    right: SymbolicValue,
    op_symbol: str,
) -> OpcodeResult:
    """Execute shift operations with exact concrete semantics or bounded abstraction."""
    concrete_shift = _extract_concrete_int(right)
    if concrete_shift is not None:
        if concrete_shift < 0:
            return OpcodeResult.terminate()
        factor = 1 << concrete_shift
        if op_symbol == "<<":
            expr = left.z3_int * z3.IntVal(factor)
        else:
            expr = py_floor_div(left.z3_int, z3.IntVal(factor))
        result = _make_int_value(name=f"shift_{state.pc}", expr=expr)
        state = state.push(result)
        return OpcodeResult.continue_with(state.advance_pc())

    interval = _extract_interval(state.path_constraints.to_list(), right.z3_int)
    if interval.contains_non_negative_small_range():
        assert interval.lower is not None
        assert interval.upper is not None
        if op_symbol == "<<":
            expr = _piecewise_exact_shift_left(
                left.z3_int, right.z3_int, interval.lower, interval.upper
            )
        else:
            expr = _piecewise_exact_shift_right(
                left.z3_int,
                right.z3_int,
                interval.lower,
                interval.upper,
            )
        result = _make_int_value(name=f"shift_{state.pc}", expr=expr)
        state = state.push(result)
        return OpcodeResult.continue_with(state.advance_pc())

    abstract = _fresh_symbolic_int(f"shift_{state.pc}")
    state = state.push(abstract)
    return OpcodeResult.continue_with(
        state.advance_pc(),
        degraded_passes=[SYMBOLIC_SHIFT_ABSTRACTION],
    )


def _handle_bitwise_op(
    state: VMState,
    left: SymbolicValue,
    right: SymbolicValue,
    op_symbol: str,
) -> OpcodeResult:
    """Execute bitwise operations with exact concrete cases and explicit abstraction."""
    left_constant = _extract_concrete_int(left)
    right_constant = _extract_concrete_int(right)
    if left_constant is not None and right_constant is not None:
        if op_symbol == "&":
            result = left & right
        elif op_symbol == "|":
            result = left | right
        else:
            result = left ^ right
        state = state.push(result)
        return OpcodeResult.continue_with(state.advance_pc())

    if op_symbol == "&":
        masked = _extract_non_negative_masked_value(left, right)
        if masked is not None:
            mask, value = masked
            width = max(1, mask.bit_length())
            expr = z3.BV2Int(
                z3.Int2BV(value.z3_int, width) & z3.BitVecVal(mask, width), is_signed=False
            )
            result = _make_int_value(name=f"mask_{state.pc}", expr=expr, min_val=0, max_val=mask)
            state = state.push(result)
            return OpcodeResult.continue_with(state.advance_pc())

    if op_symbol == "&":
        result = left & right
    elif op_symbol == "|":
        result = left | right
    else:
        result = left ^ right
    state = state.push(result)
    return OpcodeResult.continue_with(state.advance_pc())


def _extract_interval(constraints: list[z3.BoolRef], symbol: z3.ArithRef) -> IntInterval:
    """Extract simple integer bounds for *symbol* from the current path."""
    interval = IntInterval()
    lower = interval.lower
    upper = interval.upper

    for constraint in constraints:
        normalized = _normalize_constraint(constraint)
        if normalized is None:
            continue
        relation, value = normalized
        if not _matches_symbol(relation[0], symbol):
            continue
        operator_name = relation[1]
        if operator_name == "==":
            lower = value if lower is None else max(lower, value)
            upper = value if upper is None else min(upper, value)
        elif operator_name == ">=":
            lower = value if lower is None else max(lower, value)
        elif operator_name == ">":
            lower = (value + 1) if lower is None else max(lower, value + 1)
        elif operator_name == "<=":
            upper = value if upper is None else min(upper, value)
        elif operator_name == "<":
            upper = (value - 1) if upper is None else min(upper, value - 1)

    return IntInterval(lower=lower, upper=upper)


def _normalize_constraint(
    constraint: z3.BoolRef,
) -> tuple[tuple[z3.ExprRef, str], int] | None:
    """Normalize simple constraints to ``(symbol, operator, constant)`` form."""
    target = constraint
    negated = False
    if target.decl().kind() == z3.Z3_OP_NOT and target.num_args() == 1:
        target = target.arg(0)
        negated = True

    if target.num_args() != 2:
        return None

    left = target.arg(0)
    right = target.arg(1)
    left_constant = _extract_int_constant(left)
    right_constant = _extract_int_constant(right)

    kind = target.decl().kind()
    if left_constant is None and right_constant is None:
        return None

    if left_constant is not None and right_constant is None:
        relation = _relation_from_kind(kind, negated, swapped=True)
        if relation is None:
            return None
        return ((right, relation), left_constant)

    if right_constant is not None and left_constant is None:
        relation = _relation_from_kind(kind, negated, swapped=False)
        if relation is None:
            return None
        return ((left, relation), right_constant)

    return None


def _relation_from_kind(kind: int, negated: bool, swapped: bool) -> str | None:
    """Map a Z3 comparator kind to a normalized operator string."""
    direct: dict[int, str] = {
        z3.Z3_OP_EQ: "==",
        z3.Z3_OP_GE: ">=",
        z3.Z3_OP_GT: ">",
        z3.Z3_OP_LE: "<=",
        z3.Z3_OP_LT: "<",
    }
    inverse: dict[str, str] = {
        "==": "!=",
        ">=": "<",
        ">": "<=",
        "<=": ">",
        "<": ">=",
    }
    swapped_map: dict[str, str] = {
        ">=": "<=",
        ">": "<",
        "<=": ">=",
        "<": ">",
        "==": "==",
    }
    relation = direct.get(kind)
    if relation is None:
        return None
    if swapped:
        relation = swapped_map[relation]
    if negated:
        relation = inverse.get(relation)
    return relation if relation in {"==", ">=", ">", "<=", "<"} else None


def _matches_symbol(candidate: z3.ExprRef, symbol: z3.ArithRef) -> bool:
    """Return whether *candidate* and *symbol* refer to the same Z3 AST."""
    return z3.eq(candidate, symbol)


def _extract_int_constant(expr: z3.ExprRef) -> int | None:
    """Extract a Python integer from a Z3 integer numeral expression."""
    if isinstance(expr, z3.IntNumRef):
        return expr.as_long()
    return None


def _piecewise_exact_power(
    base: z3.ArithRef,
    exponent: z3.ArithRef,
    lower: int,
    upper: int,
) -> z3.ArithRef:
    """Encode exact bounded exponentiation over a small non-negative range."""
    values = list(range(lower, upper + 1))
    tail = _exact_power_expr(base, values[-1])
    for value in reversed(values[:-1]):
        tail = z3.If(exponent == value, _exact_power_expr(base, value), tail)
    return tail


def _piecewise_exact_shift_left(
    value: z3.ArithRef,
    shift: z3.ArithRef,
    lower: int,
    upper: int,
) -> z3.ArithRef:
    """Encode exact left shift over a small non-negative shift interval."""
    values = list(range(lower, upper + 1))
    tail = value * z3.IntVal(1 << values[-1])
    for current in reversed(values[:-1]):
        tail = z3.If(shift == current, value * z3.IntVal(1 << current), tail)
    return tail


def _piecewise_exact_shift_right(
    value: z3.ArithRef,
    shift: z3.ArithRef,
    lower: int,
    upper: int,
) -> z3.ArithRef:
    """Encode exact right shift over a small non-negative shift interval."""
    values = list(range(lower, upper + 1))
    tail = py_floor_div(value, z3.IntVal(1 << values[-1]))
    for current in reversed(values[:-1]):
        tail = z3.If(shift == current, py_floor_div(value, z3.IntVal(1 << current)), tail)
    return tail


def _exact_power_expr(base: z3.ArithRef, exponent: int) -> z3.ArithRef:
    """Build repeated-multiplication power expressions for small exponents."""
    result = z3.IntVal(1)
    for _ in range(exponent):
        result = result * base
    return result


def _extract_non_negative_masked_value(
    left: SymbolicValue,
    right: SymbolicValue,
) -> tuple[int, SymbolicValue] | None:
    """Extract a concrete non-negative mask and its paired symbolic operand."""
    left_constant = _extract_concrete_int(left)
    if left_constant is not None and left_constant >= 0:
        return left_constant, right
    right_constant = _extract_concrete_int(right)
    if right_constant is not None and right_constant >= 0:
        return right_constant, left
    return None


def _extract_concrete_int(value: SymbolicValue) -> int | None:
    """Extract a concrete integer or boolean value when available."""
    constant = value.value
    if isinstance(constant, bool):
        return int(constant)
    if isinstance(constant, int):
        return constant
    return None


def _fresh_symbolic_int(name: str) -> SymbolicValue:
    """Create a fresh symbolic integer result."""
    symbolic, _ = SymbolicValue.symbolic_int(name)
    return symbolic


def _make_int_value(
    *,
    name: str,
    expr: z3.ArithRef,
    min_val: int | None = None,
    max_val: int | None = None,
) -> SymbolicValue:
    """Create an integer-typed ``SymbolicValue`` for an exact numeric result."""
    return SymbolicValue(
        _name=name,
        z3_int=expr,
        is_int=Z3_TRUE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_float=Z3_FALSE,
        affinity_type="int",
        min_val=min_val,
        max_val=max_val,
    )


def _is_int_like(value: SymbolicValue) -> bool:
    """Return whether the symbolic value is explicitly integer-typed."""
    return value.affinity_type in {"int", "bool"}


def _push_havoc_result(state: VMState, name: str) -> OpcodeResult:
    """Push a fresh generic symbolic value for unsupported arithmetic cases."""
    value, constraint = SymbolicValue.symbolic(name)
    state = state.add_constraint(constraint)
    state = state.push(value)
    return OpcodeResult.continue_with(state.advance_pc())


def _path_is_sat(constraints: list[z3.BoolRef]) -> bool:
    """Check satisfiability with the same cheap deep-path fallback as opcode handlers."""
    if len(constraints) < 12:
        return is_satisfiable(constraints)
    return not quick_contradiction_check(constraints)
