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

"""Numeric opcode helpers: dunder dispatch, division/shift guards, and havoc tags.

Centralizes modeled binary operator routing, satisfiability checks for exceptional
paths, and degradation constants consumed by :mod:`pysymex.execution.opcodes.common.numeric.ops`.
Does not register opcodes directly.
"""

from __future__ import annotations

import dis
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, cast

import z3
from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.state.types import ProtocolCallCandidate
from pysymex.core.constants import Z3_FALSE
from pysymex.core.constants import Z3_TRUE
from pysymex.core.constants import Z3_ZERO
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.analysis.static.arithmetic.conditions import tagged_numeric_zero_condition
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.numeric.fallbacks import unsupported_numeric_event
from pysymex.execution.opcodes.common.numeric.labels import UNSUPPORTED_NUMERIC_ABSTRACTION
from pysymex.execution.opcodes.common.path_feasibility import path_is_sat

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


class ModeledMethodProtocol(Protocol):
    """Structural protocol for modeled callables exposing argument normalization."""

    def get_call_args(
        self,
        args: tuple[object, ...],
        kwargs: dict[str, object],
    ) -> tuple[tuple[object, ...], dict[str, object]]:
        """Return CPython-ordered positional and keyword arguments for a modeled call."""
        ...


MAX_EXACT_SYMBOLIC_EXPONENT = 8


@dataclass(frozen=True, slots=True)
class ModeledException(SymbolicException):
    """Lightweight exception placeholder routed through opcode exception handlers."""

    @property
    def name(self) -> str:
        """Return the exception type name used by opcode exception routing."""
        return str(self.exc_type)


def _right_reflection_precedes_direct(left: object, right: object, reflected_method: str) -> bool:
    """Return whether a proven strict subclass declares priority reflection."""
    from pysymex.models.objects import SymbolicInstance

    left_instance = getattr(left, "_modeled_object", None)
    right_instance = getattr(right, "_modeled_object", None)
    if not isinstance(left_instance, SymbolicInstance) or not isinstance(
        right_instance, SymbolicInstance
    ):
        return False
    right_class = right_instance.cls
    return (
        right_class is not left_instance.cls
        and bool(getattr(right_class, "_pysymex_bases_complete", False))
        and right_class.is_subclass_of(left_instance.cls)
        and reflected_method in right_class.methods
    )


def try_binary_dunder_call(
    state: VMState,
    ctx: OpcodeDispatcher | None,
    left: object,
    right: object,
    op_symbol: str,
) -> OpcodeResult | None:
    """Call modeled binary dunders in CPython dispatch order where supported."""
    if ctx is None:
        return None
    base_op = op_symbol[:-1] if op_symbol.endswith("=") else op_symbol
    direct_method = BINARY_DUNDER_BY_OP.get(base_op)
    reflected_method = REFLECTED_DUNDER_BY_OP.get(base_op)
    if direct_method is None or reflected_method is None:
        return None
    candidates: list[tuple[object, str, object]] = []
    if op_symbol.endswith("="):
        in_place_method = INPLACE_DUNDER_BY_OP.get(base_op)
        if in_place_method is not None:
            candidates.append((left, in_place_method, right))
    binary_candidates = [(left, direct_method, right), (right, reflected_method, left)]
    if _right_reflection_precedes_direct(left, right, reflected_method):
        binary_candidates.reverse()
    candidates.extend(binary_candidates)

    protocol_candidates: list[ProtocolCallCandidate] = []
    for owner, method_name, argument in candidates:
        method = lookup_modeled_method(owner, method_name)
        if method is None:
            continue
        protocol_candidates.append(
            ProtocolCallCandidate(
                owner=cast("StackValue", owner),
                method_name=method_name,
                argument=cast("StackValue", argument),
            )
        )
    if not protocol_candidates:
        return None
    from pysymex.execution.calls.interprocedural import (
        perform_interprocedural_call_impl,
    )

    first = protocol_candidates[0]
    first_method = lookup_modeled_method(first.owner, first.method_name)
    if first_method is not None:
        result = perform_interprocedural_call_impl(
            state,
            ctx,
            first_method,
            [first.owner, first.argument],
            {},
            protocol_method="__numeric__",
            protocol_retained_operand=(
                op_symbol,
                cast("StackValue", left),
                cast("StackValue", right),
            ),
            protocol_fallbacks=tuple(protocol_candidates[1:]),
        )
        if result is not None:
            return result
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[UNSUPPORTED_NUMERIC_ABSTRACTION],
        fallback_events=[
            unsupported_numeric_event(
                state=state,
                reason=f"modeled binary numeric protocol for {op_symbol!r} could not be entered",
                unsupported_protocol=True,
            )
        ],
        terminal=True,
    )


def lookup_modeled_method(value: object, method_name: str) -> ModeledMethodProtocol | None:
    """Return a modeled-object method implementation when one is installed."""
    try:
        modeled_object = object.__getattribute__(value, "_modeled_object")
    except AttributeError:
        return None
    get_attribute = getattr(modeled_object, "get_attribute", None)
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
        return cast("ModeledMethodProtocol", method)
    return None


def check_division_by_zero(
    right: object,
    state: VMState,
    op: str,
    left: object,
) -> bool:
    """Return whether the current path allows a division-like zero divisor."""
    _ = (op, left)
    if isinstance(right, SymbolicValue):
        return path_is_sat([*state.path_constraints.to_list(), right.z3_int == Z3_ZERO])
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
        return path_is_sat([*state.path_constraints.to_list(), right.z3_int < Z3_ZERO])
    return isinstance(right, int) and right < 0


def division_by_zero_condition(right: SymbolicValue, is_truediv: bool = False) -> z3.BoolRef:
    """Build the zero-divisor condition used by division-like opcodes."""
    return tagged_numeric_zero_condition(
        concrete_value=right.value,
        affinity_type=right.affinity_type,
        is_int=right.is_int,
        int_expr=right.z3_int,
        is_bool=right.is_bool,
        bool_expr=right.z3_bool,
        is_float=right.is_float,
        float_expr=right.z3_float,
        include_float=not is_truediv,
    )


def jump_to_modeled_exception_handler(
    state: VMState,
    ctx: OpcodeDispatcher | None,
    instr: dis.Instruction,
    exception_name: str,
) -> VMState | None:
    """Route a modeled exception through the current exception handler, if any."""
    if ctx is None:
        return None

    from pysymex.execution.opcodes.common.exceptions import jump_to_exception_handler

    exc: StackValue = ModeledException(exception_name)
    return jump_to_exception_handler(state, ctx, instr.offset, exc)


BINARY_DUNDER_BY_OP: dict[str, str] = {
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
REFLECTED_DUNDER_BY_OP: dict[str, str] = {
    "+": "__radd__",
    "-": "__rsub__",
    "*": "__rmul__",
    "/": "__rtruediv__",
    "//": "__rfloordiv__",
    "%": "__rmod__",
    "**": "__rpow__",
    "<<": "__rlshift__",
    ">>": "__rrshift__",
    "&": "__rand__",
    "|": "__ror__",
    "^": "__rxor__",
}
INPLACE_DUNDER_BY_OP: dict[str, str] = {
    "+": "__iadd__",
    "-": "__isub__",
    "*": "__imul__",
    "/": "__itruediv__",
    "//": "__ifloordiv__",
    "%": "__imod__",
    "**": "__ipow__",
    "<<": "__ilshift__",
    ">>": "__irshift__",
    "&": "__iand__",
    "|": "__ior__",
    "^": "__ixor__",
}


def extract_non_negative_masked_value(
    left: SymbolicValue,
    right: SymbolicValue,
) -> tuple[int, SymbolicValue] | None:
    """Extract a concrete non-negative mask and its paired symbolic operand."""
    left_constant = extract_concrete_int(left)
    if left_constant is not None and left_constant >= 0:
        return left_constant, right
    right_constant = extract_concrete_int(right)
    if right_constant is not None and right_constant >= 0:
        return right_constant, left
    return None


def extract_concrete_int(value: SymbolicValue) -> int | None:
    """Extract a concrete integer or boolean value when available."""
    constant = value.value
    if isinstance(constant, bool):
        return int(constant)
    if isinstance(constant, int):
        return constant
    return None


def fresh_symbolic_int(name: str) -> SymbolicValue:
    """Create a fresh symbolic integer result."""
    symbolic, _ = SymbolicValue.symbolic_int(name)
    return symbolic


def make_int_value(
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


def is_int_like(value: SymbolicValue) -> bool:
    """Return whether the symbolic value is explicitly integer-typed."""
    return value.affinity_type in {"int", "bool"}


def push_havoc_result(state: VMState, name: str) -> OpcodeResult:
    """Push a fresh generic symbolic value for unsupported arithmetic cases."""
    fallback_event = unsupported_numeric_event(
        state=state,
        reason=f"unsupported numeric operation {name!r} produced a havoc value",
    )
    value, constraint = SymbolicValue.symbolic(name)
    state = state.add_constraint(constraint)
    state = state.push(value)
    return OpcodeResult.continue_with(
        state.advance_pc(),
        degraded_passes=[UNSUPPORTED_NUMERIC_ABSTRACTION],
        fallback_events=[fallback_event],
    )
