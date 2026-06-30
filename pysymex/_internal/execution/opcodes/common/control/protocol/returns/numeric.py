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

"""Numeric protocol return normalization."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.opcodes.common.control.protocol.returns.objects import (
    ProtocolObjectPredicates,
)
from pysymex._internal.execution.opcodes.common.numeric.labels import UNSUPPORTED_NUMERIC_REFLECTION

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import CallFrame
    from pysymex._internal.typing.protocols import StackValue

_INDEX_PROTOCOLS = {
    "__index_value__",
    "__index_subscr__",
    "__index_slice_start__",
    "__index_slice_stop__",
    "__index_built_slice_start__",
    "__index_built_slice_stop__",
    "__index_built_slice_step__",
}


def normalize_numeric(
    frame: CallFrame,
    return_value: StackValue | None,
    state: VMState,
) -> tuple[StackValue | None, Issue | None, str | None] | None:
    """Normalize numeric conversion and reflection protocol returns."""
    if frame.protocol_method == "__int_value__":
        return _normalize_integral_return(return_value, state, method_name="__int__")

    if frame.protocol_method in _INDEX_PROTOCOLS:
        return _normalize_integral_return(return_value, state, method_name="__index__")

    if frame.protocol_method == "__float_value__":
        return _normalize_float_return(return_value, state)

    if (
        frame.protocol_method == "__numeric__"
        and not frame.protocol_fallbacks
        and _is_not_implemented(return_value)
    ):
        if _has_definite_numeric_type_error(frame):
            return (
                return_value,
                Issue(
                    kind=IssueKind.TYPE_ERROR,
                    message="Possible TypeError: numeric methods returned NotImplemented",
                    constraints=list(state.path_constraints),
                    pc=state.pc,
                ),
                None,
            )
        return return_value, None, UNSUPPORTED_NUMERIC_REFLECTION
    return None


def _normalize_integral_return(
    return_value: StackValue | None,
    state: VMState,
    *,
    method_name: str,
) -> tuple[StackValue | None, Issue | None, str | None]:
    """Normalize ``__int__`` or ``__index__`` result values."""
    concrete_value = return_value.value if isinstance(return_value, SymbolicValue) else return_value
    if isinstance(concrete_value, bool):
        return SymbolicValue.from_const(int(concrete_value)), None, None
    if isinstance(concrete_value, int):
        return SymbolicValue.from_const(concrete_value), None, None
    if isinstance(return_value, SymbolicValue) and z3.is_true(simplify_expr(return_value.is_int)):
        return return_value, None, None
    return (
        return_value,
        Issue(
            kind=IssueKind.TYPE_ERROR,
            message=f"Possible TypeError: {method_name} returned non-int",
            constraints=list(state.path_constraints),
            pc=state.pc,
        ),
        None,
    )


def _normalize_float_return(
    return_value: StackValue | None,
    state: VMState,
) -> tuple[StackValue | None, Issue | None, str | None]:
    """Normalize ``__float__`` result values."""
    concrete_value = return_value.value if isinstance(return_value, SymbolicValue) else return_value
    if isinstance(concrete_value, float):
        return SymbolicValue.from_const(concrete_value), None, None
    if isinstance(return_value, SymbolicValue) and z3.is_true(simplify_expr(return_value.is_float)):
        return return_value, None, None
    return (
        return_value,
        Issue(
            kind=IssueKind.TYPE_ERROR,
            message="Possible TypeError: __float__ returned non-float",
            constraints=list(state.path_constraints),
            pc=state.pc,
        ),
        None,
    )


def _has_definite_numeric_type_error(frame: CallFrame) -> bool:
    """Return whether retained operands guarantee a numeric ``TypeError``."""
    retained = frame.protocol_retained_operand
    if not isinstance(retained, tuple):
        return False
    operands = cast("tuple[StackValue, ...]", retained)
    if len(operands) != 3:
        return False
    left, right = operands[1], operands[2]
    if ProtocolObjectPredicates.is_modeled(left) and ProtocolObjectPredicates.is_modeled(right):
        return True
    from pysymex._internal.core.classes.instances import SymbolicInstance

    for modeled, primitive in ((left, right), (right, left)):
        if not ProtocolObjectPredicates.is_modeled(
            modeled,
        ) or not ProtocolObjectPredicates.is_non_object(primitive):
            continue
        instance = getattr(modeled, "_modeled_object", None)
        return isinstance(instance, SymbolicInstance) and bool(
            getattr(instance.cls, "_pysymex_bases_complete", False),
        )
    return False


def _is_not_implemented(value: StackValue | None) -> bool:
    """Return whether *value* is a concrete or wrapped ``NotImplemented`` result."""
    return value is NotImplemented or (
        isinstance(value, SymbolicValue) and value.value is NotImplemented
    )
