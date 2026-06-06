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

"""Validate and normalize return values from suspended dunder protocol calls.

Runs when a modeled interprocedural call completes (``CallFrame.protocol_method`` set).
Coerces truth, ``__len__``, ``__int__``, ``__index__``, ``__float__``, rich compare, and
``__init__`` returns into CPython-shaped stack values or emits ``TYPE_ERROR`` issues.
Delegates construction returns to
:mod:`pysymex.execution.opcodes.common.control.lifecycle_returns` and membership
continuations to :mod:`pysymex.execution.opcodes.common.control.truth_continuations`.

Limitations:
    Identity and numeric TypeError shortcuts apply only when modeled-instance tags are
    definite; ambiguous symbolic carriers may pass through without normalization.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.opcodes.common.control.protocol.fallbacks import (
    UNSUPPORTED_COMPARISON_REFLECTION,
    UNSUPPORTED_INIT_RETURN_PROTOCOL,
)
from pysymex.execution.opcodes.common.numeric.labels import UNSUPPORTED_NUMERIC_REFLECTION

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.types import CallFrame
    from pysymex.core.state.record import VMState

_MEMBERSHIP_BOOL_PROTOCOLS = {
    "__contains___truth_bool__",
    "__contains_not___truth_bool__",
}


def _is_definite_modeled_object(value: StackValue) -> bool:
    """Return whether the value is definitely a modeled heap object."""
    return (
        isinstance(value, SymbolicValue)
        and getattr(value, "_modeled_object", None) is not None
        and z3.is_true(z3.simplify(value.is_obj))
    )


def _is_definite_non_object(value: StackValue) -> bool:
    """Return whether the value is definitely not a heap object."""
    if isinstance(value, SymbolicNone):
        return True
    if isinstance(value, SymbolicValue):
        return z3.is_false(z3.simplify(value.is_obj))
    return value is None or isinstance(value, (bool, int, float, str, bytes))


def _modeled_instance_id(value: StackValue) -> int | None:
    """Return the modeled instance id when the value is a definite instance."""
    if not _is_definite_modeled_object(value):
        return None
    from pysymex.models.objects import SymbolicInstance

    modeled_object = getattr(value, "_modeled_object", None)
    if not isinstance(modeled_object, SymbolicInstance):
        return None
    return modeled_object.instance_id


def _complete_definite_identity_comparison(frame: CallFrame) -> SymbolicValue | None:
    """Synthesize a bool result for definite rich-comparison identity cases."""
    retained = frame.protocol_retained_operand
    if not isinstance(retained, tuple):
        return None
    operands = cast("tuple[StackValue, ...]", retained)
    if len(operands) != 2:
        return None
    left, right = operands
    if left is right:
        is_identical = True
    elif (left_id := _modeled_instance_id(left)) is not None and (
        right_id := _modeled_instance_id(right)
    ) is not None:
        is_identical = left_id == right_id
    elif (_is_definite_modeled_object(left) and _is_definite_non_object(right)) or (
        _is_definite_modeled_object(right) and _is_definite_non_object(left)
    ):
        is_identical = False
    else:
        return None
    result = not is_identical if frame.protocol_method == "__richcmp_ne__" else is_identical
    return SymbolicValue.from_const(result)


def _has_definite_numeric_type_error(frame: CallFrame) -> bool:
    """Return whether retained operands guarantee a numeric ``TypeError``."""
    retained = frame.protocol_retained_operand
    if not isinstance(retained, tuple):
        return False
    operands = cast("tuple[StackValue, ...]", retained)
    if len(operands) != 3:
        return False
    left, right = operands[1], operands[2]
    if _is_definite_modeled_object(left) and _is_definite_modeled_object(right):
        return True
    from pysymex.models.objects import SymbolicInstance

    for modeled, primitive in ((left, right), (right, left)):
        if not _is_definite_modeled_object(modeled) or not _is_definite_non_object(primitive):
            continue
        instance = getattr(modeled, "_modeled_object", None)
        return isinstance(instance, SymbolicInstance) and bool(
            getattr(instance.cls, "_pysymex_bases_complete", False)
        )
    return False


def normalize_truth_protocol_return(
    frame: CallFrame,
    return_value: StackValue | None,
    state: VMState,
) -> tuple[StackValue | None, Issue | None, str | None]:
    """Normalize modeled truth protocol returns or expose unsupported precision."""
    if frame.is_init_call:
        if return_value is None or isinstance(return_value, SymbolicNone):
            return return_value, None, None
        if isinstance(return_value, SymbolicValue) and not z3.is_false(
            z3.simplify(return_value.is_none)
        ):
            return return_value, None, UNSUPPORTED_INIT_RETURN_PROTOCOL
        return (
            return_value,
            Issue(
                kind=IssueKind.TYPE_ERROR,
                message="Possible TypeError: __init__() should return None",
                constraints=list(state.path_constraints),
                pc=state.pc,
            ),
            None,
        )

    from pysymex.execution.opcodes.common.control.lifecycle_returns import (
        normalize_construction_protocol_return,
    )

    construction_result = normalize_construction_protocol_return(frame, return_value)
    if construction_result is not None:
        return construction_result

    if frame.protocol_method == "__iter__":
        if isinstance(return_value, SymbolicValue):
            from pysymex.execution.opcodes.common.numeric.helpers import lookup_modeled_method

            if lookup_modeled_method(return_value, "__next__") is not None:
                return return_value, None, None
        return (
            return_value,
            Issue(
                kind=IssueKind.TYPE_ERROR,
                message="Possible TypeError: iter() returned non-iterator",
                constraints=list(state.path_constraints),
                pc=state.pc,
            ),
            None,
        )

    if frame.protocol_method == "__int_value__":
        concrete_value = (
            return_value.value if isinstance(return_value, SymbolicValue) else return_value
        )
        if isinstance(concrete_value, bool):
            return SymbolicValue.from_const(int(concrete_value)), None, None
        if isinstance(concrete_value, int):
            return SymbolicValue.from_const(concrete_value), None, None
        if isinstance(return_value, SymbolicValue) and z3.is_true(z3.simplify(return_value.is_int)):
            return return_value, None, None
        return (
            return_value,
            Issue(
                kind=IssueKind.TYPE_ERROR,
                message="Possible TypeError: __int__ returned non-int",
                constraints=list(state.path_constraints),
                pc=state.pc,
            ),
            None,
        )

    if frame.protocol_method in {
        "__index_value__",
        "__index_subscr__",
        "__index_slice_start__",
        "__index_slice_stop__",
        "__index_built_slice_start__",
        "__index_built_slice_stop__",
        "__index_built_slice_step__",
    }:
        concrete_value = (
            return_value.value if isinstance(return_value, SymbolicValue) else return_value
        )
        if isinstance(concrete_value, bool):
            return SymbolicValue.from_const(int(concrete_value)), None, None
        if isinstance(concrete_value, int):
            return SymbolicValue.from_const(concrete_value), None, None
        if isinstance(return_value, SymbolicValue) and z3.is_true(z3.simplify(return_value.is_int)):
            return return_value, None, None
        return (
            return_value,
            Issue(
                kind=IssueKind.TYPE_ERROR,
                message="Possible TypeError: __index__ returned non-int",
                constraints=list(state.path_constraints),
                pc=state.pc,
            ),
            None,
        )

    if frame.protocol_method == "__float_value__":
        concrete_value = (
            return_value.value if isinstance(return_value, SymbolicValue) else return_value
        )
        if isinstance(concrete_value, float):
            return SymbolicValue.from_const(concrete_value), None, None
        if isinstance(return_value, SymbolicValue) and z3.is_true(
            z3.simplify(return_value.is_float)
        ):
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

    if (
        frame.protocol_method == "__numeric__"
        and not frame.protocol_fallbacks
        and (
            return_value is NotImplemented
            or (isinstance(return_value, SymbolicValue) and return_value.value is NotImplemented)
        )
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

    if (
        frame.protocol_method == "__richcmp__"
        and not frame.protocol_fallbacks
        and (
            return_value is NotImplemented
            or (isinstance(return_value, SymbolicValue) and return_value.value is NotImplemented)
        )
    ):
        return (
            return_value,
            Issue(
                kind=IssueKind.TYPE_ERROR,
                message="Possible TypeError: ordered comparison methods returned NotImplemented",
                constraints=list(state.path_constraints),
                pc=state.pc,
            ),
            None,
        )

    if (
        frame.protocol_method in {"__richcmp_eq__", "__richcmp_ne__"}
        and not frame.protocol_fallbacks
        and (
            return_value is NotImplemented
            or (isinstance(return_value, SymbolicValue) and return_value.value is NotImplemented)
        )
    ):
        completed = _complete_definite_identity_comparison(frame)
        if completed is not None:
            return completed, None, None
        return return_value, None, UNSUPPORTED_COMPARISON_REFLECTION

    if frame.protocol_method == "__descriptor_hasattr__":
        return SymbolicValue.from_const(True), None, None

    if frame.protocol_method in {"__contains__", "__contains_not__"}:
        return return_value, None, None

    if frame.protocol_method == "__bool__" or frame.protocol_method in _MEMBERSHIP_BOOL_PROTOCOLS:
        if isinstance(return_value, bool):
            return return_value, None, None
        if isinstance(return_value, SymbolicValue):
            is_bool = z3.simplify(return_value.is_bool)
            if z3.is_true(is_bool) or not z3.is_false(is_bool):
                return return_value, None, None
        return (
            return_value,
            Issue(
                kind=IssueKind.TYPE_ERROR,
                message="Possible TypeError: __bool__ should return bool",
                constraints=list(state.path_constraints),
                pc=state.pc,
            ),
            None,
        )

    from pysymex.execution.opcodes.common.control.length_returns import (
        normalize_length_protocol_return,
    )

    length_result = normalize_length_protocol_return(frame, return_value, state)
    if length_result is not None:
        return length_result
    return return_value, None, None


__all__ = ["normalize_truth_protocol_return"]
