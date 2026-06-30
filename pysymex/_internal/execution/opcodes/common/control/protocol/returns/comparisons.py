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

"""Rich-comparison protocol return normalization."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.opcodes.common.control.protocol.fallbacks import (
    UNSUPPORTED_COMPARISON_REFLECTION,
)
from pysymex._internal.execution.opcodes.common.control.protocol.returns.objects import (
    ProtocolObjectPredicates,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import CallFrame
    from pysymex._internal.typing.protocols import StackValue


def normalize_comparison(
    frame: CallFrame,
    return_value: StackValue | None,
    state: VMState,
) -> tuple[StackValue | None, Issue | None, str | None] | None:
    """Normalize rich-comparison ``NotImplemented`` returns."""
    if (
        frame.protocol_method == "__richcmp__"
        and not frame.protocol_fallbacks
        and _is_not_implemented(return_value)
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
        and _is_not_implemented(return_value)
    ):
        completed = _complete_definite_identity_comparison(frame)
        if completed is not None:
            return completed, None, None
        return return_value, None, UNSUPPORTED_COMPARISON_REFLECTION
    return None


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
    elif (left_id := ProtocolObjectPredicates.instance_id(left)) is not None and (
        right_id := ProtocolObjectPredicates.instance_id(right)
    ) is not None:
        is_identical = left_id == right_id
    elif (
        ProtocolObjectPredicates.is_modeled(left) and ProtocolObjectPredicates.is_non_object(right)
    ) or (
        ProtocolObjectPredicates.is_modeled(right) and ProtocolObjectPredicates.is_non_object(left)
    ):
        is_identical = False
    else:
        return None
    result = not is_identical if frame.protocol_method == "__richcmp_ne__" else is_identical
    return SymbolicValue.from_const(result)


def _is_not_implemented(value: StackValue | None) -> bool:
    """Return whether *value* is a concrete or wrapped ``NotImplemented`` result."""
    return value is NotImplemented or (
        isinstance(value, SymbolicValue) and value.value is NotImplemented
    )
