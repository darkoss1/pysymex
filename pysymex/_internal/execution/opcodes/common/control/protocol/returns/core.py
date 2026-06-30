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

"""Dispatch modeled protocol return normalization by protocol family."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.opcodes.common.control.protocol.fallbacks import (
    UNSUPPORTED_INIT_RETURN_PROTOCOL,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import CallFrame
    from pysymex._internal.typing.protocols import StackValue

_MEMBERSHIP_BOOL_PROTOCOLS = {
    "__contains___truth_bool__",
    "__contains_not___truth_bool__",
}


class ProtocolReturns:
    """Domain owner for modeled protocol return normalization."""

    @staticmethod
    def truth(
        frame: CallFrame,
        return_value: StackValue | None,
        state: VMState,
    ) -> tuple[StackValue | None, Issue | None, str | None]:
        """Normalize modeled protocol returns or expose unsupported precision."""
        if frame.is_init_call:
            init_result = _normalize_init_return(frame, return_value, state)
            if init_result is not None:
                return init_result

        construction_result = ProtocolReturns.construction(frame, return_value)
        if construction_result is not None:
            return construction_result

        if frame.protocol_method == "__iter__":
            return _normalize_iter_return(return_value, state)

        numeric_result = ProtocolReturns.numeric(frame, return_value, state)
        if numeric_result is not None:
            return numeric_result

        comparison_result = ProtocolReturns.comparison(frame, return_value, state)
        if comparison_result is not None:
            return comparison_result

        if frame.protocol_method == "__descriptor_hasattr__":
            return SymbolicValue.from_const(True), None, None

        if frame.protocol_method in {"__contains__", "__contains_not__"}:
            return return_value, None, None

        if (
            frame.protocol_method == "__bool__"
            or frame.protocol_method in _MEMBERSHIP_BOOL_PROTOCOLS
        ):
            return _normalize_bool_return(return_value, state)

        length_result = ProtocolReturns.length(frame, return_value, state)
        if length_result is not None:
            return length_result
        return return_value, None, None

    @staticmethod
    def numeric(
        frame: CallFrame,
        return_value: StackValue | None,
        state: VMState,
    ) -> tuple[StackValue | None, Issue | None, str | None] | None:
        """Normalize numeric conversion and reflection protocol returns."""
        from pysymex._internal.execution.opcodes.common.control.protocol.returns.numeric import (
            normalize_numeric,
        )

        return normalize_numeric(frame, return_value, state)

    @staticmethod
    def comparison(
        frame: CallFrame,
        return_value: StackValue | None,
        state: VMState,
    ) -> tuple[StackValue | None, Issue | None, str | None] | None:
        """Normalize rich-comparison ``NotImplemented`` returns."""
        from pysymex._internal.execution.opcodes.common.control.protocol.returns.comparisons import (
            normalize_comparison,
        )

        return normalize_comparison(frame, return_value, state)

    @staticmethod
    def construction(
        frame: CallFrame,
        return_value: StackValue | None,
    ) -> tuple[StackValue | None, Issue | None, str | None] | None:
        """Complete definite foreign-instance ``__new__`` returns without ``__init__``."""
        from pysymex._internal.execution.opcodes.common.control.returns.lifecycle import (
            normalize_construction,
        )

        return normalize_construction(frame, return_value)

    @staticmethod
    def length(
        frame: CallFrame,
        return_value: StackValue | None,
        state: VMState,
    ) -> tuple[StackValue | None, Issue | None, str | None] | None:
        """Normalize a modeled length return or return ``None`` for other protocols."""
        from pysymex._internal.execution.opcodes.common.control.returns.length import (
            normalize_length,
        )

        return normalize_length(frame, return_value, state)


def _normalize_init_return(
    frame: CallFrame,
    return_value: StackValue | None,
    state: VMState,
) -> tuple[StackValue | None, Issue | None, str | None] | None:
    """Normalize ``__init__`` returns for CPython-compatible ``None`` handling."""
    _ = frame
    if return_value is None or isinstance(return_value, SymbolicNoneType):
        return return_value, None, None
    if isinstance(return_value, SymbolicValue) and not z3.is_false(
        simplify_expr(return_value.is_none),
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


def _normalize_iter_return(
    return_value: StackValue | None,
    state: VMState,
) -> tuple[StackValue | None, Issue | None, str | None]:
    """Normalize ``__iter__`` returns to definite iterator objects."""
    if isinstance(return_value, SymbolicValue):
        from pysymex._internal.execution.opcodes.common.numeric.dunder import lookup_modeled_method

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


def _normalize_bool_return(
    return_value: StackValue | None,
    state: VMState,
) -> tuple[StackValue | None, Issue | None, str | None]:
    """Normalize ``__bool__`` and membership truth continuations."""
    if isinstance(return_value, bool):
        return return_value, None, None
    if isinstance(return_value, SymbolicValue):
        is_bool = simplify_expr(return_value.is_bool)
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
