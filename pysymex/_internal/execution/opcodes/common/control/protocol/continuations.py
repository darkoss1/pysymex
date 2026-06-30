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

"""Resume native opcodes after a modeled protocol call returns.

Inspects ``CallFrame.protocol_method`` and ``protocol_retained_operand`` to finish
slice-index suspension, membership tests, and attribute protocol chains. Invoked from
return opcodes before pushing the final result onto the caller stack.

Limitations:
    ``__new__``, bare numeric, and rich-compare methods intentionally return ``None`` here
    so other normalizers handle them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import CallFrame
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def complete_retained_protocol_operation(
    frame: CallFrame,
    return_value: StackValue | None,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult | None:
    """Finish a suspended operation that retained one operand across a call."""
    if frame.protocol_method is not None and frame.protocol_method.startswith("__contains"):
        from pysymex._internal.execution.opcodes.common.control.truth.continuations import (
            complete_retained_membership,
        )

        membership_result = complete_retained_membership(frame, return_value, state, ctx)
        if membership_result is not None:
            return membership_result
    if frame.protocol_retained_operand is None or return_value is None:
        return None
    if frame.protocol_method is not None and frame.protocol_method.startswith(
        "__index_built_slice_",
    ):
        from pysymex._internal.execution.opcodes.common.collections.protocols.index import (
            complete_retained_built_slice_index,
        )

        state.depth -= 1
        return complete_retained_built_slice_index(frame, return_value, state)
    if frame.protocol_method == "__index_slice_start__":
        from pysymex._internal.execution.opcodes.common.collections.protocols.index import (
            complete_retained_slice_index,
        )

        state.depth -= 1
        return complete_retained_slice_index(frame, return_value, state)
    from pysymex._internal.execution.opcodes.common.control.match.pattern_ops import MatchPatternOps

    match_class_result = MatchPatternOps.complete_class_attr(frame, return_value, state, ctx)
    if match_class_result is not None:
        return match_class_result
    if frame.protocol_method in {"__new__", "__numeric__", "__richcmp_eq__", "__richcmp_ne__"}:
        return None
    from pysymex._internal.execution.opcodes.common.functions.attribute.protocols.constants import (
        ATTRIBUTE_LOAD_PROTOCOL_METHODS,
        GETATTR_DEFAULT_PROTOCOL_METHODS,
        complete_attribute_load_protocol_return,
    )

    if frame.protocol_method in GETATTR_DEFAULT_PROTOCOL_METHODS:
        return None
    if (
        frame.protocol_method in ATTRIBUTE_LOAD_PROTOCOL_METHODS
        and complete_attribute_load_protocol_return(
            state,
            frame.protocol_retained_operand,
            return_value,
        )
    ):
        state.depth -= 1
        return OpcodeResult.continue_with(state)
    from pysymex._internal.execution.opcodes.common.collections.unpack.protocol import (
        complete_retained_unpack_iter,
    )

    unpack_result = complete_retained_unpack_iter(frame, return_value, state, ctx)
    if unpack_result is not None:
        return unpack_result
    from pysymex._internal.execution.opcodes.common.control.iteration.callable.sentinel import (
        finish_callable_sentinel_return,
    )

    callable_sentinel_result = finish_callable_sentinel_return(
        frame,
        return_value,
        state,
    )
    if callable_sentinel_result is not None:
        return callable_sentinel_result
    from pysymex._internal.execution.opcodes.common.control.iteration.sequence import (
        finish_getitem_return,
        is_next_iteration_return,
    )

    if is_next_iteration_return(frame):
        return None
    sequence_result = finish_getitem_return(frame, return_value, state)
    if sequence_result is not None:
        return sequence_result
    from pysymex._internal.execution.opcodes.common.control.truth.continuations import (
        complete_retained_truth_jump,
    )

    state.depth -= 1
    return complete_retained_truth_jump(frame, return_value, state, ctx)
