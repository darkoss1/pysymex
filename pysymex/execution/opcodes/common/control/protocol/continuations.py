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

from pysymex.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.types import CallFrame
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def complete_retained_protocol_operation(
    frame: CallFrame,
    return_value: StackValue | None,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult | None:
    """Finish a suspended operation that retained one operand across a call."""
    if frame.protocol_method is not None and frame.protocol_method.startswith("__contains"):
        from pysymex.execution.opcodes.common.control.truth_continuations import (
            complete_retained_membership,
        )

        membership_result = complete_retained_membership(frame, return_value, state, ctx)
        if membership_result is not None:
            return membership_result
    if frame.protocol_retained_operand is None or return_value is None:
        return None
    if frame.protocol_method is not None and frame.protocol_method.startswith(
        "__index_built_slice_"
    ):
        from pysymex.execution.opcodes.common.collections.protocols import (
            complete_retained_built_slice_index,
        )

        state.depth -= 1
        return complete_retained_built_slice_index(frame, return_value, state)
    if frame.protocol_method == "__index_slice_start__":
        from pysymex.execution.opcodes.common.collections.protocols import (
            complete_retained_slice_index,
        )

        state.depth -= 1
        return complete_retained_slice_index(frame, return_value, state)
    if frame.protocol_method in {"__new__", "__numeric__", "__richcmp_eq__", "__richcmp_ne__"}:
        return None
    from pysymex.execution.opcodes.common.functions.attribute.protocols import (
        GETATTR_DEFAULT_PROTOCOL_METHODS,
    )

    if frame.protocol_method in GETATTR_DEFAULT_PROTOCOL_METHODS:
        return None
    from pysymex.execution.opcodes.common.collections.unpack import complete_retained_unpack_iter

    unpack_result = complete_retained_unpack_iter(frame, return_value, state, ctx)
    if unpack_result is not None:
        return unpack_result
    from pysymex.execution.opcodes.common.control.callable_sentinel_iteration import (
        complete_callable_sentinel_iteration_return,
    )

    callable_sentinel_result = complete_callable_sentinel_iteration_return(
        frame,
        return_value,
        state,
    )
    if callable_sentinel_result is not None:
        return callable_sentinel_result
    from pysymex.execution.opcodes.common.control.sequence_iteration import (
        complete_sequence_getitem_iteration_return,
        is_next_iteration_return,
    )

    if is_next_iteration_return(frame):
        return None
    sequence_result = complete_sequence_getitem_iteration_return(frame, return_value, state)
    if sequence_result is not None:
        return sequence_result
    from pysymex.execution.opcodes.common.control.truth_continuations import (
        complete_retained_truth_jump,
    )

    state.depth -= 1
    return complete_retained_truth_jump(frame, return_value, state, ctx)


__all__ = ["complete_retained_protocol_operation"]
