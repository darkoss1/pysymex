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

"""Modeled rich-comparison protocol dispatch for ``COMPARE_OP``."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.state.types import ProtocolCallCandidate
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.control.protocol.fallbacks import (
    COMPARISON_CALL_UNAVAILABLE_REASON,
    UNSUPPORTED_COMPARISON_PROTOCOL,
    flag_unsupported_comparison,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue

_RICH_COMPARISON_METHODS = {
    "<": ("__lt__", "__gt__"),
    "<=": ("__le__", "__ge__"),
    "==": ("__eq__", "__eq__"),
    "!=": ("__ne__", "__ne__"),
    ">": ("__gt__", "__lt__"),
    ">=": ("__ge__", "__le__"),
}


def dispatch_modeled_rich_comparison(
    state: VMState,
    ctx: OpcodeDispatcher,
    left: StackValue,
    right: StackValue,
    op_name: str,
) -> OpcodeResult | None:
    """Dispatch modeled rich comparison via interprocedural dunder calls."""
    method_names = _RICH_COMPARISON_METHODS.get(op_name)
    if method_names is None:
        return None
    from pysymex._internal.execution.opcodes.common.numeric.dunder import lookup_modeled_method

    candidates: list[ProtocolCallCandidate] = []
    ordered_candidates = [
        (left, method_names[0], right),
        (right, method_names[1], left),
    ]
    if _right_rich_comparison_precedes_direct(left, right):
        ordered_candidates.reverse()
    for owner, method_name, argument in ordered_candidates:
        if lookup_modeled_method(owner, method_name) is not None:
            candidates.append(
                ProtocolCallCandidate(
                    owner=owner,
                    method_name=method_name,
                    argument=argument,
                ),
            )
    if not candidates:
        return None
    from pysymex._internal.execution.calls.interprocedural.entry import (
        perform_interprocedural_call_impl,
    )

    first = candidates[0]
    method = lookup_modeled_method(first.owner, first.method_name)
    if method is not None:
        protocol_method = {"==": "__richcmp_eq__", "!=": "__richcmp_ne__"}.get(
            op_name,
            "__richcmp__",
        )
        result = perform_interprocedural_call_impl(
            state,
            ctx,
            method,
            [first.owner, first.argument],
            {},
            protocol_method=protocol_method,
            protocol_retained_operand=(left, right) if op_name in {"==", "!="} else None,
            protocol_fallbacks=tuple(candidates[1:]),
        )
        if result is not None:
            return result
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[UNSUPPORTED_COMPARISON_PROTOCOL],
        fallback_events=[
            flag_unsupported_comparison(
                state=state,
                reason=COMPARISON_CALL_UNAVAILABLE_REASON,
            ),
        ],
        terminal=True,
    )


def _right_rich_comparison_precedes_direct(left: object, right: object) -> bool:
    """Return whether a proven strict subtype receives rich-comparison priority."""
    from pysymex._internal.core.classes.instances import SymbolicInstance

    left_instance = getattr(left, "_modeled_object", None)
    right_instance = getattr(right, "_modeled_object", None)
    if not isinstance(left_instance, SymbolicInstance) or not isinstance(
        right_instance,
        SymbolicInstance,
    ):
        return False
    right_class = right_instance.cls
    return (
        right_class is not left_instance.cls
        and bool(getattr(right_class, "_pysymex_bases_complete", False))
        and right_class.is_subclass_of(left_instance.cls)
    )
