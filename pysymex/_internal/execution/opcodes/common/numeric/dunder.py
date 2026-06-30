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

"""Modeled numeric dunder lookup and binary dispatch.

Owns CPython-style direct/reflected/in-place binary method ordering for modeled
objects. Numeric op handlers call this before symbolic fallback arithmetic.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, cast

from pysymex._internal.core.state.types import ProtocolCallCandidate
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.numeric.fallbacks import unsupported_numeric_event
from pysymex._internal.execution.opcodes.common.numeric.labels import (
    UNSUPPORTED_NUMERIC_ABSTRACTION,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


class ModeledMethodProtocol(Protocol):
    """Structural protocol for modeled callables exposing argument normalization."""

    def get_call_args(
        self,
        args: tuple[object, ...],
        kwargs: dict[str, object],
    ) -> tuple[tuple[object, ...], dict[str, object]]:
        """Return CPython-ordered positional and keyword arguments for a modeled call."""
        ...


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
    base_op = op_symbol.removesuffix("=")
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
            ),
        )
    if not protocol_candidates:
        return None
    from pysymex._internal.execution.calls.interprocedural.entry import (
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
            ),
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


def _right_reflection_precedes_direct(left: object, right: object, reflected_method: str) -> bool:
    """Return whether a proven strict subclass declares priority reflection."""
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
        and reflected_method in right_class.methods
    )
