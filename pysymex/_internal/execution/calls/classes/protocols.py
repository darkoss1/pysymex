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

"""Constructor protocol helpers for modeled class calls."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.execution.calls.construction_fallbacks import (
    METACLASS_CALL_UNAVAILABLE_REASON,
    UNSUPPORTED_CONSTRUCTION_PROTOCOL,
    flag_unsupported_construction,
)
from pysymex._internal.execution.calls.interprocedural.entry import (
    perform_interprocedural_call_impl,
)
from pysymex._internal.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    import dis
    from collections.abc import Callable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def apply_init_type_hints(modeled_cls: object, hints: object) -> None:
    """Apply registration-time init type-hint strings to modeled constructor parameters."""
    if not isinstance(hints, dict):
        return
    typed_hints = cast("dict[object, object]", hints)
    for param in getattr(modeled_cls, "init_params", []):
        param_name = getattr(param, "name", None)
        if isinstance(param_name, str) and param_name in typed_hints:
            param.type_hint = str(typed_hints[param_name]).lower()


def modeled_method_callable(method: object | None) -> Callable[..., object] | None:
    """Return the concrete callable carried by a modeled method, when present."""
    raw_func = getattr(method, "func", None)
    if callable(raw_func):
        return raw_func
    return None


def dispatch_custom_metaclass_call(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    class_value: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    modeled_cls: object,
) -> OpcodeResult | None:
    """Enter a source-visible metaclass ``__call__`` before direct construction."""
    from pysymex._internal.core.classes.classes import SymbolicClass

    metaclass = getattr(modeled_cls, "metaclass", None)
    if not isinstance(metaclass, SymbolicClass):
        return None
    if metaclass.module == "builtins" and metaclass.name == "type":
        return None
    call_method = metaclass.lookup_method("__call__")
    if call_method is None:
        return None
    bind_to_class = getattr(call_method, "bind_to_class", None)
    if not callable(bind_to_class):
        return None
    bound_call = bind_to_class(cast("StackValue", class_value))
    result = perform_interprocedural_call_impl(
        state,
        ctx,
        bound_call,
        args,
        kwargs,
        protocol_method="metaclass.__call__",
    )
    if result is not None:
        return result
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[UNSUPPORTED_CONSTRUCTION_PROTOCOL],
        fallback_events=[
            flag_unsupported_construction(
                state=state,
                reason=METACLASS_CALL_UNAVAILABLE_REASON,
            ),
        ],
        terminal=True,
    )
