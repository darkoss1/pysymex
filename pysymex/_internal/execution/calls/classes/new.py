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

"""Modeled ``__new__`` entry for class construction calls."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.execution.calls.construction_fallbacks import (
    CONSTRUCTOR_ENTRY_UNAVAILABLE_REASON,
    UNSUPPORTED_CONSTRUCTION_PROTOCOL,
    flag_unsupported_construction,
)
from pysymex._internal.execution.calls.interprocedural.entry import (
    perform_interprocedural_call_impl,
)
from pysymex._internal.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    from pysymex._internal.core.classes.classes import SymbolicClass
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def dispatch_new_method(
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: object,
    modeled_cls: SymbolicClass,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult | None:
    """Enter modeled ``__new__`` or return an unsupported-construction terminal result."""
    new_method = modeled_cls.lookup_method("__new__")
    if new_method is None:
        return None

    retained_constructor_call = cast(
        "StackValue",
        (cast("StackValue", func_obj), tuple(args), dict(kwargs)),
    )
    new_result = perform_interprocedural_call_impl(
        state,
        ctx,
        new_method,
        [cast("StackValue", func_obj), *args],
        kwargs,
        protocol_method="__new__",
        protocol_retained_operand=retained_constructor_call,
    )
    if new_result is not None:
        return new_result
    return OpcodeResult(
        new_states=[],
        issues=[],
        degraded_passes=[UNSUPPORTED_CONSTRUCTION_PROTOCOL],
        fallback_events=[
            flag_unsupported_construction(
                state=state,
                reason=CONSTRUCTOR_ENTRY_UNAVAILABLE_REASON,
            ),
        ],
        terminal=True,
    )
