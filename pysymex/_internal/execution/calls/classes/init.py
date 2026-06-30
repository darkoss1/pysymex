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

"""Modeled class instance initialization for constructor calls."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.execution.calls.classes.protocols import modeled_method_callable
from pysymex._internal.execution.calls.contract_obligations import (
    has_enabled_runtime_contract_obligations,
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


def complete_instance_construction(
    state: VMState,
    ctx: OpcodeDispatcher,
    class_name: str,
    modeled_cls: SymbolicClass,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult:
    """Instantiate a modeled class and run or summarize ``__init__``."""
    from pysymex._internal.core.classes.registry import class_registry
    from pysymex._internal.execution.opcodes.common.functions.classes.init import (
        apply_straight_line_init_assignments,
    )
    from pysymex._internal.execution.opcodes.common.functions.classes.instances.values import (
        modeled_instance_value,
    )

    kwargs_obj = cast("dict[str, object]", dict(kwargs))
    instance = class_registry.instantiate(modeled_cls, tuple(args), kwargs_obj, state.pc)
    result_val = modeled_instance_value(class_name, instance, state.pc)

    init_method = modeled_cls.lookup_method("__init__")
    init_callable = modeled_method_callable(init_method)
    can_summarize_init = not (
        init_callable is not None
        and has_enabled_runtime_contract_obligations(
            init_callable,
            getattr(ctx, "config", None),
        )
    )
    if can_summarize_init and apply_straight_line_init_assignments(
        modeled_cls,
        instance,
        args,
        kwargs,
    ):
        state = state.push(result_val)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    if init_method is not None:
        result = perform_interprocedural_call_impl(
            state,
            ctx,
            init_method,
            [result_val, *args],
            kwargs,
            is_init=True,
            init_instance=result_val,
        )
        if result:
            return result

    state = state.push(result_val)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
