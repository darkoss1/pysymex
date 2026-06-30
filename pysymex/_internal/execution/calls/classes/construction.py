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

"""Modeled class-constructor dispatch for resolved ``CALL`` targets."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.execution.calls.classes.init import complete_instance_construction
from pysymex._internal.execution.calls.classes.issues import (
    abstract_class_error_result,
    named_tuple_error_result,
)
from pysymex._internal.execution.calls.classes.new import dispatch_new_method
from pysymex._internal.execution.calls.classes.protocols import (
    apply_init_type_hints,
    dispatch_custom_metaclass_call,
)
from pysymex._internal.execution.calls.classes.targets import (
    class_target_code,
    class_target_name,
    is_class_like_target,
    resolve_modeled_class,
)
from pysymex._internal.execution.calls.type_call import BoundTypeCall

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.dispatch.result import OpcodeResult
    from pysymex._internal.typing.protocols import StackValue


def try_modeled_class_call(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    *,
    bypass_metaclass: bool = False,
) -> OpcodeResult | None:
    """Try to handle a call via the unified modeled class registry."""
    if isinstance(func_obj, BoundTypeCall):
        type_call_args = list(args)
        if type_call_args and type_call_args[0] is func_obj.target:
            type_call_args = type_call_args[1:]
        return try_modeled_class_call(
            instr,
            state,
            ctx,
            func_obj.target,
            type_call_args,
            kwargs,
            bypass_metaclass=True,
        )

    try:
        from pysymex._internal.core.classes.registry import class_registry
        from pysymex._internal.execution.calls.classes.stdlib import (
            try_literal_enum_constructor,
        )

        class_name = class_target_name(func_obj)
        if class_name is None or not is_class_like_target(func_obj):
            return None
        if class_name.startswith("module_"):
            return None

        init_type_hints = getattr(func_obj, "_pysymex_init_type_hints", None)
        modeled_cls = resolve_modeled_class(
            func_obj,
            class_name,
            class_target_code(func_obj),
            init_type_hints,
        )
        if modeled_cls is None:
            return None

        apply_init_type_hints(modeled_cls, init_type_hints)
        type_error_result = abstract_class_error_result(state, modeled_cls)
        if type_error_result is not None:
            return type_error_result
        type_error_result = named_tuple_error_result(state, modeled_cls, class_name, args, kwargs)
        if type_error_result is not None:
            return type_error_result

        enum_result = try_literal_enum_constructor(
            instr,
            state,
            ctx,
            modeled_cls,
            class_registry,
            class_name,
            args,
            kwargs,
        )
        if enum_result is not None:
            return enum_result

        if not bypass_metaclass:
            metaclass_result = dispatch_custom_metaclass_call(
                instr,
                state,
                ctx,
                func_obj,
                args,
                kwargs,
                modeled_cls,
            )
            if metaclass_result is not None:
                return metaclass_result

        new_result = dispatch_new_method(state, ctx, func_obj, modeled_cls, args, kwargs)
        if new_result is not None:
            return new_result

        return complete_instance_construction(state, ctx, class_name, modeled_cls, args, kwargs)
    except (ImportError, AttributeError, TypeError, KeyError, z3.Z3Exception):
        return None
