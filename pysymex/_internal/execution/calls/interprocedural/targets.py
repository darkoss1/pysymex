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

"""Callable target normalization for nested bytecode entry."""

from __future__ import annotations

import types
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.calls.payload import SymbolicFunctionPayload, function_payload
from pysymex._internal.execution.calls.value.coercion import coerce_call_stack_value

if TYPE_CHECKING:
    from pysymex._internal.typing.protocols import StackValue


@dataclass(frozen=True, slots=True)
class InterproceduralTarget:
    """Normalized callable target ready for callee local binding and frame entry."""

    func_obj: object
    func_code: types.CodeType
    func_name: str
    symbolic_closure: tuple[object, ...]
    args: list[StackValue]
    kwargs: dict[str, StackValue]


def resolve_interprocedural_target(
    func_obj: object,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> InterproceduralTarget | None:
    """Resolve modeled/bound callable wrappers to a concrete code object."""
    func_code = getattr(func_obj, "__code__", None) or getattr(func_obj, "_func_code", None)
    symbolic_closure: tuple[object, ...] = ()

    if isinstance(func_obj, SymbolicFunctionPayload):
        func_code = func_obj.code
        symbolic_closure = func_obj.closure

    if isinstance(func_obj, types.MethodType) and func_obj.__self__ is not None:
        bound_self = coerce_call_stack_value(func_obj.__self__)
        args = [bound_self, *args]
        func_obj = func_obj.__func__
        func_code = getattr(func_obj, "__code__", None) or getattr(func_obj, "_func_code", None)

    symbolic_method_type = _symbolic_method_type()
    if symbolic_method_type is not None and isinstance(func_obj, symbolic_method_type):
        get_call_args = getattr(func_obj, "get_call_args", None)
        method_func = getattr(func_obj, "func", None)
        if not callable(get_call_args):
            return None
        method_args_obj, method_kwargs_obj = cast(
            "tuple[object, object]",
            get_call_args(
                tuple(args),
                cast("dict[str, object]", dict(kwargs)),
            ),
        )
        method_args = cast("tuple[object, ...]", method_args_obj)
        method_kwargs = cast("dict[str, StackValue]", method_kwargs_obj)
        args = cast("list[StackValue]", list(method_args))
        kwargs = method_kwargs
        payload = function_payload(method_func)
        if payload is not None:
            func_code = payload.code
            symbolic_closure = payload.closure
        else:
            func_code = getattr(method_func, "__code__", None) or getattr(
                method_func,
                "_func_code",
                None,
            )
        func_obj = method_func

    if func_code is None and hasattr(func_obj, "value"):
        inner = getattr(func_obj, "value", None)
        if inner is not None:
            func_code = getattr(inner, "__code__", None) or getattr(inner, "_func_code", None)
            func_obj = inner
    if func_code is None and hasattr(func_obj, "_modeled_object"):
        inner = getattr(func_obj, "_modeled_object", None)
        if inner is not None:
            payload = function_payload(inner)
            if payload is not None:
                func_code = payload.code
                symbolic_closure = payload.closure
            elif hasattr(inner, "co_code"):
                func_code = inner
            else:
                func_code = getattr(inner, "__code__", None) or getattr(inner, "_func_code", None)
            func_obj = inner

    if not isinstance(func_code, types.CodeType):
        return None

    func_name_obj = getattr(func_obj, "__name__", None) or getattr(
        func_obj,
        "_func_name",
        "anonymous",
    )
    func_name = func_name_obj if isinstance(func_name_obj, str) else str(func_name_obj)
    return InterproceduralTarget(
        func_obj=func_obj,
        func_code=func_code,
        func_name=func_name,
        symbolic_closure=symbolic_closure,
        args=args,
        kwargs=kwargs,
    )


def _symbolic_method_type() -> type[object] | None:
    """Return the optional modeled method type without hard-failing imports."""
    try:
        from pysymex._internal.core.classes.types import SymbolicMethod
    except ImportError:
        return None
    return SymbolicMethod
