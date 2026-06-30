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

"""Namespace and container constructor builtin models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.models.contracts.results import SideEffects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

from pysymex._internal.core.state.types import is_bound
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.iteration.consumption import iterator_exhaustion_side_effect
from pysymex._internal.models.builtins.iteration.hashability import (
    exact_dict_items_error,
    exact_dict_items_from_iterable,
)
from pysymex._internal.models.builtins.iteration.sources import IterationSources
from pysymex._internal.models.builtins.types.containers.dicts.shared import get_symbolic_dict
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult


@dataclass(frozen=True, slots=True)
class ModeledSuperProxy:
    """Execution-visible payload for a zero-argument ``super()`` result."""

    receiver: StackValue


def _runtime_error_side_effect(source: str, message: str) -> dict[str, object]:
    return {
        "raised_exception": {
            "issue_kind": "RUNTIME_ERROR",
            "exception_type": "RuntimeError",
            "message": message,
            "source": source,
        },
    }


class SuperModel(FunctionModel):
    """Model for super()."""

    name = "super"
    qualname = "builtins.super"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"super_{state.pc}")
        if len(args) > 2 or kwargs:
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.super",
                    "super() accepts at most two arguments",
                ),
            )
        if not args:
            receiver = _zero_arg_super_receiver(state)
            if receiver is not None:
                result.attach_modeled_object(ModeledSuperProxy(receiver=receiver))
                result.affinity_type = "super"
                return ModelResult(value=result, constraints=[constraint])
            if "__class__" in state.local_vars:
                result.affinity_type = "super"
                return ModelResult(value=result, constraints=[constraint])
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=_runtime_error_side_effect("builtins.super", "super(): no arguments"),
            )
        return ModelResult(value=result, constraints=[constraint])


def _zero_arg_super_receiver(state: VMState) -> StackValue | None:
    """Return the active method receiver for zero-argument ``super()``, if known."""
    receiver = state.local_vars.get("self")
    if receiver is not None:
        return receiver
    receiver = state.local_vars.get("cls")
    if receiver is not None:
        return receiver
    for name, value in state.local_vars.items():
        if str(name).startswith("__"):
            continue
        return value
    return None


class IssubclassModel(FunctionModel):
    """Model for issubclass()."""

    name = "issubclass"
    qualname = "builtins.issubclass"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic_bool(f"issubclass_{state.pc}")
        if len(args) != 2 or kwargs:
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.issubclass",
                    f"issubclass() received invalid positional argument count: {len(args)}",
                ),
            )
        cls, classinfo = args
        if (
            cls is None
            or isinstance(cls, (int, float, bool, str, bytes, list, dict, set))
            or classinfo is None
            or isinstance(classinfo, (int, float, bool, str, bytes, list, dict, set))
        ):
            return ModelResult(
                value=result,
                constraints=[constraint, result.is_bool],
                side_effects=SideEffects.type_error(
                    "builtins.issubclass",
                    "issubclass() arguments must be classes",
                ),
            )
        if isinstance(cls, type) and isinstance(classinfo, type):
            return ModelResult(value=SymbolicValue.from_const(issubclass(cls, classinfo)))
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class GlobalsModel(FunctionModel):
    """Model for globals().

    Returns an exact snapshot of current bound global names and values.

    Limitations:
        Mutating the returned dictionary does not yet write through to the VM
        global namespace as CPython's live dictionary does.
    """

    name = "globals"
    qualname = "builtins.globals"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if args or kwargs:
            result, constraint = SymbolicDict.symbolic(f"globals_invalid_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.globals",
                    "globals() takes no arguments",
                ),
            )
        values: dict[object, object] = {
            name: value for name, value in state.global_vars.items() if is_bound(value)
        }
        return ModelResult(value=SymbolicDict.from_const_named("globals", values))


class LocalsModel(FunctionModel):
    """Model for locals().

    Returns an exact snapshot of current bound local names and values.

    Limitations:
        CPython's write-through behavior varies by scope. Mutations of this
        modeled snapshot do not update the VM local namespace.
    """

    name = "locals"
    qualname = "builtins.locals"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if args or kwargs:
            result, constraint = SymbolicDict.symbolic(f"locals_invalid_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.locals",
                    "locals() takes no arguments",
                ),
            )
        values: dict[object, object] = {
            name: value for name, value in state.local_vars.items() if is_bound(value)
        }
        return ModelResult(value=SymbolicDict.from_const_named("locals", values))


class DictModel(FunctionModel):
    """Model for dict()."""

    name = "dict"
    qualname = "builtins.dict"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) > 1:
            result, constraint = SymbolicDict.symbolic(f"dict_invalid_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.dict",
                    "dict() accepts at most one positional argument",
                ),
            )
        if not args and not kwargs:
            result, constraint = SymbolicDict.symbolic(f"dict_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        if kwargs and not args:
            kwargs_items: dict[object, object] = dict(kwargs.items())
            return ModelResult(value=SymbolicDict.from_const(kwargs_items))
        if args and (args[0] is None or isinstance(args[0], (int, float, bool))):
            result, constraint = SymbolicDict.symbolic(f"dict_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.dict",
                    "dict() argument is not iterable",
                ),
            )
        if args:
            source = SymbolicObject.resolve(args[0], state)
            source_dict = get_symbolic_dict(source, state)
            if source_dict is not None:
                result = source_dict.copy()
                for key, value in kwargs.items():
                    result = result.__setitem__(key, value)
                return ModelResult(value=result)
            if isinstance(source, dict):
                concrete_source = cast("dict[object, object]", source)
                merged_items = dict(concrete_source)
                kwargs_updates: dict[object, object] = dict(kwargs.items())
                merged_items.update(kwargs_updates)
                result = SymbolicDict.from_const(merged_items)
                return ModelResult(value=result)
            direct_items = IterationSources.iterable_items(source, state)
            if direct_items is not None:
                exact_items = exact_dict_items_from_iterable(direct_items, state)
                if exact_items is not None:
                    exact_items.update(dict(kwargs.items()))
                    return ModelResult(
                        value=SymbolicDict.from_const(exact_items),
                        side_effects=iterator_exhaustion_side_effect(source, state) or {},
                    )
                item_error = exact_dict_items_error(direct_items, state)
                if item_error is not None:
                    result, constraint = SymbolicDict.symbolic(f"dict_invalid_{state.pc}")
                    error_effect = (
                        SideEffects.value_error(
                            "builtins.dict",
                            "dictionary update sequence element has length != 2",
                        )
                        if item_error == "value"
                        else SideEffects.type_error(
                            "builtins.dict",
                            "dict() iterable contains an invalid pair",
                        )
                    )
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects=error_effect,
                    )
        result, constraint = SymbolicDict.symbolic(f"dict_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])
