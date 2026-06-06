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

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

from pysymex.core.constants import Z3_FALSE
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.core.helpers import resolve_heap_object
from pysymex.models.builtins.core.iterator_items import (
    concrete_iterable_items,
    contains_definitely_unhashable_item,
    exact_dict_items_from_iterable,
    iterator_exhaustion_side_effect,
)
from pysymex.models.containers.dicts.shared import get_symbolic_dict
from ..base import FunctionModel, ModelResult
from ..core.helpers import type_error_side_effect


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
        }
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
                side_effects=type_error_side_effect(
                    "builtins.super", "super() accepts at most two arguments"
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
        result, constraint = SymbolicValue.symbolic(f"issubclass_{state.pc}")
        if len(args) != 2 or kwargs:
            return ModelResult(
                value=result,
                constraints=[constraint, result.is_bool],
                side_effects=type_error_side_effect(
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
                side_effects=type_error_side_effect(
                    "builtins.issubclass", "issubclass() arguments must be classes"
                ),
            )
        if isinstance(cls, type) and isinstance(classinfo, type):
            return ModelResult(value=SymbolicValue.from_const(issubclass(cls, classinfo)))
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class GlobalsModel(FunctionModel):
    """Model for globals()."""

    name = "globals"
    qualname = "builtins.globals"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicDict.symbolic(f"globals_{state.pc}")
        if args or kwargs:
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.globals", "globals() takes no arguments"
                ),
            )
        return ModelResult(value=result, constraints=[constraint])


class LocalsModel(FunctionModel):
    """Model for locals()."""

    name = "locals"
    qualname = "builtins.locals"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicDict.symbolic(f"locals_{state.pc}")
        if args or kwargs:
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.locals", "locals() takes no arguments"
                ),
            )
        return ModelResult(value=result, constraints=[constraint])


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
                side_effects=type_error_side_effect(
                    "builtins.dict", "dict() accepts at most one positional argument"
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
                side_effects=type_error_side_effect(
                    "builtins.dict", "dict() argument is not iterable"
                ),
            )
        if args:
            source = resolve_heap_object(args[0], state)
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
            direct_items = concrete_iterable_items(source, state)
            if direct_items is not None:
                exact_items = exact_dict_items_from_iterable(direct_items, state)
                if exact_items is not None:
                    exact_items.update(dict(kwargs.items()))
                    return ModelResult(
                        value=SymbolicDict.from_const(exact_items),
                        side_effects=iterator_exhaustion_side_effect(source, state) or {},
                    )
        result, constraint = SymbolicDict.symbolic(f"dict_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class SetModel(FunctionModel):
    """Model for set()."""

    name = "set"
    qualname = "builtins.set"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"set_{state.pc}")
        if len(args) > 1 or kwargs:
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.set", "set() accepts at most one argument"
                ),
            )
        if not args:
            return ModelResult(value=_exact_set_value(set()))
        source = resolve_heap_object(args[0], state)
        if source is None or isinstance(source, (int, float, bool)):
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.set", "set() argument is not iterable"
                ),
            )
        direct_items = concrete_iterable_items(source, state)
        if direct_items is not None:
            iterator_side_effects = iterator_exhaustion_side_effect(source, state)
            if contains_definitely_unhashable_item(direct_items, state):
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=type_error_side_effect(
                        "builtins.set", "set() argument contains an unhashable item"
                    ),
                )
            try:
                return ModelResult(
                    value=_exact_set_value(set(direct_items)),
                    side_effects=iterator_side_effects or {},
                )
            except TypeError:
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=type_error_side_effect(
                        "builtins.set", "set() argument contains an unhashable item"
                    ),
                )
        return ModelResult(value=result, constraints=[constraint])


def _exact_set_value(values: set[object]) -> SymbolicValue:
    result = SymbolicValue.from_const(values)
    result.set_runtime_type("set")
    result.is_none = Z3_FALSE
    return result
