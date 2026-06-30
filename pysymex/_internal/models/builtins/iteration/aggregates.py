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

"""Iterable-producing builtin models."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.constants import Z3_ZERO
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.models.contracts.results import SideEffects

if TYPE_CHECKING:
    from collections.abc import Sequence

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

from pysymex._internal.core.types.base import SymbolicType
from pysymex._internal.core.types.containers.generators import ModeledGenerator
from pysymex._internal.core.types.containers.iterator_sources import (
    EnumerateIteratorSource,
    ZipIteratorSource,
)
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.common.builtin_policies import (
    BuiltinAggregatePolicy,
    BuiltinInputPolicy,
)
from pysymex._internal.models.builtins.iteration.consumption import iterator_exhaustion_side_effect
from pysymex._internal.models.builtins.iteration.generator.sum import modeled_generator_sum
from pysymex._internal.models.builtins.iteration.sources import IterationSources
from pysymex._internal.models.builtins.numeric.sum_precision import symbolic_sum_result
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult


def _iterable_arity_error(
    name: str,
    args: list[StackValue],
    state: VMState,
    message: str | None = None,
) -> ModelResult:
    result, constraint = SymbolicList.symbolic(f"{name}_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects=SideEffects.type_error(
            f"builtins.{name}",
            message or f"{name}() received invalid positional argument count: {len(args)}",
        ),
    )


class SortedModel(FunctionModel):
    """Model for sorted()."""

    name = "sorted"
    qualname = "builtins.sorted"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or set(kwargs) - {"key", "reverse"}:
            return _iterable_arity_error("sorted", args, state)
        obj = args[0]
        reverse = kwargs.get("reverse", False)
        if kwargs.get("key") is None and isinstance(reverse, bool):
            concrete_items = _concrete_iterable_items(obj, state)
            if concrete_items is not None:
                iterator_side_effects = iterator_exhaustion_side_effect(obj, state)
                if len(concrete_items) <= 1:
                    return ModelResult(
                        value=_concrete_symbolic_list(f"sorted_{state.pc}", concrete_items),
                        side_effects=iterator_side_effects or {},
                    )
                sorted_items = BuiltinAggregatePolicy.safe_sorted_concrete(
                    concrete_items,
                    reverse=reverse,
                )
                if sorted_items is not None:
                    return ModelResult(
                        value=_concrete_symbolic_list(f"sorted_{state.pc}", sorted_items),
                        side_effects=iterator_side_effects or {},
                    )
                if BuiltinInputPolicy.definite_ordering_type_error(concrete_items):
                    result, constraint = SymbolicList.symbolic(f"sorted_{state.pc}")
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects={
                            **(iterator_side_effects or {}),
                            **SideEffects.type_error(
                                "builtins.sorted",
                                "items are not mutually orderable",
                            ),
                        },
                    )
                result, constraint = SymbolicList.symbolic(f"sorted_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=iterator_side_effects or {},
                )
        if BuiltinInputPolicy.iter_type_error(obj):
            result, constraint = SymbolicList.symbolic(f"sorted_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.sorted",
                    "sorted() argument is not iterable",
                ),
            )
        if isinstance(obj, SymbolicList):
            result, constraint = SymbolicList.symbolic(f"sorted_{obj.name}")
            return ModelResult(
                value=result,
                constraints=[constraint, result.z3_len == obj.z3_len],
            )
        result, constraint = SymbolicList.symbolic(f"sorted_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class SumModel(FunctionModel):
    """Model for sum()."""

    name = "sum"
    qualname = "builtins.sum"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply sum() model."""
        if (
            not args
            or len(args) > 2
            or set(kwargs) - {"start"}
            or (len(args) > 1 and "start" in kwargs)
        ):
            return ModelResult(
                value=0,
                side_effects=SideEffects.type_error(
                    "builtins.sum",
                    f"sum() received invalid positional argument count: {len(args)}",
                ),
            )

        iterable = args[0]
        start = args[1] if len(args) > 1 else kwargs.get("start", 0)

        if isinstance(iterable, ModeledGenerator):
            generator_result = modeled_generator_sum(
                name="sum",
                generator=iterable,
                state=state,
            )
            if generator_result is not None:
                return generator_result
            return ModelResult.int(f"sum_{state.pc}")

        concrete_items = _concrete_iterable_items(iterable, state)
        if concrete_items is not None:
            symbolic_sum = symbolic_sum_result(concrete_items, start, f"sum_{state.pc}")
            if symbolic_sum is not None:
                return symbolic_sum
            if all(
                not isinstance(x, (SymbolicValue, SymbolicType)) for x in concrete_items
            ) and not isinstance(start, (SymbolicValue, SymbolicType)):
                concrete_sum = BuiltinAggregatePolicy.safe_sum_concrete(
                    concrete_items,
                    cast("StackValue", start),
                )
                if concrete_sum is not None:
                    return ModelResult(value=concrete_sum)
                if _contains_forbidden_sum_text(concrete_items, start):
                    return ModelResult(
                        value=0,
                        side_effects=SideEffects.type_error(
                            "builtins.sum",
                            "sum() does not accept string or bytes values",
                        ),
                    )

        if BuiltinInputPolicy.iter_type_error(iterable):
            return ModelResult(
                value=0,
                side_effects=SideEffects.type_error(
                    "builtins.sum",
                    "sum() argument is not iterable",
                ),
            )

        return ModelResult.int(f"sum_{state.pc}")


def _contains_forbidden_sum_text(values: Sequence[object], start: object) -> bool:
    return isinstance(start, (str, bytes, bytearray)) or any(
        isinstance(item, (str, bytes, bytearray)) for item in values
    )


class EnumerateModel(FunctionModel):
    """Model for enumerate()."""

    name = "enumerate"
    qualname = "builtins.enumerate"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if (
            len(args) > 2
            or set(kwargs) - {"iterable", "start"}
            or (args and "iterable" in kwargs)
            or (len(args) > 1 and "start" in kwargs)
            or (not args and "iterable" not in kwargs)
        ):
            return _iterable_arity_error("enumerate", args, state)
        iterable = args[0] if args else kwargs["iterable"]
        start_value = args[1] if len(args) > 1 else kwargs.get("start", 0)
        if _definite_invalid_index(start_value):
            return _iterable_arity_error(
                "enumerate",
                args,
                state,
                "enumerate() start must be an integer",
            )
        concrete_items = _concrete_iterable_items(iterable, state)
        start = _concrete_int(start_value)
        if start is not None and (
            concrete_items is not None or _known_iterable_shape(iterable, state)
        ):
            source = EnumerateIteratorSource(iterable=iterable, start=start)
            return ModelResult(value=SymbolicIterator(f"enumerate_{state.pc}", source))
        if BuiltinInputPolicy.iter_type_error(iterable):
            return _iterable_arity_error(
                "enumerate",
                args,
                state,
                "enumerate() argument is not iterable",
            )

        result, constraint = SymbolicList.symbolic(f"enumerate_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class ZipModel(FunctionModel):
    """Model for zip()."""

    name = "zip"
    qualname = "builtins.zip"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if set(kwargs) - {"strict"}:
            return _iterable_arity_error("zip", args, state)
        strict = kwargs.get("strict", False)
        if not kwargs or isinstance(strict, bool):
            concrete_inputs: list[list[StackValue]] = []
            all_inputs_are_precise = True
            for arg in args:
                concrete_items = _concrete_iterable_items(arg, state)
                if concrete_items is None:
                    if BuiltinInputPolicy.iter_type_error(arg):
                        return _iterable_arity_error(
                            "zip",
                            args,
                            state,
                            "zip() argument is not iterable",
                        )
                    if not _known_iterable_shape(arg, state):
                        all_inputs_are_precise = False
                    continue
                concrete_inputs.append(concrete_items)
            if strict is False and all_inputs_are_precise:
                source = ZipIteratorSource(iterables=tuple(args))
                return ModelResult(value=SymbolicIterator(f"zip_{state.pc}", source))
            if len(concrete_inputs) == len(args):
                try:
                    pairs = list(zip(*concrete_inputs, strict=True))
                except ValueError as exc:
                    result, constraint = SymbolicList.symbolic(f"zip_{state.pc}")
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects=SideEffects.value_error("builtins.zip", str(exc)),
                    )
                return ModelResult(value=SymbolicIterator(f"zip_{state.pc}", pairs))
        elif any(BuiltinInputPolicy.iter_type_error(arg) for arg in args):
            return _iterable_arity_error("zip", args, state, "zip() argument is not iterable")

        result, constraint = SymbolicList.symbolic(f"zip_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


def _known_iterable_shape(value: object, state: VMState) -> bool:
    resolved = SymbolicObject.resolve(value, state)
    return isinstance(
        resolved,
        (list, tuple, str, bytes, bytearray, range, SymbolicIterator, SymbolicList, SymbolicString),
    )


def _concrete_int(value: StackValue) -> int | None:
    if isinstance(value, int):
        return int(value)
    if isinstance(value, SymbolicValue) and isinstance(value.value, int):
        return value.value
    return None


def _definite_invalid_index(value: StackValue) -> bool:
    if value is None or isinstance(value, (float, str, bytes, list, tuple, dict, set)):
        return True
    return isinstance(value, SymbolicValue) and value.affinity_type in {
        "float",
        "str",
        "bytes",
        "none",
        "NoneType",
        "list",
        "dict",
    }


def _concrete_iterable_items(value: StackValue, state: VMState) -> list[StackValue] | None:
    shared_items = IterationSources.iterable_items(value, state)
    if shared_items is not None:
        return shared_items
    if isinstance(value, (list, tuple)):
        return _stack_values_from_sequence(cast("Sequence[object]", value))
    return None


def _stack_values_from_sequence(items: Sequence[object]) -> list[StackValue]:
    return [cast("StackValue", item) for item in items]


def _concrete_symbolic_list(name: str, items: Sequence[StackValue]) -> SymbolicList:
    z3_array = z3.Array(f"{name}_arr", z3.IntSort(), z3.IntSort())
    for index, item in enumerate(items):
        if isinstance(item, SymbolicValue):
            stored = item.z3_int
        elif isinstance(item, bool):
            stored = ConstraintValues.int(int(item))
        elif isinstance(item, int):
            stored = ConstraintValues.int(item)
        else:
            stored = Z3_ZERO
        z3_array = z3.Store(z3_array, index, stored)
    return SymbolicList(
        name,
        z3_array=z3_array,
        z3_len=ConstraintValues.int(len(items)),
        element_type="any",
        _concrete_items=list(items),
    )
