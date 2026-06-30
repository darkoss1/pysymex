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

"""Counter model for collections."""

from __future__ import annotations

import collections
import inspect
from typing import TYPE_CHECKING, Literal, cast

from pysymex._internal.core.identity.addressing import next_address
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelDegradation, ModelResult
from pysymex._internal.models.stdlib.literals import concrete_call, concrete_value, raised_exception

if TYPE_CHECKING:
    from collections.abc import Callable

    import z3

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def _counter_storage(value: object, state: VMState) -> SymbolicDict | None:
    if isinstance(value, SymbolicDict):
        return value
    if isinstance(value, SymbolicObject) and value.address != -1:
        stored = state.load_heap(value.address)
        if isinstance(stored, SymbolicDict) and stored.runtime_type == "Counter":
            return stored
    return None


def _tag_counter(storage: SymbolicDict) -> SymbolicDict:
    storage.set_runtime_type("Counter")
    storage.enable_default_factory()
    return storage


def _counter_degradation(method: str, reason: str) -> ModelDegradation:
    return ModelDegradation(
        kind="unknown",
        label=f"collections.Counter.{method}",
        owner="Counter runtime models",
        reason=reason,
    )


def _binding_failure(
    function: Callable[..., object],
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    source: str,
) -> ModelResult | None:
    try:
        inspect.signature(function).bind(*args, **kwargs)
    except TypeError as exc:
        return raised_exception(source, exc)
    return None


class CounterConstructorModel(FunctionModel):
    """Construct heap-backed counters with exact retained counts when possible."""

    name = "Counter"
    qualname = "collections.Counter"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        invalid = _binding_failure(collections.Counter, args, kwargs, self.qualname)
        if invalid is not None:
            return invalid
        concrete = concrete_call(args, kwargs)
        constraints: list[z3.BoolRef] = []
        degradations: list[ModelDegradation] = []
        if concrete is not None:
            try:
                counter_factory = cast(
                    "Callable[..., collections.Counter[object]]",
                    collections.Counter,
                )
                storage = _tag_counter(
                    SymbolicDict.from_const(dict(counter_factory(*concrete[0], **concrete[1]))),
                )
            except (TypeError, ValueError) as exc:
                return raised_exception(self.qualname, exc)
        else:
            storage, constraint = SymbolicDict.symbolic(f"counter_{state.pc}")
            storage = _tag_counter(storage)
            constraints.append(constraint)
            degradations.append(_counter_degradation("__init__", "counts depend on symbolic input"))
        address = next_address()
        handle = SymbolicObject(
            f"Counter_{address}",
            address,
            ConstraintValues.int(address),
            {address},
        )
        state.store_heap(address, storage)
        return ModelResult(value=handle, constraints=constraints, degradations=degradations)


class CounterQueryModel(FunctionModel):
    """Model Counter queries over exact retained count mappings."""

    aliases: tuple[str, ...]

    def __init__(self, method: Literal["most_common", "elements", "total"]) -> None:
        self._method = method
        self.name = method
        self.qualname = f"collections.Counter.{method}"
        self.aliases = (f"Counter.{method}",)

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        storage = _counter_storage(args[0], state) if args else None
        if storage is None:
            return self._unknown_result(state, "receiver storage is not a modeled Counter")
        payload = concrete_value(storage)
        concrete_rest = concrete_call(args[1:], kwargs)
        if isinstance(payload, dict) and concrete_rest is not None:
            counter = collections.Counter(cast("dict[object, int]", payload))
            try:
                if self._method == "most_common":
                    most_common = cast(
                        "Callable[..., list[tuple[object, int]]]",
                        counter.most_common,
                    )
                    return ModelResult(
                        value=SymbolicList.from_const(
                            most_common(*concrete_rest[0], **concrete_rest[1]),
                        ),
                    )
                if self._method == "elements":
                    values = SymbolicList.from_const(list(counter.elements()))
                    return ModelResult(
                        value=SymbolicIterator(f"counter_elements_{state.pc}", values),
                    )
                return ModelResult(value=SymbolicValue.from_const(counter.total()))
            except (TypeError, ValueError) as exc:
                return raised_exception(self.qualname, exc)
        return self._unknown_result(state, "query depends on symbolic counts or arguments")

    def _unknown_result(self, state: VMState, reason: str) -> ModelResult:
        degradation = [_counter_degradation(self._method, reason)]
        if self._method == "most_common":
            value, constraint = SymbolicList.symbolic(f"counter_most_common_{state.pc}")
            return ModelResult(value=value, constraints=[constraint], degradations=degradation)
        if self._method == "elements":
            return ModelResult(
                value=SymbolicIterator(f"counter_elements_{state.pc}", object()),
                degradations=degradation,
            )
        value, constraint = SymbolicValue.symbolic(f"counter_total_{state.pc}")
        return ModelResult(value=value, constraints=[constraint], degradations=degradation)


class CounterMutationModel(FunctionModel):
    """Apply exact Counter update/subtract mutations through the dict mutation seam."""

    aliases: tuple[str, ...]

    def __init__(self, method: Literal["update", "subtract"]) -> None:
        self._method = method
        self.name = method
        self.qualname = f"collections.Counter.{method}"
        self.aliases = (f"Counter.{method}",)

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        storage = _counter_storage(args[0], state) if args else None
        if storage is None:
            return ModelResult(
                value=ModelResult.none().value,
                degradations=[
                    _counter_degradation(self._method, "receiver storage is not a modeled Counter"),
                ],
            )
        payload = concrete_value(storage)
        concrete_rest = concrete_call(args[1:], kwargs)
        if isinstance(payload, dict) and concrete_rest is not None:
            counter = collections.Counter(cast("dict[object, int]", payload))
            try:
                getattr(counter, self._method)(*concrete_rest[0], **concrete_rest[1])
            except (TypeError, ValueError) as exc:
                return raised_exception(self.qualname, exc)
            updated = _tag_counter(SymbolicDict.from_const(dict(counter)))
            return ModelResult(
                value=ModelResult.none().value,
                side_effects={
                    "dict_mutation": {
                        "operation": f"counter.{self._method}",
                        "original_dict": storage,
                        "updated_dict": updated,
                    },
                },
            )
        return ModelResult(
            value=ModelResult.none().value,
            degradations=[
                _counter_degradation(
                    self._method,
                    "mutation depends on symbolic counts or arguments",
                ),
            ],
        )


class CounterModel:
    """Model for collections.Counter.

    Counter is a dict subclass for counting hashable objects.
    Elements are stored as dictionary keys and counts as values.
    """

    @staticmethod
    def model_init(
        state: VMState,
        iterable: SymbolicList | None = None,
    ) -> SymbolicDict:
        """Model Counter() initialization."""
        return SymbolicDict.empty("counter")

    @staticmethod
    def model_most_common(
        counter: SymbolicDict,
        n: SymbolicValue | int | None = None,
    ) -> SymbolicList:
        """Model Counter.most_common(n)."""
        return SymbolicList.empty("most_common_result")

    @staticmethod
    def model_elements(counter: SymbolicDict) -> SymbolicList:
        """Model Counter.elements()."""
        return SymbolicList.empty("counter_elements")

    @staticmethod
    def model_subtract(
        counter: SymbolicDict,
        other: SymbolicDict | None = None,
    ) -> None:
        """Model Counter.subtract()."""

    @staticmethod
    def model_update(
        counter: SymbolicDict,
        other: SymbolicDict | None = None,
    ) -> None:
        """Model Counter.update()."""


COUNTER_MODELS: list[FunctionModel] = [
    CounterConstructorModel(),
    *(CounterQueryModel(method) for method in ("most_common", "elements", "total")),
    *(CounterMutationModel(method) for method in ("update", "subtract")),
]
