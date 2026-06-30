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

"""Execution-facing models for the public :mod:`itertools` family."""

from __future__ import annotations

import inspect
import itertools
from typing import TYPE_CHECKING, Literal, cast

from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelDegradation, ModelResult
from pysymex._internal.models.stdlib.literals import concrete_call, raised_exception

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

FiniteOperation = Literal[
    "batched",
    "chain.from_iterable",
    "combinations",
    "combinations_with_replacement",
    "compress",
    "filterfalse",
    "groupby",
    "islice",
    "pairwise",
    "permutations",
    "product",
    "repeat",
    "tee",
    "zip_longest",
]
OpaqueOperation = Literal["count", "cycle", "dropwhile", "starmap", "takewhile"]


def _callable(operation: str) -> Callable[..., object]:
    if operation == "chain.from_iterable":
        return cast("Callable[..., object]", itertools.chain.from_iterable)
    return cast("Callable[..., object]", getattr(itertools, operation))


def _binding_failure(
    function: Callable[..., object],
    args: list[StackValue],
    kwargs: dict[str, StackValue],
    source: str,
) -> ModelResult | None:
    """Validate call shape when CPython exposes an inspectable signature."""
    try:
        signature = inspect.signature(function)
    except (TypeError, ValueError):
        return None
    try:
        signature.bind(*args, **kwargs)
    except TypeError as exc:
        return raised_exception(source, exc)
    return None


def _degradation(
    qualname: str,
    reason: str,
    *,
    kind: Literal["precision_loss", "unknown", "unsupported"],
) -> ModelDegradation:
    return ModelDegradation(
        kind=kind,
        label=qualname,
        owner="itertools models",
        reason=reason,
    )


def _exact_iterator(operation: str, values: Iterable[object], state: VMState) -> SymbolicIterator:
    materialized = SymbolicList.from_const(list(values))
    return SymbolicIterator(f"itertools_{operation}_{state.pc}", materialized)


def _opaque_iterator(operation: str, state: VMState) -> SymbolicIterator:
    return SymbolicIterator(f"itertools_{operation}_{state.pc}", object())


class FiniteItertoolsModel(FunctionModel):
    """Model pure finite itertools calls with exact retained output items."""

    aliases: tuple[str, ...] = ()

    def __init__(self, operation: FiniteOperation) -> None:
        self._operation = operation
        self.name = operation.rsplit(".", 1)[-1]
        self.qualname = f"itertools.{operation}"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        function = _callable(self._operation)
        invalid = _binding_failure(function, args, kwargs, self.qualname)
        if invalid is not None:
            return invalid

        resolved_args = [cast("StackValue", SymbolicObject.resolve(arg, state)) for arg in args]
        resolved_kwargs = {
            name: cast("StackValue", SymbolicObject.resolve(value, state))
            for name, value in kwargs.items()
        }
        concrete = concrete_call(resolved_args, resolved_kwargs)
        if concrete is not None and self._can_run_without_user_callback(concrete):
            try:
                result = function(*concrete[0], **concrete[1])
                if self._operation == "tee":
                    iterators = cast("tuple[Iterable[object], ...]", result)
                    return ModelResult(
                        value=SymbolicTuple(
                            tuple(
                                _exact_iterator(f"tee_{index}", iterator, state)
                                for index, iterator in enumerate(iterators)
                            ),
                        ),
                    )
                if self._operation == "groupby":
                    groups = [
                        (key, list(group))
                        for key, group in cast("Iterable[tuple[object, Iterable[object]]]", result)
                    ]
                    return ModelResult(value=_exact_iterator(self._operation, groups, state))
                return ModelResult(
                    value=_exact_iterator(
                        self._operation,
                        cast("Iterable[object]", result),
                        state,
                    ),
                )
            except (TypeError, ValueError) as exc:
                return raised_exception(self.qualname, exc)

        return ModelResult(
            value=_opaque_iterator(self._operation, state),
            degradations=[
                _degradation(
                    self.qualname,
                    "iterator values depend on symbolic input or a user callback",
                    kind="precision_loss",
                ),
            ],
        )

    def _can_run_without_user_callback(
        self,
        concrete: tuple[list[object], dict[str, object]],
    ) -> bool:
        if self._operation == "filterfalse":
            return bool(concrete[0]) and concrete[0][0] is None
        if self._operation == "groupby":
            key = concrete[0][1] if len(concrete[0]) > 1 else concrete[1].get("key")
            return key is None
        return True


class OpaqueItertoolsModel(FunctionModel):
    """Represent callback-driven and infinite iterators without inventing items."""

    aliases: tuple[str, ...] = ()

    def __init__(self, operation: OpaqueOperation) -> None:
        self._operation = operation
        self.name = operation
        self.qualname = f"itertools.{operation}"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        function = _callable(self._operation)
        invalid = _binding_failure(function, args, kwargs, self.qualname)
        if invalid is not None:
            return invalid
        infinite = self._operation in {"count", "cycle"}
        return ModelResult(
            value=_opaque_iterator(self._operation, state),
            degradations=[
                _degradation(
                    self.qualname,
                    (
                        "unbounded iterator values are generated lazily"
                        if infinite
                        else "user callback execution is not summarized by this model"
                    ),
                    kind="unknown" if infinite else "unsupported",
                ),
            ],
        )


itertools_runtime_models: list[FunctionModel] = [
    *(
        FiniteItertoolsModel(operation)
        for operation in cast(
            "tuple[FiniteOperation, ...]",
            (
                "batched",
                "chain.from_iterable",
                "combinations",
                "combinations_with_replacement",
                "compress",
                "filterfalse",
                "groupby",
                "islice",
                "pairwise",
                "permutations",
                "product",
                "repeat",
                "tee",
                "zip_longest",
            ),
        )
    ),
    *(
        OpaqueItertoolsModel(operation)
        for operation in cast(
            "tuple[OpaqueOperation, ...]",
            (
                "count",
                "cycle",
                "dropwhile",
                "starmap",
                "takewhile",
            ),
        )
    ),
]
