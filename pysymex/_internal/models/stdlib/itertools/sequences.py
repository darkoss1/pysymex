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

"""Sequence-oriented itertools models."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.types.containers.lists import SymbolicList
    from pysymex._internal.typing.protocols import StackValue
else:
    from pysymex._internal.core.types.containers.lists import SymbolicList


def model_chain(*iterables: SymbolicList) -> SymbolicList:
    """Model itertools.chain(*iterables).

    Chains multiple iterables into a single iterator.
    The length is the sum of all input lengths.

    Args:
        *iterables: Iterables to chain together

    Returns:
        A SymbolicList representing the chained result

    """
    concrete_items = _chain_concrete_items(iterables)
    if concrete_items is not None:
        return SymbolicList.from_const(concrete_items)

    result = SymbolicList.empty("chain_result")
    if iterables:
        total_len = iterables[0].z3_len
        for it in iterables[1:]:
            total_len = total_len + it.z3_len
        result.z3_len = total_len

    return result


def _chain_concrete_items(iterables: tuple[SymbolicList, ...]) -> list[object] | None:
    chained: list[object] = []
    for iterable in iterables:
        items = iterable.concrete_items
        if items is None:
            return None
        chained.extend(items)
    return chained


def model_chain_from_iterable(iterable: SymbolicList) -> SymbolicList:
    """Model itertools.chain.from_iterable(iterable).

    Chains iterables from a single iterable of iterables.
    """
    return SymbolicList.empty("chain_from_iterable_result")


def model_islice(
    iterable: SymbolicList,
    *args: object,
) -> SymbolicList:
    """Model itertools.islice(iterable, stop) or islice(iterable, start, stop[, step]).

    Returns selected elements from the iterable.

    Args:
        iterable: Source iterable
        *args: Slice arguments

    Returns:
        A SymbolicList with sliced elements

    """
    result = SymbolicList.empty("islice_result")
    if len(args) == 1:
        stop = args[0]
        if isinstance(stop, int):
            clamped = z3.If(
                iterable.z3_len < stop,
                iterable.z3_len,
                ConstraintValues.int(stop),
            )
            result.z3_len = clamped
    elif len(args) >= 2:
        start, stop = args[0], args[1]
        step = args[2] if len(args) > 2 else 1
        if isinstance(start, int) and isinstance(stop, int) and isinstance(step, int):
            expected_len = max(0, (stop - start + step - 1) // step)
            result.z3_len = ConstraintValues.int(expected_len)

    return result


def model_groupby(
    iterable: SymbolicList,
    key: Callable[..., object] | None = None,
) -> SymbolicList:
    """Model itertools.groupby(iterable, key=None).

    Groups consecutive elements with the same key.

    Args:
        iterable: Iterable to group
        key: Key function (None = identity)

    Returns:
        A SymbolicList of (key, group) pairs

    """
    return SymbolicList.empty("groupby_result")


def model_accumulate(
    iterable: SymbolicList,
    func: object | None = None,
    initial: object = None,
) -> SymbolicList:
    """Model itertools.accumulate(iterable, func=None, *, initial=None).

    Returns running accumulation of iterable.
    """
    concrete = _model_default_accumulate_items(iterable, func, initial)
    if concrete is not None:
        return concrete

    result = SymbolicList.empty("accumulate_result")
    if initial is not None:
        result.z3_len = iterable.z3_len + 1
    else:
        result.z3_len = iterable.z3_len
    return result


def _model_default_accumulate_items(
    iterable: SymbolicList,
    func: object | None,
    initial: object,
) -> SymbolicList | None:
    if func is not None and not isinstance(func, SymbolicNoneType):
        return None
    items = iterable.concrete_items
    if items is None:
        return None

    result = SymbolicList.empty("accumulate_result")
    running = _known_int_like(initial) if initial is not None else None
    if initial is not None:
        if running is None:
            return None
        result = result.append(running)

    for item in items:
        next_value = _known_int_like(item)
        if next_value is None:
            return None
        running = next_value if running is None else running + next_value
        result = result.append(running)
    return result


def _known_int_like(value: object) -> SymbolicValue | None:
    if isinstance(value, bool | int):
        return SymbolicValue.from_const(value)
    if isinstance(value, SymbolicValue) and (
        value.affinity_type in {"int", "bool"}
        or z3.is_true(value.is_int)
        or z3.is_true(value.is_bool)
    ):
        return value
    return None


class AccumulateModel(FunctionModel):
    """Execution model for finite-shape ``itertools.accumulate`` calls."""

    name = "accumulate"
    qualname = "itertools.accumulate"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        iterable = SymbolicList.resolve(args[0], state) if args else None
        if iterable is None:
            result, constraint = SymbolicList.symbolic(f"accumulate_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        func = args[1] if len(args) > 1 else None
        return ModelResult(
            value=model_accumulate(iterable, func=func, initial=kwargs.get("initial")),
        )


class ChainModel(FunctionModel):
    """Execution model for finite-shape ``itertools.chain`` calls."""

    name = "chain"
    qualname = "itertools.chain"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if kwargs:
            result, constraint = SymbolicList.symbolic(f"chain_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])

        iterables: list[SymbolicList] = []
        for arg in args:
            iterable = SymbolicList.resolve(arg, state)
            if iterable is None:
                result, constraint = SymbolicList.symbolic(f"chain_{state.pc}")
                return ModelResult(value=result, constraints=[constraint])
            iterables.append(iterable)
        return ModelResult(value=model_chain(*iterables))


def model_takewhile(
    predicate: Callable[..., object],
    iterable: SymbolicList,
) -> SymbolicList:
    """Model itertools.takewhile(predicate, iterable).

    Takes elements while predicate is true.
    """
    return SymbolicList.empty("takewhile_result")


def model_dropwhile(
    predicate: Callable[..., object],
    iterable: SymbolicList,
) -> SymbolicList:
    """Model itertools.dropwhile(predicate, iterable).

    Drops elements while predicate is true, then yields rest.
    """
    return SymbolicList.empty("dropwhile_result")
