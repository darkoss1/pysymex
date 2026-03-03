"""
pysymex Iterator Protocol - Phase 16

Hub module — re-exports from:
  iterators_base       : IteratorState, IterationResult, SymbolicIterator, SymbolicRange, SymbolicSequenceIterator
  iterators_combinators: SymbolicEnumerate, SymbolicZip, SymbolicMap, SymbolicFilter, SymbolicReversed,
                         SymbolicDictKeysIterator, SymbolicDictItemsIterator, LoopBounds

Factory functions (create_iterator, symbolic_*) remain here.
"""

from __future__ import annotations


from collections.abc import Callable

from typing import Any


import z3


from pysymex.core.memory_model import SymbolicArray


from pysymex.core.iterators_base import (
    IterationResult,
    IteratorState,
    SymbolicIterator,
    SymbolicRange,
    SymbolicSequenceIterator,
)

from pysymex.core.iterators_combinators import (
    LoopBounds,
    SymbolicDictItemsIterator,
    SymbolicDictKeysIterator,
    SymbolicEnumerate,
    SymbolicFilter,
    SymbolicMap,
    SymbolicReversed,
    SymbolicZip,
)


def create_iterator(iterable: Any, name: str = "iter") -> SymbolicIterator:
    """
    Create an appropriate symbolic iterator for the given iterable.
    """

    if isinstance(iterable, SymbolicIterator):
        return iterable

    if isinstance(iterable, range):
        return SymbolicRange.from_args(iterable.start, iterable.stop, iterable.step, name=name)

    if isinstance(iterable, (list, tuple, str)):
        return SymbolicSequenceIterator(sequence=iterable, _name=name)

    if isinstance(iterable, dict):
        keys_list: list[Any] = list(iterable.keys())

        return SymbolicDictKeysIterator(keys=keys_list, _name=name)

    if isinstance(iterable, SymbolicArray):
        return SymbolicSequenceIterator(sequence=iterable, _name=name)

    try:
        return SymbolicSequenceIterator(sequence=list(iterable), _name=name)

    except Exception as exc:
        raise TypeError(f"Cannot create iterator from {type(iterable)}") from exc


def symbolic_range(*args: int | z3.ArithRef, name: str = "range") -> SymbolicRange:
    """Create a symbolic range iterator."""

    return SymbolicRange.from_args(*args, name=name)


def symbolic_enumerate(iterable: Any, start: int = 0, name: str = "enumerate") -> SymbolicEnumerate:
    """Create a symbolic enumerate iterator."""

    inner = create_iterator(iterable, f"{name}_inner")

    return SymbolicEnumerate(inner=inner, counter=start, _name=name)


def symbolic_zip(*iterables: Any, name: str = "zip") -> SymbolicZip:
    """Create a symbolic zip iterator."""

    iterators = [create_iterator(it, f"{name}_{i}") for i, it in enumerate(iterables)]

    return SymbolicZip(iterators=iterators, _name=name)


def symbolic_map(func: Callable[..., Any], iterable: Any, name: str = "map") -> SymbolicMap:
    """Create a symbolic map iterator."""

    inner = create_iterator(iterable, f"{name}_inner")

    return SymbolicMap(func=func, inner=inner, _name=name)


def symbolic_filter(
    predicate: Callable[..., Any], iterable: Any, name: str = "filter"
) -> SymbolicFilter:
    """Create a symbolic filter iterator."""

    inner = create_iterator(iterable, f"{name}_inner")

    return SymbolicFilter(predicate=predicate, inner=inner, _name=name)


def symbolic_reversed(sequence: Any, name: str = "reversed") -> SymbolicReversed:
    """Create a symbolic reversed iterator."""

    return SymbolicReversed(sequence=sequence, _name=name)


def collect_iterator(
    iterator: SymbolicIterator, max_iterations: int = 1000
) -> tuple[list[Any], list[z3.BoolRef]]:
    """
    Collect all values from an iterator.
    Returns (values, constraints) tuple.
    """

    values: list[Any] = []

    constraints: list[z3.BoolRef] = []

    current = iterator

    for _ in range(max_iterations):
        result = next(current)

        constraints.append(result.constraint)

        if result.exhausted:
            break

        values.append(result.value)

        current = result.iterator

    return values, constraints


__all__ = [
    "IteratorState",
    "IterationResult",
    "SymbolicIterator",
    "SymbolicRange",
    "SymbolicSequenceIterator",
    "SymbolicEnumerate",
    "SymbolicZip",
    "SymbolicMap",
    "SymbolicFilter",
    "SymbolicReversed",
    "SymbolicDictKeysIterator",
    "SymbolicDictItemsIterator",
    "LoopBounds",
    "create_iterator",
    "symbolic_range",
    "symbolic_enumerate",
    "symbolic_zip",
    "symbolic_map",
    "symbolic_filter",
    "symbolic_reversed",
    "collect_iterator",
]
