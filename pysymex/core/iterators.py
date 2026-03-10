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

import z3

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
from pysymex.core.memory_model import SymbolicArray


def create_iterator(iterable: object, name: str = "iter") -> SymbolicIterator:
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
        keys_list: list[object] = list(iterable.keys())
        return SymbolicDictKeysIterator(keys=keys_list, _name=name)
    if isinstance(iterable, SymbolicArray):
        return SymbolicSequenceIterator(sequence=iterable, _name=name)
    try:
        return SymbolicSequenceIterator(sequence=list(iterable), _name=name)
    except TypeError as exc:
        raise TypeError(f"Cannot create iterator from {type (iterable )}") from exc


def symbolic_range(*args: int | z3.ArithRef, name: str = "range") -> SymbolicRange:
    """Create a symbolic range iterator."""
    return SymbolicRange.from_args(*args, name=name)


def symbolic_enumerate(
    iterable: object, start: int = 0, name: str = "enumerate"
) -> SymbolicEnumerate:
    """Create a symbolic enumerate iterator."""
    inner = create_iterator(iterable, f"{name}_inner")
    return SymbolicEnumerate(inner=inner, counter=start, _name=name)


def symbolic_zip(*iterables: object, name: str = "zip") -> SymbolicZip:
    """Create a symbolic zip iterator."""
    iterators = [create_iterator(it, f"{name}_{i}") for i, it in enumerate(iterables)]
    return SymbolicZip(iterators=iterators, _name=name)


def symbolic_map(func: Callable[..., object], iterable: object, name: str = "map") -> SymbolicMap:
    """Create a symbolic map iterator."""
    inner = create_iterator(iterable, f"{name}_inner")
    return SymbolicMap(func=func, inner=inner, _name=name)


def symbolic_filter(
    predicate: Callable[..., object], iterable: object, name: str = "filter"
) -> SymbolicFilter:
    """Create a symbolic filter iterator."""
    inner = create_iterator(iterable, f"{name}_inner")
    return SymbolicFilter(predicate=predicate, inner=inner, _name=name)


def symbolic_reversed(sequence: object, name: str = "reversed") -> SymbolicReversed:
    """Create a symbolic reversed iterator."""
    return SymbolicReversed(sequence=sequence, _name=name)


def collect_iterator(
    iterator: SymbolicIterator, max_iterations: int = 1000
) -> tuple[list[object], list[z3.BoolRef]]:
    """
    Collect all values from an iterator.
    Returns (values, constraints) tuple.
    """
    values: list[object] = []
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
    "IterationResult",
    "IteratorState",
    "LoopBounds",
    "SymbolicDictItemsIterator",
    "SymbolicDictKeysIterator",
    "SymbolicEnumerate",
    "SymbolicFilter",
    "SymbolicIterator",
    "SymbolicMap",
    "SymbolicRange",
    "SymbolicReversed",
    "SymbolicSequenceIterator",
    "SymbolicZip",
    "collect_iterator",
    "create_iterator",
    "symbolic_enumerate",
    "symbolic_filter",
    "symbolic_map",
    "symbolic_range",
    "symbolic_reversed",
    "symbolic_zip",
]
