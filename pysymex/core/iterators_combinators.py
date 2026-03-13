"""Combinator iterators: Enumerate, Zip, Map, Filter, Reversed,
Dict iterators, and LoopBounds analysis.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

import z3

logger = logging.getLogger(__name__)

from pysymex.core.iterators_base import (
    IterationResult,
    SymbolicIterator,
    SymbolicRange,
)
from pysymex.core.memory_model import SymbolicArray
from pysymex.core.symbolic_types import SymbolicBool, SymbolicInt, SymbolicList, SymbolicTuple


@dataclass
class SymbolicEnumerate(SymbolicIterator):
    """
    Symbolic enumerate() iterator.
    Yields (index, value) pairs.
    """

    inner: SymbolicIterator
    counter: int | z3.ArithRef = field(default=0)
    _name: str = field(default="enumerate")

    def __next__(self) -> IterationResult:
        """Next."""
        """Return the next item from the iterator."""
        inner_result = next(self.inner)
        if inner_result.exhausted:
            return IterationResult(
                value=None, exhausted=True, constraint=inner_result.constraint, iterator=self
            )
        idx = self.counter
        if isinstance(idx, int):
            idx_val = SymbolicInt(z3.IntVal(idx))
        else:
            idx_val = SymbolicInt(idx)
        pair = SymbolicTuple((idx_val, inner_result.value))
        new_enum = SymbolicEnumerate(
            inner=inner_result.iterator,
            counter=self.counter + 1 if isinstance(self.counter, int) else self.counter + 1,
            _name=self._name,
        )
        return IterationResult(
            value=pair, exhausted=False, constraint=inner_result.constraint, iterator=new_enum
        )

    def has_next(self) -> z3.BoolRef:
        """Has next."""
        return self.inner.has_next()

    def remaining_bound(self) -> int | z3.ArithRef:
        """Remaining bound."""
        return self.inner.remaining_bound()

    def clone(self) -> SymbolicEnumerate:
        """Clone."""
        return SymbolicEnumerate(inner=self.inner.clone(), counter=self.counter, _name=self._name)

    @property
    def is_bounded(self) -> bool:
        """Is bounded."""
        """Property returning the is_bounded."""
        return self.inner.is_bounded


@dataclass
class SymbolicZip(SymbolicIterator):
    """
    Symbolic zip() iterator.
    Yields tuples from multiple iterables, stopping at shortest.
    """

    iterators: list[SymbolicIterator]
    _name: str = field(default="zip")

    def __next__(self) -> IterationResult:
        """Next."""
        """Return the next item from the iterator."""
        values: list[object] = []
        constraints: list[z3.BoolRef] = []
        new_iterators: list[SymbolicIterator] = []
        for it in self.iterators:
            result = next(it)
            if result.exhausted:
                return IterationResult(
                    value=None,
                    exhausted=True,
                    constraint=z3.And(*constraints) if constraints else z3.BoolVal(True),
                    iterator=self,
                )
            values.append(result.value)
            constraints.append(result.constraint)
            new_iterators.append(result.iterator)
        new_zip = SymbolicZip(iterators=new_iterators, _name=self._name)
        return IterationResult(
            value=SymbolicTuple(tuple(values)),
            exhausted=False,
            constraint=z3.And(*constraints) if constraints else z3.BoolVal(True),
            iterator=new_zip,
        )

    def has_next(self) -> z3.BoolRef:
        """Has next."""
        if not self.iterators:
            return z3.BoolVal(False)
        conditions = [it.has_next() for it in self.iterators]
        return z3.And(*conditions)

    def remaining_bound(self) -> int | z3.ArithRef:
        """Remaining bound."""
        if not self.iterators:
            return 0
        bounds = [it.remaining_bound() for it in self.iterators]
        if all(isinstance(b, int) for b in bounds):
            return min(bounds)
        result = bounds[0]
        for b in bounds[1:]:
            if isinstance(result, int) and isinstance(b, int):
                result = min(result, b)
            else:
                r = result if isinstance(result, z3.ArithRef) else z3.IntVal(result)
                bb = b if isinstance(b, z3.ArithRef) else z3.IntVal(b)
                result = z3.If(r < bb, r, bb)
        return result

    def clone(self) -> SymbolicZip:
        """Clone."""
        return SymbolicZip(iterators=[it.clone() for it in self.iterators], _name=self._name)

    @property
    def is_bounded(self) -> bool:
        """Is bounded."""
        """Property returning the is_bounded."""
        return all(it.is_bounded for it in self.iterators)


@dataclass
class SymbolicMap(SymbolicIterator):
    """
    Symbolic map() iterator.
    Applies a function to each element.
    """

    func: Callable[[object], object]
    inner: SymbolicIterator
    _name: str = field(default="map")

    def __next__(self) -> IterationResult:
        """Next."""
        """Return the next item from the iterator."""
        inner_result = next(self.inner)
        if inner_result.exhausted:
            return IterationResult(
                value=None, exhausted=True, constraint=inner_result.constraint, iterator=self
            )
        try:
            mapped_value = self.func(inner_result.value)
        except (TypeError, ValueError, AttributeError):
            logger.debug("Map function application failed", exc_info=True)
            mapped_value = inner_result.value
        new_map = SymbolicMap(func=self.func, inner=inner_result.iterator, _name=self._name)
        return IterationResult(
            value=mapped_value,
            exhausted=False,
            constraint=inner_result.constraint,
            iterator=new_map,
        )

    def has_next(self) -> z3.BoolRef:
        """Has next."""
        return self.inner.has_next()

    def remaining_bound(self) -> int | z3.ArithRef:
        """Remaining bound."""
        return self.inner.remaining_bound()

    def clone(self) -> SymbolicMap:
        """Clone."""
        return SymbolicMap(func=self.func, inner=self.inner.clone(), _name=self._name)

    @property
    def is_bounded(self) -> bool:
        """Is bounded."""
        """Property returning the is_bounded."""
        return self.inner.is_bounded


@dataclass
class SymbolicFilter(SymbolicIterator):
    """
    Symbolic filter() iterator.
    Yields only elements where predicate is true.
    Note: Filter can change the number of iterations.
    """

    predicate: Callable[[object], bool]
    inner: SymbolicIterator
    _name: str = field(default="filter")
    _skip_count: int = field(default=0)

    _MAX_FILTER_ITERATIONS = 10000

    def __next__(self) -> IterationResult:
        """Next."""
        """Return the next item from the iterator."""
        current_inner = self.inner
        constraints: list[z3.BoolRef] = []
        for _filter_step in range(self._MAX_FILTER_ITERATIONS):
            inner_result = next(current_inner)
            if inner_result.exhausted:
                return IterationResult(
                    value=None,
                    exhausted=True,
                    constraint=z3.And(*constraints) if constraints else z3.BoolVal(True),
                    iterator=self,
                )
            constraints.append(inner_result.constraint)
            try:
                passes = self.predicate(inner_result.value)
                if isinstance(passes, (SymbolicBool, z3.BoolRef)):
                    passes = True
            except (TypeError, ValueError, AttributeError):
                logger.debug("Filter predicate evaluation failed", exc_info=True)
                passes = True
            if passes:
                new_filter = SymbolicFilter(
                    predicate=self.predicate, inner=inner_result.iterator, _name=self._name
                )
                return IterationResult(
                    value=inner_result.value,
                    exhausted=False,
                    constraint=z3.And(*constraints) if constraints else z3.BoolVal(True),
                    iterator=new_filter,
                )
            current_inner = inner_result.iterator

        logger.warning(
            "SymbolicFilter '%s' hit iteration limit (%d); "
            "treating as exhausted — results may be incomplete",
            self._name,
            self._MAX_FILTER_ITERATIONS,
        )
        return IterationResult(
            value=None,
            exhausted=True,
            constraint=z3.And(*constraints) if constraints else z3.BoolVal(True),
            iterator=self,
        )

    def has_next(self) -> z3.BoolRef:
        """Has next."""
        return self.inner.has_next()

    def remaining_bound(self) -> int | z3.ArithRef:
        """Remaining bound."""
        return self.inner.remaining_bound()

    def clone(self) -> SymbolicFilter:
        """Clone."""
        return SymbolicFilter(predicate=self.predicate, inner=self.inner.clone(), _name=self._name)

    @property
    def is_bounded(self) -> bool:
        """Is bounded."""
        """Property returning the is_bounded."""
        return self.inner.is_bounded


@dataclass
class SymbolicReversed(SymbolicIterator):
    """
    Symbolic reversed() iterator.
    Iterates over a sequence in reverse order.
    """

    sequence: list[object] | tuple[object, ...] | str | SymbolicList
    index: int | z3.ArithRef = field(init=False)
    _name: str = field(default="reversed")

    def __post_init__(self):
        """Post init."""
        if isinstance(self.sequence, (list, tuple, str)):
            self.index = len(self.sequence) - 1
        elif isinstance(self.sequence, SymbolicArray):
            self.index = self.sequence.length - 1
        else:
            self.index = -1

    def __next__(self) -> IterationResult:
        """Next."""
        """Return the next item from the iterator."""
        has_next_constraint = self.has_next()
        if isinstance(self.index, int) and self.index < 0:
            return IterationResult(
                value=None, exhausted=True, constraint=has_next_constraint, iterator=self
            )
        if isinstance(self.sequence, (list, tuple, str)):
            if isinstance(self.index, int) and 0 <= self.index < len(self.sequence):
                value = self.sequence[self.index]
                exhausted = False
            else:
                value = None
                exhausted = True
        else:
            value = self.sequence[self.index] if hasattr(self.sequence, "__getitem__") else None
            exhausted = False
        new_iter = self.clone()
        if isinstance(new_iter.index, int):
            new_iter.index = new_iter.index - 1
        else:
            new_iter.index = new_iter.index - 1
        return IterationResult(
            value=value, exhausted=exhausted, constraint=has_next_constraint, iterator=new_iter
        )

    def has_next(self) -> z3.BoolRef:
        """Has next."""
        if isinstance(self.index, int):
            return z3.BoolVal(self.index >= 0)
        else:
            return self.index >= 0

    def remaining_bound(self) -> int | z3.ArithRef:
        """Remaining bound."""
        if isinstance(self.index, int):
            return max(0, self.index + 1)
        else:
            return z3.If(self.index >= 0, self.index + 1, z3.IntVal(0))

    def clone(self) -> SymbolicReversed:
        """Clone."""
        new_rev = SymbolicReversed(sequence=self.sequence, _name=self._name)
        new_rev.index = self.index
        return new_rev

    @property
    def is_bounded(self) -> bool:
        """Is bounded."""
        """Property returning the is_bounded."""
        return True


@dataclass
class SymbolicDictKeysIterator(SymbolicIterator):
    """Iterator over dictionary keys."""

    keys: list[object]
    index: int = field(default=0)
    _name: str = field(default="dict_keys")

    def __next__(self) -> IterationResult:
        """Next."""
        """Return the next item from the iterator."""
        if self.index >= len(self.keys):
            return IterationResult(
                value=None, exhausted=True, constraint=z3.BoolVal(True), iterator=self
            )
        value = self.keys[self.index]
        new_iter = SymbolicDictKeysIterator(keys=self.keys, index=self.index + 1, _name=self._name)
        return IterationResult(
            value=value, exhausted=False, constraint=z3.BoolVal(True), iterator=new_iter
        )

    def has_next(self) -> z3.BoolRef:
        """Has next."""
        return z3.BoolVal(self.index < len(self.keys))

    def remaining_bound(self) -> int:
        """Remaining bound."""
        return max(0, len(self.keys) - self.index)

    def clone(self) -> SymbolicDictKeysIterator:
        """Clone."""
        return SymbolicDictKeysIterator(keys=self.keys, index=self.index, _name=self._name)

    @property
    def is_bounded(self) -> bool:
        """Is bounded."""
        """Property returning the is_bounded."""
        return True


@dataclass
class SymbolicDictItemsIterator(SymbolicIterator):
    """Iterator over dictionary items (key, value pairs)."""

    items: list[object]
    index: int = field(default=0)
    _name: str = field(default="dict_items")

    def __next__(self) -> IterationResult:
        """Next."""
        """Return the next item from the iterator."""
        if self.index >= len(self.items):
            return IterationResult(
                value=None, exhausted=True, constraint=z3.BoolVal(True), iterator=self
            )
        key, value = self.items[self.index]
        pair = SymbolicTuple((key, value))
        new_iter = SymbolicDictItemsIterator(
            items=self.items, index=self.index + 1, _name=self._name
        )
        return IterationResult(
            value=pair, exhausted=False, constraint=z3.BoolVal(True), iterator=new_iter
        )

    def has_next(self) -> z3.BoolRef:
        """Has next."""
        return z3.BoolVal(self.index < len(self.items))

    def remaining_bound(self) -> int:
        """Remaining bound."""
        return max(0, len(self.items) - self.index)

    def clone(self) -> SymbolicDictItemsIterator:
        """Clone."""
        return SymbolicDictItemsIterator(items=self.items, index=self.index, _name=self._name)

    @property
    def is_bounded(self) -> bool:
        """Is bounded."""
        """Property returning the is_bounded."""
        return True


@dataclass
class LoopBounds:
    """
    Analysis results for loop bounds.
    """

    min_iterations: int | z3.ArithRef
    max_iterations: int | z3.ArithRef
    is_finite: bool
    is_symbolic: bool
    constraint: z3.BoolRef | None = None

    @classmethod
    def from_iterator(cls, iterator: SymbolicIterator) -> LoopBounds:
        """Analyze an iterator to determine loop bounds."""
        bound = iterator.remaining_bound()
        if isinstance(bound, int):
            return cls(min_iterations=0, max_iterations=bound, is_finite=True, is_symbolic=False)
        else:
            return cls(
                min_iterations=0,
                max_iterations=bound,
                is_finite=iterator.is_bounded,
                is_symbolic=True,
                constraint=bound >= 0,
            )

    @classmethod
    def from_range(cls, start: object, stop: object, step: object = 1) -> LoopBounds:
        """Analyze bounds from range parameters."""
        sym_range = SymbolicRange(start=start, stop=stop, step=step)
        return cls.from_iterator(sym_range)

    def get_unroll_count(self, max_unroll: int = 100) -> int:
        """Get a safe number of iterations to unroll."""
        if isinstance(self.max_iterations, int):
            return min(self.max_iterations, max_unroll)
        return max_unroll
