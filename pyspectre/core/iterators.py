"""
PySpectre Iterator Protocol - Phase 16
Provides symbolic iteration support for for-loops and comprehensions.
Critical for verifying code with loops.
Architecture:
    GET_ITER    → Create SymbolicIterator from iterable
    FOR_ITER    → Fork execution: (has_next, value) or (exhausted)
    END_FOR     → Merge execution paths
Supported Iterators:
    - range(start, stop, step)
    - enumerate(iterable)
    - zip(iter1, iter2, ...)
    - map(func, iterable)
    - filter(pred, iterable)
    - reversed(sequence)
    - iter(sequence)
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any
import z3
from .memory_model import SymbolicArray
from .symbolic_types import SymbolicBool, SymbolicInt, SymbolicList, SymbolicTuple


class IteratorState(Enum):
    """State of a symbolic iterator."""

    ACTIVE = auto()
    EXHAUSTED = auto()
    UNKNOWN = auto()


@dataclass
class IterationResult:
    """Result of calling next() on an iterator."""

    value: Any
    exhausted: bool
    constraint: z3.BoolRef
    iterator: SymbolicIterator

    @property
    def has_value(self) -> bool:
        return not self.exhausted


class SymbolicIterator(ABC):
    """
    Base class for symbolic iterators.
    Supports both concrete iteration (known bounds) and symbolic
    iteration (bounds depend on symbolic values).
    """

    @abstractmethod
    def __next__(self) -> IterationResult:
        """
        Get the next value from the iterator.
        Returns an IterationResult with:
        - value: The next value (if not exhausted)
        - exhausted: Whether the iterator is done
        - constraint: Z3 constraint for this path
        - iterator: Updated iterator state
        """

    @abstractmethod
    def has_next(self) -> z3.BoolRef:
        """Return a Z3 expression for whether there are more elements."""

    @abstractmethod
    def remaining_bound(self) -> int | z3.ArithRef:
        """
        Return an upper bound on remaining iterations.
        Used for termination proofs and loop unrolling decisions.
        """

    @abstractmethod
    def clone(self) -> SymbolicIterator:
        """Create a copy of this iterator at current state."""

    @property
    @abstractmethod
    def is_bounded(self) -> bool:
        """Whether the iterator has a known finite bound."""

    def __iter__(self) -> SymbolicIterator:
        return self


@dataclass
class SymbolicRange(SymbolicIterator):
    """
    Symbolic range iterator.
    Models Python's range(start, stop, step) with full symbolic support.
    """

    start: int | z3.ArithRef
    stop: int | z3.ArithRef
    step: int | z3.ArithRef
    current: int | z3.ArithRef = field(init=False)
    _iteration_count: int = field(default=0, init=False)
    _name: str = field(default="range")

    def __post_init__(self):
        self.current = self.start
        if not isinstance(self.start, (int, z3.ArithRef)):
            self.start = self.start.value if hasattr(self.start, "value") else int(self.start)
        if not isinstance(self.stop, (int, z3.ArithRef)):
            self.stop = self.stop.value if hasattr(self.stop, "value") else int(self.stop)
        if not isinstance(self.step, (int, z3.ArithRef)):
            self.step = self.step.value if hasattr(self.step, "value") else int(self.step)

    @classmethod
    def from_args(cls, *args, name: str = "range") -> SymbolicRange:
        """Create from Python range() style arguments."""
        if len(args) == 1:
            return cls(start=0, stop=args[0], step=1, _name=name)
        elif len(args) == 2:
            return cls(start=args[0], stop=args[1], step=1, _name=name)
        elif len(args) == 3:
            return cls(start=args[0], stop=args[1], step=args[2], _name=name)
        else:
            raise ValueError(f"range() takes 1-3 arguments, got {len(args)}")

    def __next__(self) -> IterationResult:
        has_next_constraint = self.has_next()
        value = self.current
        if isinstance(value, int):
            result_value = SymbolicInt(z3.IntVal(value))
        elif isinstance(value, z3.ArithRef):
            result_value = SymbolicInt(value)
        else:
            result_value = value
        new_iter = self.clone()
        if isinstance(new_iter.current, int) and isinstance(new_iter.step, int):
            new_iter.current = new_iter.current + new_iter.step
        else:
            curr = (
                new_iter.current
                if isinstance(new_iter.current, z3.ArithRef)
                else z3.IntVal(new_iter.current)
            )
            step = (
                new_iter.step
                if isinstance(new_iter.step, z3.ArithRef)
                else z3.IntVal(new_iter.step)
            )
            new_iter.current = curr + step
        new_iter._iteration_count = self._iteration_count + 1
        if self._is_concrete:
            exhausted = not self._concrete_has_next()
            constraint = z3.BoolVal(True)
        else:
            exhausted = False
            constraint = has_next_constraint
        return IterationResult(
            value=result_value, exhausted=exhausted, constraint=constraint, iterator=new_iter
        )

    def has_next(self) -> z3.BoolRef:
        """Check if there are more elements."""
        if self._is_concrete:
            return z3.BoolVal(self._concrete_has_next())
        curr = self.current if isinstance(self.current, z3.ArithRef) else z3.IntVal(self.current)
        stop = self.stop if isinstance(self.stop, z3.ArithRef) else z3.IntVal(self.stop)
        step = self.step if isinstance(self.step, z3.ArithRef) else z3.IntVal(self.step)
        positive_step = z3.And(step > 0, curr < stop)
        negative_step = z3.And(step < 0, curr > stop)
        return z3.Or(positive_step, negative_step)

    def _concrete_has_next(self) -> bool:
        """Concrete check for more elements."""
        if not self._is_concrete:
            return True
        curr = self.current if isinstance(self.current, int) else self.current.as_long()
        stop = self.stop if isinstance(self.stop, int) else self.stop.as_long()
        step = self.step if isinstance(self.step, int) else self.step.as_long()
        if step > 0:
            return curr < stop
        elif step < 0:
            return curr > stop
        else:
            return False

    @property
    def _is_concrete(self) -> bool:
        """Check if all values are concrete."""
        return (
            (
                isinstance(self.current, int)
                or (isinstance(self.current, z3.ArithRef) and z3.is_int_value(self.current))
            )
            and (
                isinstance(self.stop, int)
                or (isinstance(self.stop, z3.ArithRef) and z3.is_int_value(self.stop))
            )
            and (
                isinstance(self.step, int)
                or (isinstance(self.step, z3.ArithRef) and z3.is_int_value(self.step))
            )
        )

    def remaining_bound(self) -> int | z3.ArithRef:
        """Calculate remaining iterations."""
        if self._is_concrete:
            curr = self.current if isinstance(self.current, int) else self.current.as_long()
            stop = self.stop if isinstance(self.stop, int) else self.stop.as_long()
            step = self.step if isinstance(self.step, int) else self.step.as_long()
            if step > 0:
                return max(0, (stop - curr + step - 1) // step)
            elif step < 0:
                return max(0, (curr - stop - step - 1) // (-step))
            else:
                return 0
        curr = self.current if isinstance(self.current, z3.ArithRef) else z3.IntVal(self.current)
        stop = self.stop if isinstance(self.stop, z3.ArithRef) else z3.IntVal(self.stop)
        step = self.step if isinstance(self.step, z3.ArithRef) else z3.IntVal(self.step)
        diff = stop - curr
        return z3.If(
            step > 0,
            z3.If(diff > 0, (diff + step - 1) / step, z3.IntVal(0)),
            z3.If(diff < 0, (-diff - step - 1) / (-step), z3.IntVal(0)),
        )

    def clone(self) -> SymbolicRange:
        """Create a copy at current state."""
        new_range = SymbolicRange(
            start=self.start, stop=self.stop, step=self.step, _name=self._name
        )
        new_range.current = self.current
        new_range._iteration_count = self._iteration_count
        return new_range

    @property
    def is_bounded(self) -> bool:
        return True

    @property
    def length(self) -> int | z3.ArithRef:
        """Total length of the range."""
        if self._is_concrete:
            start = self.start if isinstance(self.start, int) else self.start.as_long()
            stop = self.stop if isinstance(self.stop, int) else self.stop.as_long()
            step = self.step if isinstance(self.step, int) else self.step.as_long()
            if step > 0:
                return max(0, (stop - start + step - 1) // step)
            elif step < 0:
                return max(0, (start - stop - step - 1) // (-step))
            else:
                return 0
        start = self.start if isinstance(self.start, z3.ArithRef) else z3.IntVal(self.start)
        stop = self.stop if isinstance(self.stop, z3.ArithRef) else z3.IntVal(self.stop)
        step = self.step if isinstance(self.step, z3.ArithRef) else z3.IntVal(self.step)
        diff = stop - start
        return z3.If(
            step > 0,
            z3.If(diff > 0, (diff + step - 1) / step, z3.IntVal(0)),
            z3.If(diff < 0, (-diff - step - 1) / (-step), z3.IntVal(0)),
        )

    def __repr__(self) -> str:
        return f"SymbolicRange({self.start}, {self.stop}, {self.step}, current={self.current})"


@dataclass
class SymbolicSequenceIterator(SymbolicIterator):
    """
    Iterator over a sequence (list, tuple, string).
    """

    sequence: list | tuple | str | SymbolicList | SymbolicArray
    index: int | z3.ArithRef = field(default=0)
    _name: str = field(default="iter")

    def __post_init__(self):
        if isinstance(self.index, SymbolicInt):
            self.index = self.index.value

    def __next__(self) -> IterationResult:
        has_next_constraint = self.has_next()
        if isinstance(self.sequence, (list, tuple, str)):
            if isinstance(self.index, int) and 0 <= self.index < len(self.sequence):
                value = self.sequence[self.index]
            else:
                value = None
            exhausted = isinstance(self.index, int) and self.index >= len(self.sequence)
        elif isinstance(self.sequence, SymbolicArray):
            value = self.sequence.get(self.index)
            exhausted = False
        else:
            value = self.sequence[self.index] if hasattr(self.sequence, "__getitem__") else None
            exhausted = False
        new_iter = self.clone()
        if isinstance(new_iter.index, int):
            new_iter.index = new_iter.index + 1
        else:
            new_iter.index = new_iter.index + 1
        return IterationResult(
            value=value, exhausted=exhausted, constraint=has_next_constraint, iterator=new_iter
        )

    def has_next(self) -> z3.BoolRef:
        if isinstance(self.sequence, (list, tuple, str)):
            length = len(self.sequence)
            if isinstance(self.index, int):
                return z3.BoolVal(self.index < length)
            else:
                return self.index < length
        elif isinstance(self.sequence, SymbolicArray):
            idx = self.index if isinstance(self.index, z3.ArithRef) else z3.IntVal(self.index)
            return idx < self.sequence.length
        return z3.BoolVal(True)

    def remaining_bound(self) -> int | z3.ArithRef:
        if isinstance(self.sequence, (list, tuple, str)):
            length = len(self.sequence)
            if isinstance(self.index, int):
                return max(0, length - self.index)
            else:
                return z3.If(self.index < length, length - self.index, z3.IntVal(0))
        elif isinstance(self.sequence, SymbolicArray):
            idx = self.index if isinstance(self.index, z3.ArithRef) else z3.IntVal(self.index)
            return z3.If(idx < self.sequence.length, self.sequence.length - idx, z3.IntVal(0))
        return z3.Int(f"{self._name}_remaining")

    def clone(self) -> SymbolicSequenceIterator:
        return SymbolicSequenceIterator(sequence=self.sequence, index=self.index, _name=self._name)

    @property
    def is_bounded(self) -> bool:
        return True


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
        pair = SymbolicTuple([idx_val, inner_result.value])
        new_enum = SymbolicEnumerate(
            inner=inner_result.iterator,
            counter=self.counter + 1 if isinstance(self.counter, int) else self.counter + 1,
            _name=self._name,
        )
        return IterationResult(
            value=pair, exhausted=False, constraint=inner_result.constraint, iterator=new_enum
        )

    def has_next(self) -> z3.BoolRef:
        return self.inner.has_next()

    def remaining_bound(self) -> int | z3.ArithRef:
        return self.inner.remaining_bound()

    def clone(self) -> SymbolicEnumerate:
        return SymbolicEnumerate(inner=self.inner.clone(), counter=self.counter, _name=self._name)

    @property
    def is_bounded(self) -> bool:
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
        values = []
        constraints = []
        new_iterators = []
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
            value=SymbolicTuple(values),
            exhausted=False,
            constraint=z3.And(*constraints) if constraints else z3.BoolVal(True),
            iterator=new_zip,
        )

    def has_next(self) -> z3.BoolRef:
        if not self.iterators:
            return z3.BoolVal(False)
        conditions = [it.has_next() for it in self.iterators]
        return z3.And(*conditions)

    def remaining_bound(self) -> int | z3.ArithRef:
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
        return SymbolicZip(iterators=[it.clone() for it in self.iterators], _name=self._name)

    @property
    def is_bounded(self) -> bool:
        return all(it.is_bounded for it in self.iterators)


@dataclass
class SymbolicMap(SymbolicIterator):
    """
    Symbolic map() iterator.
    Applies a function to each element.
    """

    func: Callable[[Any], Any]
    inner: SymbolicIterator
    _name: str = field(default="map")

    def __next__(self) -> IterationResult:
        inner_result = next(self.inner)
        if inner_result.exhausted:
            return IterationResult(
                value=None, exhausted=True, constraint=inner_result.constraint, iterator=self
            )
        try:
            mapped_value = self.func(inner_result.value)
        except Exception:
            mapped_value = inner_result.value
        new_map = SymbolicMap(func=self.func, inner=inner_result.iterator, _name=self._name)
        return IterationResult(
            value=mapped_value,
            exhausted=False,
            constraint=inner_result.constraint,
            iterator=new_map,
        )

    def has_next(self) -> z3.BoolRef:
        return self.inner.has_next()

    def remaining_bound(self) -> int | z3.ArithRef:
        return self.inner.remaining_bound()

    def clone(self) -> SymbolicMap:
        return SymbolicMap(func=self.func, inner=self.inner.clone(), _name=self._name)

    @property
    def is_bounded(self) -> bool:
        return self.inner.is_bounded


@dataclass
class SymbolicFilter(SymbolicIterator):
    """
    Symbolic filter() iterator.
    Yields only elements where predicate is true.
    Note: Filter can change the number of iterations.
    """

    predicate: Callable[[Any], bool]
    inner: SymbolicIterator
    _name: str = field(default="filter")
    _skip_count: int = field(default=0)

    def __next__(self) -> IterationResult:
        current_inner = self.inner
        constraints = []
        while True:
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
            except Exception:
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

    def has_next(self) -> z3.BoolRef:
        return self.inner.has_next()

    def remaining_bound(self) -> int | z3.ArithRef:
        return self.inner.remaining_bound()

    def clone(self) -> SymbolicFilter:
        return SymbolicFilter(predicate=self.predicate, inner=self.inner.clone(), _name=self._name)

    @property
    def is_bounded(self) -> bool:
        return self.inner.is_bounded


@dataclass
class SymbolicReversed(SymbolicIterator):
    """
    Symbolic reversed() iterator.
    Iterates over a sequence in reverse order.
    """

    sequence: list | tuple | str | SymbolicList
    index: int | z3.ArithRef = field(init=False)
    _name: str = field(default="reversed")

    def __post_init__(self):
        if isinstance(self.sequence, (list, tuple, str)):
            self.index = len(self.sequence) - 1
        elif isinstance(self.sequence, SymbolicArray):
            self.index = self.sequence.length - 1
        else:
            self.index = -1

    def __next__(self) -> IterationResult:
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
        if isinstance(self.index, int):
            return z3.BoolVal(self.index >= 0)
        else:
            return self.index >= 0

    def remaining_bound(self) -> int | z3.ArithRef:
        if isinstance(self.index, int):
            return max(0, self.index + 1)
        else:
            return z3.If(self.index >= 0, self.index + 1, z3.IntVal(0))

    def clone(self) -> SymbolicReversed:
        new_rev = SymbolicReversed(sequence=self.sequence, _name=self._name)
        new_rev.index = self.index
        return new_rev

    @property
    def is_bounded(self) -> bool:
        return True


@dataclass
class SymbolicDictKeysIterator(SymbolicIterator):
    """Iterator over dictionary keys."""

    keys: list
    index: int = field(default=0)
    _name: str = field(default="dict_keys")

    def __next__(self) -> IterationResult:
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
        return z3.BoolVal(self.index < len(self.keys))

    def remaining_bound(self) -> int:
        return max(0, len(self.keys) - self.index)

    def clone(self) -> SymbolicDictKeysIterator:
        return SymbolicDictKeysIterator(keys=self.keys, index=self.index, _name=self._name)

    @property
    def is_bounded(self) -> bool:
        return True


@dataclass
class SymbolicDictItemsIterator(SymbolicIterator):
    """Iterator over dictionary items (key, value pairs)."""

    items: list
    index: int = field(default=0)
    _name: str = field(default="dict_items")

    def __next__(self) -> IterationResult:
        if self.index >= len(self.items):
            return IterationResult(
                value=None, exhausted=True, constraint=z3.BoolVal(True), iterator=self
            )
        key, value = self.items[self.index]
        pair = SymbolicTuple([key, value])
        new_iter = SymbolicDictItemsIterator(
            items=self.items, index=self.index + 1, _name=self._name
        )
        return IterationResult(
            value=pair, exhausted=False, constraint=z3.BoolVal(True), iterator=new_iter
        )

    def has_next(self) -> z3.BoolRef:
        return z3.BoolVal(self.index < len(self.items))

    def remaining_bound(self) -> int:
        return max(0, len(self.items) - self.index)

    def clone(self) -> SymbolicDictItemsIterator:
        return SymbolicDictItemsIterator(items=self.items, index=self.index, _name=self._name)

    @property
    def is_bounded(self) -> bool:
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
    def from_range(cls, start: Any, stop: Any, step: Any = 1) -> LoopBounds:
        """Analyze bounds from range parameters."""
        sym_range = SymbolicRange(start=start, stop=stop, step=step)
        return cls.from_iterator(sym_range)

    def get_unroll_count(self, max_unroll: int = 100) -> int:
        """Get a safe number of iterations to unroll."""
        if isinstance(self.max_iterations, int):
            return min(self.max_iterations, max_unroll)
        return max_unroll


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
        return SymbolicDictKeysIterator(keys=list(iterable.keys()), _name=name)
    if isinstance(iterable, SymbolicArray):
        return SymbolicSequenceIterator(sequence=iterable, _name=name)
    try:
        return SymbolicSequenceIterator(sequence=list(iterable), _name=name)
    except Exception:
        raise TypeError(f"Cannot create iterator from {type(iterable)}")


def symbolic_range(*args, name: str = "range") -> SymbolicRange:
    """Create a symbolic range iterator."""
    return SymbolicRange.from_args(*args, name=name)


def symbolic_enumerate(iterable: Any, start: int = 0, name: str = "enumerate") -> SymbolicEnumerate:
    """Create a symbolic enumerate iterator."""
    inner = create_iterator(iterable, f"{name}_inner")
    return SymbolicEnumerate(inner=inner, counter=start, _name=name)


def symbolic_zip(*iterables, name: str = "zip") -> SymbolicZip:
    """Create a symbolic zip iterator."""
    iterators = [create_iterator(it, f"{name}_{i}") for i, it in enumerate(iterables)]
    return SymbolicZip(iterators=iterators, _name=name)


def symbolic_map(func: Callable, iterable: Any, name: str = "map") -> SymbolicMap:
    """Create a symbolic map iterator."""
    inner = create_iterator(iterable, f"{name}_inner")
    return SymbolicMap(func=func, inner=inner, _name=name)


def symbolic_filter(predicate: Callable, iterable: Any, name: str = "filter") -> SymbolicFilter:
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
    values = []
    constraints = []
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
