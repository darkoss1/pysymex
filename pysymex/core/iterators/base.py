# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Iterator base types, ABC, and core iterators: Range and Sequence."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto

import z3

logger = logging.getLogger(__name__)

from pysymex.core.memory import SymbolicArray
from pysymex.core.types import SymbolicInt, SymbolicList


class IteratorState(Enum):
    """State of a symbolic iterator."""

    ACTIVE = auto()
    EXHAUSTED = auto()
    UNKNOWN = auto()


@dataclass
class IterationResult:
    """Result of calling next() on an iterator."""

    value: object
    exhausted: bool
    constraint: z3.BoolRef
    iterator: SymbolicIterator

    @property
    def has_value(self) -> bool:
        """Property returning the has_value."""
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
        """Return an iterator over the container."""
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

    def __post_init__(self) -> None:
        """Post init."""
        self.current = self.start

    @classmethod
    def from_args(cls, *args: int | z3.ArithRef, name: str = "range") -> SymbolicRange:
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
        """Return the next item from the iterator."""
        has_next_constraint = self.has_next()
        value = self.current
        if isinstance(value, int):
            result_value = SymbolicInt(z3.IntVal(value))
        else:
            result_value = SymbolicInt(value)
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
            (isinstance(self.current, int) or z3.is_int_value(self.current))
            and (isinstance(self.stop, int) or z3.is_int_value(self.stop))
            and (isinstance(self.step, int) or z3.is_int_value(self.step))
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
        """Property returning the is_bounded."""
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

    sequence: list[object] | tuple[object, ...] | str | SymbolicList | SymbolicArray
    index: int | z3.ArithRef = field(default=0)
    _name: str = field(default="iter")

    def __post_init__(self) -> None:
        if isinstance(self.index, SymbolicInt):
            self.index = self.index.value

    def __next__(self) -> IterationResult:
        """Return the next item from the iterator."""
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
        new_iter.index = new_iter.index + 1
        return IterationResult(
            value=value, exhausted=exhausted, constraint=has_next_constraint, iterator=new_iter
        )

    def has_next(self) -> z3.BoolRef:
        """Has next."""
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
        """Remaining bound."""
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
        """Property returning the is_bounded."""
        return True

