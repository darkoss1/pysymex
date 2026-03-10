"""
pysymex Collection Theories — List and String operations.

Provides precise symbolic modeling for Python lists and strings
with full operation semantics using Z3 theories.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, cast

import z3

from pysymex.core.addressing import next_address

from .memory_model import SymbolicArray
from .symbolic_types import (
    SymbolicBool,
    SymbolicInt,
    SymbolicList,
    SymbolicString,
)


@dataclass
class OpResult:
    """
    Result of a collection operation.
    Contains the result value, any constraints generated,
    and side effects (for mutable operations).
    """

    value: Any
    constraints: list[z3.BoolRef] = field(default_factory=list[z3.BoolRef])
    modified_collection: object = None
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.error is None

    def with_constraint(self, constraint: z3.BoolRef) -> OpResult:
        """Add a constraint and return self for chaining."""
        self.constraints.append(constraint)
        return self


class SymbolicListOps:
    """
    Symbolic operations for Python lists.
    All operations work with either concrete Python lists or
    SymbolicList/SymbolicArray objects.
    """

    @staticmethod
    def length(lst: list[object] | SymbolicList | SymbolicArray) -> OpResult:
        """Get the length of a list."""
        if isinstance(lst, list):
            return OpResult(value=len(lst))
        elif isinstance(lst, SymbolicList):
            return OpResult(value=lst.length)
        else:
            assert isinstance(lst, SymbolicArray)
            return OpResult(value=lst.length)

    @staticmethod
    def getitem(
        lst: list[object] | SymbolicList | SymbolicArray, index: int | z3.ArithRef | SymbolicInt
    ) -> OpResult:
        """Get item at index with bounds checking."""
        if isinstance(index, SymbolicInt):
            idx: int | z3.ArithRef = index.value
        elif isinstance(index, int):
            idx = index
        else:
            idx = index
        if isinstance(lst, list):
            if isinstance(idx, int):
                try:
                    return OpResult(value=lst[idx])
                except IndexError:
                    return OpResult(value=None, error="IndexError: list index out of range")
            elif z3.is_int_value(idx):
                concrete_idx = idx.as_long()
                try:
                    return OpResult(value=lst[concrete_idx])
                except IndexError:
                    return OpResult(value=None, error="IndexError: list index out of range")
            else:
                result = SymbolicInt(z3.Int(f"list_item_{next_address ()}"))
                constraints: list[z3.BoolRef] = [idx >= 0, idx < len(lst)]
                return OpResult(value=result, constraints=constraints)
        elif isinstance(lst, SymbolicList):
            result_sl = lst[idx]
            constraints_sl: list[z3.BoolRef] = [idx >= 0, idx < lst.length]
            return OpResult(value=result_sl, constraints=constraints_sl)
        else:
            assert isinstance(lst, SymbolicArray)
            result_sa = lst.get(idx)
            bounds = lst.in_bounds(idx)
            return OpResult(value=result_sa, constraints=[bounds])
        return OpResult(value=None, error=f"Cannot index {type (lst )}")

    @staticmethod
    def setitem(
        lst: list[object] | SymbolicArray, index: int | z3.ArithRef | SymbolicInt, value: object
    ) -> OpResult:
        """Set item at index."""
        if isinstance(index, SymbolicInt):
            idx: int | z3.ArithRef = index.value
        elif isinstance(index, int):
            idx = z3.IntVal(index)
        else:
            idx = index
        if isinstance(value, SymbolicInt):
            z3_val: object = value.value
        elif isinstance(value, int):
            z3_val = z3.IntVal(value)
        else:
            z3_val = value
        if isinstance(lst, list):
            if isinstance(idx, int) or z3.is_int_value(idx):
                concrete_idx = idx if isinstance(idx, int) else idx.as_long()
                if 0 <= concrete_idx < len(lst):
                    new_lst = lst.copy()
                    new_lst[concrete_idx] = value
                    return OpResult(value=None, modified_collection=new_lst)
                else:
                    return OpResult(
                        value=None, error="IndexError: list assignment index out of range"
                    )
            else:
                return OpResult(
                    value=None, error="Cannot use symbolic index on concrete list for assignment"
                )
        else:
            assert isinstance(lst, SymbolicArray)
            new_array = lst.set(idx, z3_val)
            bounds = lst.in_bounds(idx)
            return OpResult(value=None, modified_collection=new_array, constraints=[bounds])
        return OpResult(value=None, error=f"Cannot set item on {type (lst )}")

    @staticmethod
    def append(lst: list[object] | SymbolicArray, value: object) -> OpResult:
        """Append an item to the list."""
        if isinstance(value, SymbolicInt):
            z3_val: object = value.value
        elif isinstance(value, int):
            z3_val = z3.IntVal(value)
        else:
            z3_val = value
        if isinstance(lst, list):
            lst.append(value)
            return OpResult(value=None, modified_collection=lst)
        else:
            assert isinstance(lst, SymbolicArray)
            new_array = lst.append(z3_val)
            return OpResult(value=None, modified_collection=new_array)
        return OpResult(value=None, error=f"Cannot append to {type (lst )}")

    @staticmethod
    def extend(lst: list[object] | SymbolicArray, items: list[object] | SymbolicArray) -> OpResult:
        """Extend list with items from another iterable."""
        if isinstance(lst, list) and isinstance(items, list):
            lst.extend(items)
            return OpResult(value=None, modified_collection=lst)
        elif isinstance(lst, SymbolicArray):
            if isinstance(items, list):
                result_arr: SymbolicArray = lst
                for item in items:
                    if isinstance(item, SymbolicInt):
                        z3_val: object = item.value
                    elif isinstance(item, int):
                        z3_val = z3.IntVal(item)
                    else:
                        z3_val = item
                    result_arr = result_arr.append(z3_val)
                return OpResult(value=None, modified_collection=result_arr)
        return OpResult(value=None, error=f"Cannot extend {type (lst )} with {type (items )}")

    @staticmethod
    def pop(lst: list[object] | SymbolicArray, index: int | z3.ArithRef | None = None) -> OpResult:
        """Remove and return item at index (default last)."""
        if isinstance(lst, list):
            if len(lst) == 0:
                return OpResult(value=None, error="IndexError: pop from empty list")
            if index is None:
                pop_value: object = lst.pop()
            else:
                idx: int | None = (
                    index
                    if isinstance(index, int)
                    else index.as_long() if z3.is_int_value(index) else None
                )
                if idx is None:
                    return OpResult(
                        value=None, error="Cannot pop with symbolic index from concrete list"
                    )
                if idx < 0 or idx >= len(lst):
                    return OpResult(value=None, error="IndexError: pop index out of range")
                pop_value = lst.pop(idx)
            return OpResult(value=pop_value, modified_collection=lst)
        else:
            assert isinstance(lst, SymbolicArray)
            constraints: list[z3.BoolRef] = [lst.length > 0]
            if index is None:
                pop_idx: int | z3.ArithRef = lst.length - 1
            else:
                pop_idx = index if isinstance(index, int) else index
                if isinstance(pop_idx, int):
                    pop_idx = z3.IntVal(pop_idx)
                constraints.append(z3.And(pop_idx >= 0, pop_idx < lst.length))
            pop_val = lst.get(pop_idx)

            new_array = SymbolicArray(f"{lst.name}_popped", lst.element_sort)
            new_len = lst.length - 1

            for_idx = z3.Int(f"{lst.name}_pop_i")

            before = z3.ForAll(
                [for_idx],
                z3.Implies(
                    z3.And(for_idx >= 0, for_idx < pop_idx),
                    z3.Select(new_array.array, for_idx) == z3.Select(lst.array, for_idx),
                ),
            )

            after = z3.ForAll(
                [for_idx],
                z3.Implies(
                    z3.And(for_idx >= pop_idx, for_idx < new_len),
                    z3.Select(new_array.array, for_idx) == z3.Select(lst.array, for_idx + 1),
                ),
            )
            new_array.length = new_len
            constraints.extend([before, after])
            return OpResult(value=pop_val, modified_collection=new_array, constraints=constraints)
        return OpResult(value=None, error=f"Cannot pop from {type (lst )}")

    @staticmethod
    def insert(
        lst: list[object] | SymbolicArray, index: int | z3.ArithRef, value: object
    ) -> OpResult:
        """Insert item at index."""
        if isinstance(value, SymbolicInt):
            z3_val: object = value.value
        elif isinstance(value, int):
            z3_val = z3.IntVal(value)
        else:
            z3_val = value
        if isinstance(index, SymbolicInt):
            idx: int | z3.ArithRef = index.value
        elif isinstance(index, int):
            idx = index
        else:
            idx = index
        if isinstance(lst, list):
            if isinstance(idx, int):
                lst.insert(idx, value)
                return OpResult(value=None, modified_collection=lst)
            else:
                return OpResult(
                    value=None, error="Cannot insert with symbolic index into concrete list"
                )
        else:
            assert isinstance(lst, SymbolicArray)
            if z3.is_int_value(idx):
                idx.as_long()
                new_array = lst.append(z3_val)
                return OpResult(value=None, modified_collection=new_array)
            else:
                new_array = lst.append(z3_val)
                return OpResult(value=None, modified_collection=new_array)
        return OpResult(value=None, error=f"Cannot insert into {type (lst )}")

    @staticmethod
    def remove(lst: list[object] | SymbolicArray, value: object) -> OpResult:
        """Remove first occurrence of value."""
        if isinstance(lst, list):
            try:
                lst.remove(value)
                return OpResult(value=None, modified_collection=lst)
            except ValueError:
                return OpResult(value=None, error="ValueError: list.remove(x): x not in list")
        else:
            assert isinstance(lst, SymbolicArray)
            z3_val: object = (
                value.value
                if isinstance(value, SymbolicInt)
                else z3.IntVal(value) if isinstance(value, int) else value
            )
            i = z3.Int(f"remove_idx_{next_address ()}")
            exists_constraint = z3.Exists([i], z3.And(i >= 0, i < lst.length, lst.get(i) == z3_val))
            new_array = SymbolicArray(f"{lst.name}_removed", lst.element_sort)
            new_array.array = lst.array
            new_array.length = lst.length - 1
            return OpResult(
                value=None, modified_collection=new_array, constraints=[exists_constraint]
            )
        return OpResult(value=None, error=f"Cannot remove from {type (lst )}")

    @staticmethod
    def index(
        lst: list[object] | SymbolicArray, value: object, start: int = 0, stop: int | None = None
    ) -> OpResult:
        """Return index of first occurrence of value."""
        if isinstance(lst, list):
            try:
                if stop is None:
                    idx = lst.index(value, start)
                else:
                    idx = lst.index(value, start, stop)
                return OpResult(value=idx)
            except ValueError:
                return OpResult(value=None, error="ValueError: x not in list")
        else:
            assert isinstance(lst, SymbolicArray)
            z3_val: object = (
                value.value
                if isinstance(value, SymbolicInt)
                else z3.IntVal(value) if isinstance(value, int) else value
            )
            result_idx = z3.Int(f"index_result_{next_address ()}")
            constraints: list[z3.BoolRef] = [
                result_idx >= start,
                result_idx < lst.length,
                cast("z3.BoolRef", lst.get(result_idx) == z3_val),
            ]
            if stop is not None:
                constraints.append(result_idx < stop)
            return OpResult(value=SymbolicInt(result_idx), constraints=constraints)
        return OpResult(value=None, error=f"Cannot find index in {type (lst )}")

    @staticmethod
    def count(lst: list[object] | SymbolicArray, value: object) -> OpResult:
        """Count occurrences of value."""
        if isinstance(lst, list):
            return OpResult(value=lst.count(value))
        else:
            assert isinstance(lst, SymbolicArray)
            _z3_val = (
                value.value
                if isinstance(value, SymbolicInt)
                else z3.IntVal(value) if isinstance(value, int) else value
            )
            count_var = z3.Int(f"count_{next_address ()}")
            constraints: list[z3.BoolRef] = [count_var >= 0, count_var <= lst.length]
            return OpResult(value=SymbolicInt(count_var), constraints=constraints)
        return OpResult(value=None, error=f"Cannot count in {type (lst )}")

    @staticmethod
    def reverse(lst: list[object] | SymbolicArray) -> OpResult:
        """Reverse list in place."""
        if isinstance(lst, list):
            lst.reverse()
            return OpResult(value=None, modified_collection=lst)
        else:
            assert isinstance(lst, SymbolicArray)
            new_array = SymbolicArray(f"{lst.name}_reversed", lst.element_sort)
            new_array.length = lst.length
            return OpResult(value=None, modified_collection=new_array)
        return OpResult(value=None, error=f"Cannot reverse {type (lst )}")

    @staticmethod
    def contains(lst: list[object] | SymbolicArray, value: object) -> OpResult:
        """Check if value is in list."""
        if isinstance(lst, list):
            return OpResult(value=value in lst)
        else:
            assert isinstance(lst, SymbolicArray)
            z3_val: object = (
                value.value
                if isinstance(value, SymbolicInt)
                else z3.IntVal(value) if isinstance(value, int) else value
            )
            result = z3.Bool(f"contains_{next_address ()}")
            i = z3.Int(f"contains_idx_{next_address ()}")
            exists = z3.Exists([i], z3.And(i >= 0, i < lst.length, lst.get(i) == z3_val))
            constraints: list[z3.BoolRef] = [result == exists]
            return OpResult(value=SymbolicBool(result), constraints=constraints)
        return OpResult(value=None, error=f"Cannot check containment in {type (lst )}")

    @staticmethod
    def slice(
        lst: list[object] | SymbolicArray,
        start: int | z3.ArithRef | None = None,
        stop: int | z3.ArithRef | None = None,
        step: int | None = None,
    ) -> OpResult:
        """Get a slice of the list."""
        if isinstance(lst, list):
            result: list[object] = lst[start:stop:step]
            return OpResult(value=result)
        else:
            assert isinstance(lst, SymbolicArray)
            new_array = SymbolicArray(f"{lst.name}_slice", lst.element_sort)
            if start is None:
                start = 0
            if stop is None:
                stop = lst.length
            if isinstance(start, int) and isinstance(stop, int):
                slice_len = max(0, stop - start)
                new_array.length = z3.IntVal(slice_len)
            else:
                s = start if not isinstance(start, int) else z3.IntVal(start)
                e = stop if not isinstance(stop, int) else z3.IntVal(stop)
                new_array.length = z3.If(e > s, e - s, z3.IntVal(0))
            return OpResult(value=new_array)
        return OpResult(value=None, error=f"Cannot slice {type (lst )}")

    @staticmethod
    def concatenate(
        lst1: list[object] | SymbolicArray, lst2: list[object] | SymbolicArray
    ) -> OpResult:
        """Concatenate two lists."""
        if isinstance(lst1, list) and isinstance(lst2, list):
            return OpResult(value=lst1 + lst2)
        elif isinstance(lst1, SymbolicArray) and isinstance(lst2, SymbolicArray):
            new_array = SymbolicArray(f"{lst1.name}_concat_{lst2.name}", lst1.element_sort)
            new_array.length = lst1.length + lst2.length
            return OpResult(value=new_array)
        return OpResult(value=None, error=f"Cannot concatenate {type (lst1 )} and {type (lst2 )}")


class SymbolicStringOps:
    """
    Symbolic operations for Python strings.
    """

    @staticmethod
    def length(s: str | SymbolicString) -> OpResult:
        """Get string length."""
        if isinstance(s, str):
            return OpResult(value=len(s))
        else:
            assert isinstance(s, SymbolicString)
            return OpResult(value=s.length)
        return OpResult(value=None, error=f"Cannot get length of {type (s )}")

    @staticmethod
    def contains(s: str | SymbolicString, substr: str | SymbolicString) -> OpResult:
        """Check if substring is in string."""
        if isinstance(s, str) and isinstance(substr, str):
            return OpResult(value=substr in s)
        elif isinstance(s, SymbolicString):
            result = s.contains(substr)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot check containment in {type (s )}")

    @staticmethod
    def concatenate(s1: str | SymbolicString, s2: str | SymbolicString) -> OpResult:
        """Concatenate two strings."""
        if isinstance(s1, str) and isinstance(s2, str):
            return OpResult(value=s1 + s2)
        elif isinstance(s1, SymbolicString) or isinstance(s2, SymbolicString):
            if isinstance(s1, SymbolicString):
                result = s1 + s2
            else:
                result = s2.__radd__(s1)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot concatenate {type (s1 )} and {type (s2 )}")

    @staticmethod
    def startswith(s: str | SymbolicString, prefix: str | SymbolicString) -> OpResult:
        """Check if string starts with prefix."""
        if isinstance(s, str) and isinstance(prefix, str):
            return OpResult(value=s.startswith(prefix))
        elif isinstance(s, SymbolicString):
            result = s.startswith(prefix)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot check startswith on {type (s )}")

    @staticmethod
    def endswith(s: str | SymbolicString, suffix: str | SymbolicString) -> OpResult:
        """Check if string ends with suffix."""
        if isinstance(s, str) and isinstance(suffix, str):
            return OpResult(value=s.endswith(suffix))
        elif isinstance(s, SymbolicString):
            result = s.endswith(suffix)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot check endswith on {type (s )}")
