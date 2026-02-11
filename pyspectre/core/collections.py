"""
PySpectre Collection Theories - Phase 15
Provides precise symbolic modeling for Python's built-in collections
with full operation semantics. Uses Z3 theories for verification.
Collections:
- SymbolicListOps: List operations (append, extend, pop, etc.)
- SymbolicDictOps: Dict operations (get, set, update, etc.)
- SymbolicSetOps: Set operations (add, union, intersection, etc.)
- SymbolicTupleOps: Tuple operations (indexing, slicing, etc.)
Each operation is modeled to produce:
1. The result value (possibly symbolic)
2. Constraints that must hold for the operation
3. The mutated collection (for mutable types)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
import z3
from .memory_model import SymbolicArray, SymbolicMap
from .symbolic_types import (
    SymbolicBool,
    SymbolicDict,
    SymbolicInt,
    SymbolicList,
    SymbolicSet,
    SymbolicString,
    SymbolicTuple,
)


@dataclass
class OpResult:
    """
    Result of a collection operation.
    Contains the result value, any constraints generated,
    and side effects (for mutable operations).
    """

    value: Any
    constraints: list[z3.BoolRef] = field(default_factory=list)
    modified_collection: Any = None
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
    def length(lst: list | SymbolicList | SymbolicArray) -> OpResult:
        """Get the length of a list."""
        if isinstance(lst, list):
            return OpResult(value=len(lst))
        elif isinstance(lst, SymbolicList):
            return OpResult(value=lst.length)
        elif isinstance(lst, SymbolicArray):
            return OpResult(value=lst.length)
        else:
            return OpResult(value=None, error=f"Cannot get length of {type(lst)}")

    @staticmethod
    def getitem(
        lst: list | SymbolicList | SymbolicArray, index: int | z3.ArithRef | SymbolicInt
    ) -> OpResult:
        """Get item at index with bounds checking."""
        if isinstance(index, SymbolicInt):
            idx = index.value
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
                result = SymbolicInt(z3.Int(f"list_item_{id(lst)}"))
                constraints = [idx >= 0, idx < len(lst)]
                return OpResult(value=result, constraints=constraints)
        elif isinstance(lst, SymbolicList):
            result = lst[idx]
            constraints = [idx >= 0, idx < lst.length]
            return OpResult(value=result, constraints=constraints)
        elif isinstance(lst, SymbolicArray):
            result = lst.get(idx)
            bounds = lst.in_bounds(idx)
            return OpResult(value=result, constraints=[bounds])
        return OpResult(value=None, error=f"Cannot index {type(lst)}")

    @staticmethod
    def setitem(
        lst: list | SymbolicArray, index: int | z3.ArithRef | SymbolicInt, value: Any
    ) -> OpResult:
        """Set item at index."""
        if isinstance(index, SymbolicInt):
            idx = index.value
        elif isinstance(index, int):
            idx = z3.IntVal(index)
        else:
            idx = index
        if isinstance(value, SymbolicInt):
            z3_val = value.value
        elif isinstance(value, int):
            z3_val = z3.IntVal(value)
        else:
            z3_val = value
        if isinstance(lst, list):
            if isinstance(idx, int) or z3.is_int_value(idx):
                concrete_idx = idx if isinstance(idx, int) else idx.as_long()
                if 0 <= concrete_idx < len(lst):
                    lst[concrete_idx] = value
                    return OpResult(value=None, modified_collection=lst)
                else:
                    return OpResult(
                        value=None, error="IndexError: list assignment index out of range"
                    )
            else:
                return OpResult(
                    value=None, error="Cannot use symbolic index on concrete list for assignment"
                )
        elif isinstance(lst, SymbolicArray):
            new_array = lst.set(idx, z3_val)
            bounds = lst.in_bounds(idx)
            return OpResult(value=None, modified_collection=new_array, constraints=[bounds])
        return OpResult(value=None, error=f"Cannot set item on {type(lst)}")

    @staticmethod
    def append(lst: list | SymbolicArray, value: Any) -> OpResult:
        """Append an item to the list."""
        if isinstance(value, SymbolicInt):
            z3_val = value.value
        elif isinstance(value, int):
            z3_val = z3.IntVal(value)
        else:
            z3_val = value
        if isinstance(lst, list):
            lst.append(value)
            return OpResult(value=None, modified_collection=lst)
        elif isinstance(lst, SymbolicArray):
            new_array = lst.append(z3_val)
            return OpResult(value=None, modified_collection=new_array)
        return OpResult(value=None, error=f"Cannot append to {type(lst)}")

    @staticmethod
    def extend(lst: list | SymbolicArray, items: list | SymbolicArray) -> OpResult:
        """Extend list with items from another iterable."""
        if isinstance(lst, list) and isinstance(items, list):
            lst.extend(items)
            return OpResult(value=None, modified_collection=lst)
        elif isinstance(lst, SymbolicArray):
            if isinstance(items, list):
                result = lst
                for item in items:
                    if isinstance(item, SymbolicInt):
                        z3_val = item.value
                    elif isinstance(item, int):
                        z3_val = z3.IntVal(item)
                    else:
                        z3_val = item
                    result = result.append(z3_val)
                return OpResult(value=None, modified_collection=result)
        return OpResult(value=None, error=f"Cannot extend {type(lst)} with {type(items)}")

    @staticmethod
    def pop(lst: list | SymbolicArray, index: int | z3.ArithRef | None = None) -> OpResult:
        """Remove and return item at index (default last)."""
        if isinstance(lst, list):
            if len(lst) == 0:
                return OpResult(value=None, error="IndexError: pop from empty list")
            if index is None:
                value = lst.pop()
            else:
                idx = (
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
                value = lst.pop(idx)
            return OpResult(value=value, modified_collection=lst)
        elif isinstance(lst, SymbolicArray):
            constraints = [lst.length > 0]
            if index is None:
                idx = lst.length - 1
            else:
                idx = index if isinstance(index, int) else index
                if isinstance(idx, int):
                    idx = z3.IntVal(idx)
                constraints.append(z3.And(idx >= 0, idx < lst.length))
            value = lst.get(idx)
            new_array = SymbolicArray(f"{lst.name}_popped", lst.element_sort)
            new_array._array = lst._array
            new_array._length = lst._length - 1
            return OpResult(value=value, modified_collection=new_array, constraints=constraints)
        return OpResult(value=None, error=f"Cannot pop from {type(lst)}")

    @staticmethod
    def insert(lst: list | SymbolicArray, index: int | z3.ArithRef, value: Any) -> OpResult:
        """Insert item at index."""
        if isinstance(value, SymbolicInt):
            z3_val = value.value
        elif isinstance(value, int):
            z3_val = z3.IntVal(value)
        else:
            z3_val = value
        if isinstance(index, SymbolicInt):
            idx = index.value
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
        elif isinstance(lst, SymbolicArray):
            if z3.is_int_value(idx):
                concrete_idx = idx.as_long()
                new_array = lst.append(z3_val)
                return OpResult(value=None, modified_collection=new_array)
            else:
                new_array = lst.append(z3_val)
                return OpResult(value=None, modified_collection=new_array)
        return OpResult(value=None, error=f"Cannot insert into {type(lst)}")

    @staticmethod
    def remove(lst: list | SymbolicArray, value: Any) -> OpResult:
        """Remove first occurrence of value."""
        if isinstance(lst, list):
            try:
                lst.remove(value)
                return OpResult(value=None, modified_collection=lst)
            except ValueError:
                return OpResult(value=None, error="ValueError: list.remove(x): x not in list")
        elif isinstance(lst, SymbolicArray):
            z3_val = (
                value.value
                if isinstance(value, SymbolicInt)
                else z3.IntVal(value) if isinstance(value, int) else value
            )
            i = z3.Int(f"remove_idx_{id(lst)}")
            exists_constraint = z3.Exists([i], z3.And(i >= 0, i < lst.length, lst.get(i) == z3_val))
            new_array = SymbolicArray(f"{lst.name}_removed", lst.element_sort)
            new_array._array = lst._array
            new_array._length = lst._length - 1
            return OpResult(
                value=None, modified_collection=new_array, constraints=[exists_constraint]
            )
        return OpResult(value=None, error=f"Cannot remove from {type(lst)}")

    @staticmethod
    def index(
        lst: list | SymbolicArray, value: Any, start: int = 0, stop: int | None = None
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
        elif isinstance(lst, SymbolicArray):
            z3_val = (
                value.value
                if isinstance(value, SymbolicInt)
                else z3.IntVal(value) if isinstance(value, int) else value
            )
            result_idx = z3.Int(f"index_result_{id(lst)}")
            constraints = [
                result_idx >= start,
                result_idx < lst.length,
                lst.get(result_idx) == z3_val,
            ]
            if stop is not None:
                constraints.append(result_idx < stop)
            return OpResult(value=SymbolicInt(result_idx), constraints=constraints)
        return OpResult(value=None, error=f"Cannot find index in {type(lst)}")

    @staticmethod
    def count(lst: list | SymbolicArray, value: Any) -> OpResult:
        """Count occurrences of value."""
        if isinstance(lst, list):
            return OpResult(value=lst.count(value))
        elif isinstance(lst, SymbolicArray):
            z3_val = (
                value.value
                if isinstance(value, SymbolicInt)
                else z3.IntVal(value) if isinstance(value, int) else value
            )
            count_var = z3.Int(f"count_{id(lst)}")
            constraints = [count_var >= 0, count_var <= lst.length]
            return OpResult(value=SymbolicInt(count_var), constraints=constraints)
        return OpResult(value=None, error=f"Cannot count in {type(lst)}")

    @staticmethod
    def reverse(lst: list | SymbolicArray) -> OpResult:
        """Reverse list in place."""
        if isinstance(lst, list):
            lst.reverse()
            return OpResult(value=None, modified_collection=lst)
        elif isinstance(lst, SymbolicArray):
            new_array = SymbolicArray(f"{lst.name}_reversed", lst.element_sort)
            new_array._length = lst._length
            return OpResult(value=None, modified_collection=new_array)
        return OpResult(value=None, error=f"Cannot reverse {type(lst)}")

    @staticmethod
    def contains(lst: list | SymbolicArray, value: Any) -> OpResult:
        """Check if value is in list."""
        if isinstance(lst, list):
            return OpResult(value=value in lst)
        elif isinstance(lst, SymbolicArray):
            z3_val = (
                value.value
                if isinstance(value, SymbolicInt)
                else z3.IntVal(value) if isinstance(value, int) else value
            )
            result = z3.Bool(f"contains_{id(lst)}_{id(value)}")
            i = z3.Int(f"contains_idx_{id(lst)}")
            exists = z3.Exists([i], z3.And(i >= 0, i < lst.length, lst.get(i) == z3_val))
            constraints = [result == exists]
            return OpResult(value=SymbolicBool(result), constraints=constraints)
        return OpResult(value=None, error=f"Cannot check containment in {type(lst)}")

    @staticmethod
    def slice(
        lst: list | SymbolicArray,
        start: int | z3.ArithRef | None = None,
        stop: int | z3.ArithRef | None = None,
        step: int | None = None,
    ) -> OpResult:
        """Get a slice of the list."""
        if isinstance(lst, list):
            result = lst[start:stop:step]
            return OpResult(value=result)
        elif isinstance(lst, SymbolicArray):
            new_array = SymbolicArray(f"{lst.name}_slice", lst.element_sort)
            if start is None:
                start = 0
            if stop is None:
                stop = lst.length
            if isinstance(start, int) and isinstance(stop, int):
                slice_len = max(0, stop - start)
                new_array._length = z3.IntVal(slice_len)
            else:
                s = start if not isinstance(start, int) else z3.IntVal(start)
                e = stop if not isinstance(stop, int) else z3.IntVal(stop)
                new_array._length = z3.If(e > s, e - s, z3.IntVal(0))
            return OpResult(value=new_array)
        return OpResult(value=None, error=f"Cannot slice {type(lst)}")

    @staticmethod
    def concatenate(lst1: list | SymbolicArray, lst2: list | SymbolicArray) -> OpResult:
        """Concatenate two lists."""
        if isinstance(lst1, list) and isinstance(lst2, list):
            return OpResult(value=lst1 + lst2)
        elif isinstance(lst1, SymbolicArray) and isinstance(lst2, SymbolicArray):
            new_array = SymbolicArray(f"{lst1.name}_concat_{lst2.name}", lst1.element_sort)
            new_array._length = lst1.length + lst2.length
            return OpResult(value=new_array)
        return OpResult(value=None, error=f"Cannot concatenate {type(lst1)} and {type(lst2)}")


class SymbolicDictOps:
    """
    Symbolic operations for Python dicts.
    """

    @staticmethod
    def length(d: dict | SymbolicDict | SymbolicMap) -> OpResult:
        """Get number of keys in dict."""
        if isinstance(d, dict):
            return OpResult(value=len(d))
        elif isinstance(d, SymbolicDict):
            return OpResult(value=d.length)
        elif isinstance(d, SymbolicMap):
            length_var = z3.Int(f"dict_len_{id(d)}")
            return OpResult(value=SymbolicInt(length_var), constraints=[length_var >= 0])
        return OpResult(value=None, error=f"Cannot get length of {type(d)}")

    @staticmethod
    def getitem(d: dict | SymbolicDict | SymbolicMap, key: Any) -> OpResult:
        """Get value for key."""
        if isinstance(d, dict):
            if key in d:
                return OpResult(value=d[key])
            else:
                return OpResult(value=None, error="KeyError")
        elif isinstance(d, SymbolicDict):
            result = d[key]
            has_key = d.contains(key)
            return OpResult(value=result, constraints=[has_key])
        elif isinstance(d, SymbolicMap):
            z3_key = (
                key.value
                if isinstance(key, SymbolicInt)
                else z3.IntVal(key) if isinstance(key, int) else key
            )
            result = d.get(z3_key)
            has_key = d.contains(z3_key)
            return OpResult(value=result, constraints=[has_key])
        return OpResult(value=None, error=f"Cannot get item from {type(d)}")

    @staticmethod
    def setitem(d: dict | SymbolicMap, key: Any, value: Any) -> OpResult:
        """Set value for key."""
        if isinstance(d, dict):
            d[key] = value
            return OpResult(value=None, modified_collection=d)
        elif isinstance(d, SymbolicMap):
            z3_key = (
                key.value
                if isinstance(key, SymbolicInt)
                else z3.IntVal(key) if isinstance(key, int) else key
            )
            z3_val = (
                value.value
                if isinstance(value, SymbolicInt)
                else z3.IntVal(value) if isinstance(value, int) else value
            )
            new_map = d.set(z3_key, z3_val)
            return OpResult(value=None, modified_collection=new_map)
        return OpResult(value=None, error=f"Cannot set item on {type(d)}")

    @staticmethod
    def delitem(d: dict | SymbolicMap, key: Any) -> OpResult:
        """Delete key from dict."""
        if isinstance(d, dict):
            if key in d:
                del d[key]
                return OpResult(value=None, modified_collection=d)
            else:
                return OpResult(value=None, error="KeyError")
        elif isinstance(d, SymbolicMap):
            z3_key = (
                key.value
                if isinstance(key, SymbolicInt)
                else z3.IntVal(key) if isinstance(key, int) else key
            )
            has_key = d.contains(z3_key)
            new_map = d.delete(z3_key)
            return OpResult(value=None, modified_collection=new_map, constraints=[has_key])
        return OpResult(value=None, error=f"Cannot delete from {type(d)}")

    @staticmethod
    def get(d: dict | SymbolicMap, key: Any, default: Any = None) -> OpResult:
        """Get value for key with default."""
        if isinstance(d, dict):
            return OpResult(value=d.get(key, default))
        elif isinstance(d, SymbolicMap):
            z3_key = (
                key.value
                if isinstance(key, SymbolicInt)
                else z3.IntVal(key) if isinstance(key, int) else key
            )
            z3_default = (
                default.value
                if isinstance(default, SymbolicInt)
                else z3.IntVal(default) if isinstance(default, int) else default
            )
            result = d.get(z3_key, z3_default)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot get from {type(d)}")

    @staticmethod
    def contains(d: dict | SymbolicMap, key: Any) -> OpResult:
        """Check if key is in dict."""
        if isinstance(d, dict):
            return OpResult(value=key in d)
        elif isinstance(d, SymbolicMap):
            z3_key = (
                key.value
                if isinstance(key, SymbolicInt)
                else z3.IntVal(key) if isinstance(key, int) else key
            )
            result = d.contains(z3_key)
            return OpResult(value=SymbolicBool(result))
        return OpResult(value=None, error=f"Cannot check containment in {type(d)}")

    @staticmethod
    def pop(d: dict | SymbolicMap, key: Any, default: Any = None) -> OpResult:
        """Remove and return value for key."""
        if isinstance(d, dict):
            if key in d:
                value = d.pop(key)
                return OpResult(value=value, modified_collection=d)
            elif default is not None:
                return OpResult(value=default, modified_collection=d)
            else:
                return OpResult(value=None, error="KeyError")
        elif isinstance(d, SymbolicMap):
            z3_key = (
                key.value
                if isinstance(key, SymbolicInt)
                else z3.IntVal(key) if isinstance(key, int) else key
            )
            z3_default = (
                default.value
                if isinstance(default, SymbolicInt)
                else (
                    z3.IntVal(default)
                    if isinstance(default, int) and default is not None
                    else default
                )
            )
            has_key = d.contains(z3_key)
            value = d.get(z3_key, z3_default) if z3_default is not None else d.get(z3_key)
            new_map = d.delete(z3_key)
            return OpResult(value=value, modified_collection=new_map)
        return OpResult(value=None, error=f"Cannot pop from {type(d)}")

    @staticmethod
    def setdefault(d: dict | SymbolicMap, key: Any, default: Any = None) -> OpResult:
        """Get value for key, setting default if not present."""
        if isinstance(d, dict):
            if key not in d:
                d[key] = default
            return OpResult(value=d[key], modified_collection=d)
        elif isinstance(d, SymbolicMap):
            z3_key = (
                key.value
                if isinstance(key, SymbolicInt)
                else z3.IntVal(key) if isinstance(key, int) else key
            )
            z3_default = (
                default.value
                if isinstance(default, SymbolicInt)
                else (
                    z3.IntVal(default)
                    if isinstance(default, int) and default is not None
                    else default
                )
            )
            has_key = d.contains(z3_key)
            existing_value = d.get(z3_key)
            new_map = z3.If(has_key, d, d.set(z3_key, z3_default))
            result = z3.If(has_key, existing_value, z3_default)
            final_map = d.set(z3_key, result)
            return OpResult(value=result, modified_collection=final_map)
        return OpResult(value=None, error=f"Cannot setdefault on {type(d)}")

    @staticmethod
    def update(d: dict | SymbolicMap, other: dict | SymbolicMap) -> OpResult:
        """Update dict with key-value pairs from other."""
        if isinstance(d, dict) and isinstance(other, dict):
            d.update(other)
            return OpResult(value=None, modified_collection=d)
        elif isinstance(d, SymbolicMap) and isinstance(other, dict):
            result = d
            for k, v in other.items():
                z3_key = (
                    k if isinstance(k, z3.ExprRef) else z3.IntVal(k) if isinstance(k, int) else k
                )
                z3_val = (
                    v if isinstance(v, z3.ExprRef) else z3.IntVal(v) if isinstance(v, int) else v
                )
                result = result.set(z3_key, z3_val)
            return OpResult(value=None, modified_collection=result)
        return OpResult(value=None, error=f"Cannot update {type(d)} with {type(other)}")

    @staticmethod
    def keys(d: dict | SymbolicMap) -> OpResult:
        """Get dict keys."""
        if isinstance(d, dict):
            return OpResult(value=list(d.keys()))
        return OpResult(value=None, error="Cannot enumerate keys of symbolic map")

    @staticmethod
    def values(d: dict | SymbolicMap) -> OpResult:
        """Get dict values."""
        if isinstance(d, dict):
            return OpResult(value=list(d.values()))
        return OpResult(value=None, error="Cannot enumerate values of symbolic map")

    @staticmethod
    def items(d: dict | SymbolicMap) -> OpResult:
        """Get dict items."""
        if isinstance(d, dict):
            return OpResult(value=list(d.items()))
        return OpResult(value=None, error="Cannot enumerate items of symbolic map")


class SymbolicSetOps:
    """
    Symbolic operations for Python sets.
    """

    @staticmethod
    def length(s: set | SymbolicSet) -> OpResult:
        """Get set cardinality."""
        if isinstance(s, set):
            return OpResult(value=len(s))
        elif isinstance(s, SymbolicSet):
            return OpResult(value=s.length)
        return OpResult(value=None, error=f"Cannot get length of {type(s)}")

    @staticmethod
    def contains(s: set | SymbolicSet, value: Any) -> OpResult:
        """Check if value is in set."""
        if isinstance(s, set):
            return OpResult(value=value in s)
        elif isinstance(s, SymbolicSet):
            result = s.contains(value)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot check containment in {type(s)}")

    @staticmethod
    def add(s: set | SymbolicSet, value: Any) -> OpResult:
        """Add value to set."""
        if isinstance(s, set):
            s.add(value)
            return OpResult(value=None, modified_collection=s)
        elif isinstance(s, SymbolicSet):
            new_set = s.add(value)
            return OpResult(value=None, modified_collection=new_set)
        return OpResult(value=None, error=f"Cannot add to {type(s)}")

    @staticmethod
    def remove(s: set | SymbolicSet, value: Any) -> OpResult:
        """Remove value from set (raises error if not present)."""
        if isinstance(s, set):
            if value in s:
                s.remove(value)
                return OpResult(value=None, modified_collection=s)
            else:
                return OpResult(value=None, error="KeyError")
        elif isinstance(s, SymbolicSet):
            has_value = s.contains(value)
            new_set = s.remove(value)
            return OpResult(value=None, modified_collection=new_set, constraints=[has_value.value])
        return OpResult(value=None, error=f"Cannot remove from {type(s)}")

    @staticmethod
    def discard(s: set | SymbolicSet, value: Any) -> OpResult:
        """Remove value from set if present."""
        if isinstance(s, set):
            s.discard(value)
            return OpResult(value=None, modified_collection=s)
        elif isinstance(s, SymbolicSet):
            new_set = s.remove(value)
            return OpResult(value=None, modified_collection=new_set)
        return OpResult(value=None, error=f"Cannot discard from {type(s)}")

    @staticmethod
    def pop(s: set | SymbolicSet) -> OpResult:
        """Remove and return arbitrary element."""
        if isinstance(s, set):
            if len(s) == 0:
                return OpResult(value=None, error="KeyError: pop from empty set")
            value = s.pop()
            return OpResult(value=value, modified_collection=s)
        elif isinstance(s, SymbolicSet):
            constraints = [s.length.value > 0]
            result = SymbolicInt(z3.Int(f"set_pop_{id(s)}"))
            return OpResult(value=result, constraints=constraints)
        return OpResult(value=None, error=f"Cannot pop from {type(s)}")

    @staticmethod
    def union(s1: set | SymbolicSet, s2: set | SymbolicSet) -> OpResult:
        """Return union of two sets."""
        if isinstance(s1, set) and isinstance(s2, set):
            return OpResult(value=s1 | s2)
        elif isinstance(s1, SymbolicSet) and isinstance(s2, SymbolicSet):
            result = s1.union(s2)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot union {type(s1)} and {type(s2)}")

    @staticmethod
    def intersection(s1: set | SymbolicSet, s2: set | SymbolicSet) -> OpResult:
        """Return intersection of two sets."""
        if isinstance(s1, set) and isinstance(s2, set):
            return OpResult(value=s1 & s2)
        elif isinstance(s1, SymbolicSet) and isinstance(s2, SymbolicSet):
            result = s1.intersection(s2)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot intersect {type(s1)} and {type(s2)}")

    @staticmethod
    def difference(s1: set | SymbolicSet, s2: set | SymbolicSet) -> OpResult:
        """Return difference of two sets (s1 - s2)."""
        if isinstance(s1, set) and isinstance(s2, set):
            return OpResult(value=s1 - s2)
        elif isinstance(s1, SymbolicSet) and isinstance(s2, SymbolicSet):
            result = s1.difference(s2)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot difference {type(s1)} and {type(s2)}")

    @staticmethod
    def symmetric_difference(s1: set | SymbolicSet, s2: set | SymbolicSet) -> OpResult:
        """Return symmetric difference of two sets."""
        if isinstance(s1, set) and isinstance(s2, set):
            return OpResult(value=s1 ^ s2)
        elif isinstance(s1, SymbolicSet) and isinstance(s2, SymbolicSet):
            diff1 = s1.difference(s2)
            diff2 = s2.difference(s1)
            result = diff1.union(diff2)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot symmetric_difference {type(s1)} and {type(s2)}")

    @staticmethod
    def issubset(s1: set | SymbolicSet, s2: set | SymbolicSet) -> OpResult:
        """Check if s1 is subset of s2."""
        if isinstance(s1, set) and isinstance(s2, set):
            return OpResult(value=s1 <= s2)
        elif isinstance(s1, SymbolicSet) and isinstance(s2, SymbolicSet):
            result = s1.issubset(s2)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot check subset of {type(s1)} and {type(s2)}")

    @staticmethod
    def issuperset(s1: set | SymbolicSet, s2: set | SymbolicSet) -> OpResult:
        """Check if s1 is superset of s2."""
        if isinstance(s1, set) and isinstance(s2, set):
            return OpResult(value=s1 >= s2)
        elif isinstance(s1, SymbolicSet) and isinstance(s2, SymbolicSet):
            result = s2.issubset(s1)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot check superset of {type(s1)} and {type(s2)}")

    @staticmethod
    def isdisjoint(s1: set | SymbolicSet, s2: set | SymbolicSet) -> OpResult:
        """Check if sets have no common elements."""
        if isinstance(s1, set) and isinstance(s2, set):
            return OpResult(value=s1.isdisjoint(s2))
        elif isinstance(s1, SymbolicSet) and isinstance(s2, SymbolicSet):
            inter = s1.intersection(s2)
            result = SymbolicBool(inter.length.value == 0)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot check disjoint of {type(s1)} and {type(s2)}")


class SymbolicTupleOps:
    """
    Symbolic operations for Python tuples (immutable).
    """

    @staticmethod
    def length(t: tuple | SymbolicTuple) -> OpResult:
        """Get tuple length."""
        if isinstance(t, tuple):
            return OpResult(value=len(t))
        elif isinstance(t, SymbolicTuple):
            return OpResult(value=len(t._elements))
        return OpResult(value=None, error=f"Cannot get length of {type(t)}")

    @staticmethod
    def getitem(t: tuple | SymbolicTuple, index: int | z3.ArithRef | SymbolicInt) -> OpResult:
        """Get item at index."""
        if isinstance(index, SymbolicInt):
            idx = index.value
        elif isinstance(index, int):
            idx = index
        else:
            idx = index
        if isinstance(t, tuple):
            if isinstance(idx, int):
                if 0 <= idx < len(t):
                    return OpResult(value=t[idx])
                else:
                    return OpResult(value=None, error="IndexError: tuple index out of range")
            else:
                result = SymbolicInt(z3.Int(f"tuple_item_{id(t)}"))
                constraints = [idx >= 0, idx < len(t)]
                return OpResult(value=result, constraints=constraints)
        elif isinstance(t, SymbolicTuple):
            if isinstance(idx, int) or (isinstance(idx, z3.ExprRef) and z3.is_int_value(idx)):
                concrete_idx = idx if isinstance(idx, int) else idx.as_long()
                if 0 <= concrete_idx < len(t._elements):
                    return OpResult(value=t._elements[concrete_idx])
                else:
                    return OpResult(value=None, error="IndexError: tuple index out of range")
            else:
                result = t[idx]
                constraints = [idx >= 0, idx < len(t._elements)]
                return OpResult(value=result, constraints=constraints)
        return OpResult(value=None, error=f"Cannot index {type(t)}")

    @staticmethod
    def count(t: tuple | SymbolicTuple, value: Any) -> OpResult:
        """Count occurrences of value."""
        if isinstance(t, tuple):
            return OpResult(value=t.count(value))
        elif isinstance(t, SymbolicTuple):
            count = 0
            for elem in t._elements:
                if elem == value:
                    count += 1
            return OpResult(value=count)
        return OpResult(value=None, error=f"Cannot count in {type(t)}")

    @staticmethod
    def index(
        t: tuple | SymbolicTuple, value: Any, start: int = 0, stop: int | None = None
    ) -> OpResult:
        """Return index of first occurrence of value."""
        if isinstance(t, tuple):
            try:
                if stop is None:
                    idx = t.index(value, start)
                else:
                    idx = t.index(value, start, stop)
                return OpResult(value=idx)
            except ValueError:
                return OpResult(value=None, error="ValueError: x not in tuple")
        elif isinstance(t, SymbolicTuple):
            elements = t._elements
            end = stop if stop is not None else len(elements)
            for i in range(start, end):
                if i < len(elements) and elements[i] == value:
                    return OpResult(value=i)
            return OpResult(value=None, error="ValueError: x not in tuple")
        return OpResult(value=None, error=f"Cannot find index in {type(t)}")

    @staticmethod
    def slice(
        t: tuple | SymbolicTuple,
        start: int | None = None,
        stop: int | None = None,
        step: int | None = None,
    ) -> OpResult:
        """Get a slice of the tuple."""
        if isinstance(t, tuple):
            return OpResult(value=t[start:stop:step])
        elif isinstance(t, SymbolicTuple):
            elements = t._elements[start:stop:step]
            return OpResult(value=SymbolicTuple(elements))
        return OpResult(value=None, error=f"Cannot slice {type(t)}")

    @staticmethod
    def concatenate(t1: tuple | SymbolicTuple, t2: tuple | SymbolicTuple) -> OpResult:
        """Concatenate two tuples."""
        if isinstance(t1, tuple) and isinstance(t2, tuple):
            return OpResult(value=t1 + t2)
        elif isinstance(t1, SymbolicTuple) and isinstance(t2, SymbolicTuple):
            elements = t1._elements + t2._elements
            return OpResult(value=SymbolicTuple(elements))
        return OpResult(value=None, error=f"Cannot concatenate {type(t1)} and {type(t2)}")

    @staticmethod
    def contains(t: tuple | SymbolicTuple, value: Any) -> OpResult:
        """Check if value is in tuple."""
        if isinstance(t, tuple):
            return OpResult(value=value in t)
        elif isinstance(t, SymbolicTuple):
            for elem in t._elements:
                if elem == value:
                    return OpResult(value=True)
            return OpResult(value=False)
        return OpResult(value=None, error=f"Cannot check containment in {type(t)}")


class SymbolicStringOps:
    """
    Symbolic operations for Python strings.
    """

    @staticmethod
    def length(s: str | SymbolicString) -> OpResult:
        """Get string length."""
        if isinstance(s, str):
            return OpResult(value=len(s))
        elif isinstance(s, SymbolicString):
            return OpResult(value=s.length)
        return OpResult(value=None, error=f"Cannot get length of {type(s)}")

    @staticmethod
    def contains(s: str | SymbolicString, substr: str | SymbolicString) -> OpResult:
        """Check if substring is in string."""
        if isinstance(s, str) and isinstance(substr, str):
            return OpResult(value=substr in s)
        elif isinstance(s, SymbolicString):
            result = s.contains(substr)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot check containment in {type(s)}")

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
        return OpResult(value=None, error=f"Cannot concatenate {type(s1)} and {type(s2)}")

    @staticmethod
    def startswith(s: str | SymbolicString, prefix: str | SymbolicString) -> OpResult:
        """Check if string starts with prefix."""
        if isinstance(s, str) and isinstance(prefix, str):
            return OpResult(value=s.startswith(prefix))
        elif isinstance(s, SymbolicString):
            result = s.startswith(prefix)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot check startswith on {type(s)}")

    @staticmethod
    def endswith(s: str | SymbolicString, suffix: str | SymbolicString) -> OpResult:
        """Check if string ends with suffix."""
        if isinstance(s, str) and isinstance(suffix, str):
            return OpResult(value=s.endswith(suffix))
        elif isinstance(s, SymbolicString):
            result = s.endswith(suffix)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot check endswith on {type(s)}")


__all__ = [
    "OpResult",
    "SymbolicListOps",
    "SymbolicDictOps",
    "SymbolicSetOps",
    "SymbolicTupleOps",
    "SymbolicStringOps",
]
