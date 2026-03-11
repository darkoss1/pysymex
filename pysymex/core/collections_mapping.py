"""
pysymex Collection Theories — Dict, Set, and Tuple operations.

Provides precise symbolic modeling for Python dicts, sets, and tuples
with full operation semantics using Z3 theories.
"""

from __future__ import annotations

from typing import cast

import z3

from pysymex.core.addressing import next_address

from .collections_list import OpResult
from .memory_model import SymbolicMap
from .symbolic_types import (
    SymbolicBool,
    SymbolicDict,
    SymbolicInt,
    SymbolicSet,
    SymbolicTuple,
)


class SymbolicDictOps:
    """
    Symbolic operations for Python dicts.
    """

    @staticmethod
    def length(d: dict[object, object] | SymbolicDict | SymbolicMap) -> OpResult:
        """Get number of keys in dict."""
        if isinstance(d, dict):
            return OpResult(value=len(d))
        elif isinstance(d, SymbolicDict):
            return OpResult(value=d.length)
        else:
            assert isinstance(d, SymbolicMap)
            length_var = z3.Int(f"dict_len_{next_address()}")
            return OpResult(value=SymbolicInt(length_var), constraints=[length_var >= 0])
        return OpResult(value=None, error=f"Cannot get length of {type(d)}")

    @staticmethod
    def getitem(d: dict[object, object] | SymbolicDict | SymbolicMap, key: object) -> OpResult:
        """Get value for key."""
        if isinstance(d, dict):
            if key in d:
                return OpResult(value=d[key])
            else:
                return OpResult(value=None, error="KeyError")
        elif isinstance(d, SymbolicDict):
            sym_key = (
                key if isinstance(key, SymbolicInt) else SymbolicInt(z3.IntVal(cast(int, key)))
            )
            result = d[sym_key]
            has_key = d.contains(sym_key)
            return OpResult(value=result, constraints=[has_key])
        else:
            assert isinstance(d, SymbolicMap)
            z3_key = cast(
                z3.ExprRef,
                key.value
                if isinstance(key, SymbolicInt)
                else z3.IntVal(key)
                if isinstance(key, int)
                else key,
            )
            result = d.get(z3_key)
            has_key = d.contains(z3_key)
            return OpResult(value=result, constraints=[has_key])
        return OpResult(value=None, error=f"Cannot get item from {type(d)}")

    @staticmethod
    def setitem(d: dict[object, object] | SymbolicMap, key: object, value: object) -> OpResult:
        """Set value for key."""
        if isinstance(d, dict):
            d[key] = value
            return OpResult(value=None, modified_collection=d)
        else:
            assert isinstance(d, SymbolicMap)
            z3_key = cast(
                z3.ExprRef,
                key.value
                if isinstance(key, SymbolicInt)
                else z3.IntVal(key)
                if isinstance(key, int)
                else key,
            )
            z3_val = cast(
                z3.ExprRef,
                value.value
                if isinstance(value, SymbolicInt)
                else z3.IntVal(value)
                if isinstance(value, int)
                else value,
            )
            new_map = d.set(z3_key, z3_val)
            return OpResult(value=None, modified_collection=new_map)
        return OpResult(value=None, error=f"Cannot set item on {type(d)}")

    @staticmethod
    def delitem(d: dict[object, object] | SymbolicMap, key: object) -> OpResult:
        """Delete key from dict."""
        if isinstance(d, dict):
            if key in d:
                del d[key]
                return OpResult(value=None, modified_collection=d)
            else:
                return OpResult(value=None, error="KeyError")
        else:
            assert isinstance(d, SymbolicMap)
            z3_key = cast(
                z3.ExprRef,
                key.value
                if isinstance(key, SymbolicInt)
                else z3.IntVal(key)
                if isinstance(key, int)
                else key,
            )
            has_key = d.contains(z3_key)
            new_map = d.delete(z3_key)
            return OpResult(value=None, modified_collection=new_map, constraints=[has_key])
        return OpResult(value=None, error=f"Cannot delete from {type(d)}")

    @staticmethod
    def get(d: dict[object, object] | SymbolicMap, key: object, default: object = None) -> OpResult:
        """Get value for key with default."""
        if isinstance(d, dict):
            return OpResult(value=d.get(key, default))
        else:
            assert isinstance(d, SymbolicMap)
            z3_key = cast(
                z3.ExprRef,
                key.value
                if isinstance(key, SymbolicInt)
                else z3.IntVal(key)
                if isinstance(key, int)
                else key,
            )
            z3_default = (
                cast(
                    z3.ExprRef,
                    default.value
                    if isinstance(default, SymbolicInt)
                    else z3.IntVal(default)
                    if isinstance(default, int)
                    else default,
                )
                if default is not None
                else None
            )
            result = d.get(z3_key, z3_default)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot get from {type(d)}")

    @staticmethod
    def contains(d: dict[object, object] | SymbolicMap, key: object) -> OpResult:
        """Check if key is in dict."""
        if isinstance(d, dict):
            return OpResult(value=key in d)
        else:
            assert isinstance(d, SymbolicMap)
            z3_key = cast(
                z3.ExprRef,
                key.value
                if isinstance(key, SymbolicInt)
                else z3.IntVal(key)
                if isinstance(key, int)
                else key,
            )
            result = d.contains(z3_key)
            return OpResult(value=SymbolicBool(result))
        return OpResult(value=None, error=f"Cannot check containment in {type(d)}")

    @staticmethod
    def pop(d: dict[object, object] | SymbolicMap, key: object, default: object = None) -> OpResult:
        """Remove and return value for key."""
        if isinstance(d, dict):
            if key in d:
                pop_value: object = d.pop(key)
                return OpResult(value=pop_value, modified_collection=d)
            elif default is not None:
                return OpResult(value=default, modified_collection=d)
            else:
                return OpResult(value=None, error="KeyError")
        else:
            assert isinstance(d, SymbolicMap)
            z3_key = cast(
                z3.ExprRef,
                key.value
                if isinstance(key, SymbolicInt)
                else z3.IntVal(key)
                if isinstance(key, int)
                else key,
            )
            z3_default = (
                cast(
                    z3.ExprRef,
                    default.value
                    if isinstance(default, SymbolicInt)
                    else (z3.IntVal(default) if isinstance(default, int) else default),
                )
                if default is not None
                else None
            )
            d.contains(z3_key)
            pop_val: object = d.get(z3_key, z3_default) if z3_default is not None else d.get(z3_key)
            new_map = d.delete(z3_key)
            return OpResult(value=pop_val, modified_collection=new_map)
        return OpResult(value=None, error=f"Cannot pop from {type(d)}")

    @staticmethod
    def setdefault(
        d: dict[object, object] | SymbolicMap, key: object, default: object = None
    ) -> OpResult:
        """Get value for key, setting default if not present."""
        if isinstance(d, dict):
            if key not in d:
                d[key] = default
            return OpResult(value=d[key], modified_collection=d)
        else:
            assert isinstance(d, SymbolicMap)
            z3_key = cast(
                z3.ExprRef,
                key.value
                if isinstance(key, SymbolicInt)
                else z3.IntVal(key)
                if isinstance(key, int)
                else key,
            )
            z3_default = cast(
                z3.ExprRef,
                default.value
                if isinstance(default, SymbolicInt)
                else (z3.IntVal(default) if isinstance(default, int) else default),
            )
            has_key = d.contains(z3_key)
            existing_value = d.get(z3_key)
            z3.If(has_key, d, d.set(z3_key, z3_default))
            result = z3.If(has_key, existing_value, z3_default)
            final_map = d.set(z3_key, cast(z3.ExprRef, result))
            return OpResult(value=result, modified_collection=final_map)
        return OpResult(value=None, error=f"Cannot setdefault on {type(d)}")

    @staticmethod
    def update(
        d: dict[object, object] | SymbolicMap, other: dict[object, object] | SymbolicMap
    ) -> OpResult:
        """Update dict with key-value pairs from other."""
        if isinstance(d, dict) and isinstance(other, dict):
            d.update(other)
            return OpResult(value=None, modified_collection=d)
        elif isinstance(d, SymbolicMap) and isinstance(other, dict):
            result_map: SymbolicMap = d
            for k, v in other.items():
                z3_key = cast(
                    z3.ExprRef,
                    k if isinstance(k, z3.ExprRef) else z3.IntVal(k) if isinstance(k, int) else k,
                )
                z3_val = cast(
                    z3.ExprRef,
                    v if isinstance(v, z3.ExprRef) else z3.IntVal(v) if isinstance(v, int) else v,
                )
                result_map = result_map.set(z3_key, z3_val)
            return OpResult(value=None, modified_collection=result_map)
        return OpResult(value=None, error=f"Cannot update {type(d)} with {type(other)}")

    @staticmethod
    def keys(d: dict[object, object] | SymbolicMap) -> OpResult:
        """Get dict keys."""
        if isinstance(d, dict):
            return OpResult(value=list(d.keys()))
        return OpResult(value=None, error="Cannot enumerate keys of symbolic map")

    @staticmethod
    def values(d: dict[object, object] | SymbolicMap) -> OpResult:
        """Get dict values."""
        if isinstance(d, dict):
            return OpResult(value=list(d.values()))
        return OpResult(value=None, error="Cannot enumerate values of symbolic map")

    @staticmethod
    def items(d: dict[object, object] | SymbolicMap) -> OpResult:
        """Get dict items."""
        if isinstance(d, dict):
            return OpResult(value=list(d.items()))
        return OpResult(value=None, error="Cannot enumerate items of symbolic map")


class SymbolicSetOps:
    """
    Symbolic operations for Python sets.
    """

    @staticmethod
    def length(s: set[object] | SymbolicSet) -> OpResult:
        """Get set cardinality."""
        if isinstance(s, set):
            return OpResult(value=len(s))
        else:
            assert isinstance(s, SymbolicSet)
            return OpResult(value=s.length)
        return OpResult(value=None, error=f"Cannot get length of {type(s)}")

    @staticmethod
    def contains(s: set[object] | SymbolicSet, value: object) -> OpResult:
        """Check if value is in set."""
        if isinstance(s, set):
            return OpResult(value=value in s)
        else:
            assert isinstance(s, SymbolicSet)
            sym_val = (
                value
                if isinstance(value, SymbolicInt)
                else SymbolicInt(z3.IntVal(cast(int, value)))
            )
            result = s.contains(sym_val)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot check containment in {type(s)}")

    @staticmethod
    def add(s: set[object] | SymbolicSet, value: object) -> OpResult:
        """Add value to set."""
        if isinstance(s, set):
            s.add(value)
            return OpResult(value=None, modified_collection=s)
        else:
            assert isinstance(s, SymbolicSet)
            sym_val = (
                value
                if isinstance(value, SymbolicInt)
                else SymbolicInt(z3.IntVal(cast(int, value)))
            )
            new_set = s.add(sym_val)
            return OpResult(value=None, modified_collection=new_set)
        return OpResult(value=None, error=f"Cannot add to {type(s)}")

    @staticmethod
    def remove(s: set[object] | SymbolicSet, value: object) -> OpResult:
        """Remove value from set (raises error if not present)."""
        if isinstance(s, set):
            if value in s:
                s.remove(value)
                return OpResult(value=None, modified_collection=s)
            else:
                return OpResult(value=None, error="KeyError")
        else:
            assert isinstance(s, SymbolicSet)
            sym_val = (
                value
                if isinstance(value, SymbolicInt)
                else SymbolicInt(z3.IntVal(cast(int, value)))
            )
            has_value = s.contains(sym_val)
            new_set = s.remove(sym_val)
            return OpResult(
                value=None, modified_collection=new_set, constraints=[has_value.z3_bool]
            )
        return OpResult(value=None, error=f"Cannot remove from {type(s)}")

    @staticmethod
    def discard(s: set[object] | SymbolicSet, value: object) -> OpResult:
        """Remove value from set if present."""
        if isinstance(s, set):
            s.discard(value)
            return OpResult(value=None, modified_collection=s)
        else:
            assert isinstance(s, SymbolicSet)
            sym_val = (
                value
                if isinstance(value, SymbolicInt)
                else SymbolicInt(z3.IntVal(cast(int, value)))
            )
            new_set = s.remove(sym_val)
            return OpResult(value=None, modified_collection=new_set)
        return OpResult(value=None, error=f"Cannot discard from {type(s)}")

    @staticmethod
    def pop(s: set[object] | SymbolicSet) -> OpResult:
        """Remove and return arbitrary element."""
        if isinstance(s, set):
            if len(s) == 0:
                return OpResult(value=None, error="KeyError: pop from empty set")
            pop_value: object = s.pop()
            return OpResult(value=pop_value, modified_collection=s)
        else:
            assert isinstance(s, SymbolicSet)
            constraints: list[z3.BoolRef] = [s.length.value > 0]
            result = SymbolicInt(z3.Int(f"set_pop_{next_address()}"))
            return OpResult(value=result, constraints=constraints)
        return OpResult(value=None, error=f"Cannot pop from {type(s)}")

    @staticmethod
    def union(s1: set[object] | SymbolicSet, s2: set[object] | SymbolicSet) -> OpResult:
        """Return union of two sets."""
        if isinstance(s1, set) and isinstance(s2, set):
            return OpResult(value=s1 | s2)
        elif isinstance(s1, SymbolicSet) and isinstance(s2, SymbolicSet):
            result = s1.union(s2)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot union {type(s1)} and {type(s2)}")

    @staticmethod
    def intersection(s1: set[object] | SymbolicSet, s2: set[object] | SymbolicSet) -> OpResult:
        """Return intersection of two sets."""
        if isinstance(s1, set) and isinstance(s2, set):
            return OpResult(value=s1 & s2)
        elif isinstance(s1, SymbolicSet) and isinstance(s2, SymbolicSet):
            result = s1.intersection(s2)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot intersect {type(s1)} and {type(s2)}")

    @staticmethod
    def difference(s1: set[object] | SymbolicSet, s2: set[object] | SymbolicSet) -> OpResult:
        """Return difference of two sets (s1 - s2)."""
        if isinstance(s1, set) and isinstance(s2, set):
            return OpResult(value=s1 - s2)
        elif isinstance(s1, SymbolicSet) and isinstance(s2, SymbolicSet):
            result = s1.difference(s2)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot difference {type(s1)} and {type(s2)}")

    @staticmethod
    def symmetric_difference(
        s1: set[object] | SymbolicSet, s2: set[object] | SymbolicSet
    ) -> OpResult:
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
    def issubset(s1: set[object] | SymbolicSet, s2: set[object] | SymbolicSet) -> OpResult:
        """Check if s1 is subset of s2."""
        if isinstance(s1, set) and isinstance(s2, set):
            return OpResult(value=s1 <= s2)
        elif isinstance(s1, SymbolicSet) and isinstance(s2, SymbolicSet):
            result = s1.issubset(s2)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot check subset of {type(s1)} and {type(s2)}")

    @staticmethod
    def issuperset(s1: set[object] | SymbolicSet, s2: set[object] | SymbolicSet) -> OpResult:
        """Check if s1 is superset of s2."""
        if isinstance(s1, set) and isinstance(s2, set):
            return OpResult(value=s1 >= s2)
        elif isinstance(s1, SymbolicSet) and isinstance(s2, SymbolicSet):
            result = s2.issubset(s1)
            return OpResult(value=result)
        return OpResult(value=None, error=f"Cannot check superset of {type(s1)} and {type(s2)}")

    @staticmethod
    def isdisjoint(s1: set[object] | SymbolicSet, s2: set[object] | SymbolicSet) -> OpResult:
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
    def length(t: tuple[object, ...] | SymbolicTuple) -> OpResult:
        """Get tuple length."""
        if isinstance(t, tuple):
            return OpResult(value=len(t))
        else:
            assert isinstance(t, SymbolicTuple)
            return OpResult(value=len(t.elements))
        return OpResult(value=None, error=f"Cannot get length of {type(t)}")

    @staticmethod
    def getitem(
        t: tuple[object, ...] | SymbolicTuple, index: int | z3.ArithRef | SymbolicInt
    ) -> OpResult:
        """Get item at index."""
        if isinstance(index, SymbolicInt):
            idx: int | z3.ArithRef = index.value
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
                result = SymbolicInt(z3.Int(f"tuple_item_{next_address()}"))
                constraints: list[z3.BoolRef] = [idx >= 0, idx < len(t)]
                return OpResult(value=result, constraints=constraints)
        else:
            assert isinstance(t, SymbolicTuple)
            if isinstance(idx, int) or z3.is_int_value(idx):
                concrete_idx = idx if isinstance(idx, int) else idx.as_long()
                if 0 <= concrete_idx < len(t.elements):
                    return OpResult(value=t.elements[concrete_idx])
                else:
                    return OpResult(value=None, error="IndexError: tuple index out of range")
            else:
                sym_idx = idx if isinstance(idx, SymbolicInt) else SymbolicInt(idx)
                result_st = t[sym_idx]
                z3_idx = idx
                constraints_st: list[z3.BoolRef] = [
                    z3_idx >= 0,
                    z3_idx < len(t.elements),
                ]
                return OpResult(value=result_st, constraints=constraints_st)
        return OpResult(value=None, error=f"Cannot index {type(t)}")

    @staticmethod
    def count(t: tuple[object, ...] | SymbolicTuple, value: object) -> OpResult:
        """Count occurrences of value."""
        if isinstance(t, tuple):
            return OpResult(value=t.count(value))
        else:
            assert isinstance(t, SymbolicTuple)
            count = 0
            for elem in t.elements:
                if elem == value:
                    count += 1
            return OpResult(value=count)
        return OpResult(value=None, error=f"Cannot count in {type(t)}")

    @staticmethod
    def index(
        t: tuple[object, ...] | SymbolicTuple,
        value: object,
        start: int = 0,
        stop: int | None = None,
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
        else:
            assert isinstance(t, SymbolicTuple)
            elements = t.elements
            end = stop if stop is not None else len(elements)
            for i in range(start, end):
                if i < len(elements) and elements[i] == value:
                    return OpResult(value=i)
            return OpResult(value=None, error="ValueError: x not in tuple")
        return OpResult(value=None, error=f"Cannot find index in {type(t)}")

    @staticmethod
    def slice(
        t: tuple[object, ...] | SymbolicTuple,
        start: int | None = None,
        stop: int | None = None,
        step: int | None = None,
    ) -> OpResult:
        """Get a slice of the tuple."""
        if isinstance(t, tuple):
            return OpResult(value=t[start:stop:step])
        else:
            assert isinstance(t, SymbolicTuple)
            elements = t.elements[start:stop:step]
            return OpResult(value=SymbolicTuple(elements))
        return OpResult(value=None, error=f"Cannot slice {type(t)}")

    @staticmethod
    def concatenate(
        t1: tuple[object, ...] | SymbolicTuple, t2: tuple[object, ...] | SymbolicTuple
    ) -> OpResult:
        """Concatenate two tuples."""
        if isinstance(t1, tuple) and isinstance(t2, tuple):
            return OpResult(value=t1 + t2)
        elif isinstance(t1, SymbolicTuple) and isinstance(t2, SymbolicTuple):
            elements = t1.elements + t2.elements
            return OpResult(value=SymbolicTuple(elements))
        return OpResult(value=None, error=f"Cannot concatenate {type(t1)} and {type(t2)}")

    @staticmethod
    def contains(t: tuple[object, ...] | SymbolicTuple, value: object) -> OpResult:
        """Check if value is in tuple."""
        if isinstance(t, tuple):
            return OpResult(value=value in t)
        else:
            assert isinstance(t, SymbolicTuple)
            for elem in t.elements:
                if elem == value:
                    return OpResult(value=True)
            return OpResult(value=False)
        return OpResult(value=None, error=f"Cannot check containment in {type(t)}")
