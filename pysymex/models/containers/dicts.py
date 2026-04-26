# pysymex: Python Symbolic Execution & Formal Verification
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

"""Enhanced Models for Python dict operations.
This module provides relationship-preserving symbolic models for dict methods.
Tracks key existence, length changes, and potential KeyError conditions.
Key improvements:
- get() vs [] distinction (get is safe, [] may raise KeyError)
- Length tracking for mutations (pop, popitem, clear, update)
- Key existence constraints for contains checks
- Proper side effects for debugging
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.core.types.scalars import (
    SymbolicDict,
    SymbolicList,
    SymbolicNone,
    SymbolicString,
    SymbolicValue,
)
from pysymex.models.builtins.base import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState


def _get_symbolic_dict(arg: object, state: VMState | None = None) -> SymbolicDict | None:
    """Extract SymbolicDict from argument, resolving SymbolicObject if needed."""
    if isinstance(arg, SymbolicDict):
        return arg
    if state is not None:
        from pysymex.core.types.containers import SymbolicObject

        if isinstance(arg, SymbolicObject):
            addr = arg.address
            if addr in state.memory:
                val = state.memory[addr]
                if isinstance(val, SymbolicDict):
                    return val
    return None


def _get_symbolic_string(arg: object) -> SymbolicString | None:
    """Extract SymbolicString from argument."""
    if isinstance(arg, SymbolicString):
        return arg
    return None


class DictGetModel(FunctionModel):
    """Model for dict.get(key, default) - safe key access, never raises.
    Relationships:
    - If key exists: returns dict[key]
    - If key doesn't exist: returns default (None if not provided)
    - Never raises KeyError
    """

    name = "get"
    qualname = "dict.get"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0], state) if args else None
        key = _get_symbolic_string(args[1]) if len(args) > 1 else None
        args[2] if len(args) > 2 else None
        result, constraint = SymbolicValue.symbolic(f"dict_get_{state.pc}_{state.path_id}")
        constraints = [constraint]
        if d is not None and key is not None:
            d.contains_key(key)
        return ModelResult(value=result, constraints=constraints)


class DictGetitemModel(FunctionModel):
    """Model for dict[key] - may raise KeyError.
    Bug detection: Can find cases where key might not exist.
    """

    name = "__getitem__"
    qualname = "dict.__getitem__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0], state) if args else None
        key = _get_symbolic_string(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicValue.symbolic(f"dict_getitem_{state.pc}_{state.path_id}")
        constraints: list[z3.BoolRef] = [constraint]
        side_effects: dict[str, object] = {}
        if d is not None and key is not None:
            side_effects["potential_exception"] = {
                "type": "KeyError",
                "message": "Key not found in dictionary",
                "condition": z3.Not(d.contains_key(key).z3_bool),
            }
        return ModelResult(
            value=result,
            constraints=constraints,
            side_effects=side_effects,
        )


class DictSetitemModel(FunctionModel):
    """Model for dict[key] = value - adds or updates key.
    Relationship:
    - If key was new: length increases by 1
    - If key existed: length unchanged
    """

    name = "__setitem__"
    qualname = "dict.__setitem__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0], state) if args else None
        key_arg = args[1] if len(args) > 1 else None
        value_arg = args[2] if len(args) > 2 else None
        key = _get_symbolic_string(key_arg) if key_arg is not None else None
        value = (
            value_arg
            if isinstance(value_arg, SymbolicValue)
            else SymbolicValue.from_const(value_arg)
        )
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef] = []
        if d is not None and key is not None:
            new_len = z3.Int(f"dict_len_{state.pc}_{state.path_id}")
            exists = d.contains_key(key)
            constraints.append(z3.If(exists.z3_bool, new_len == d.z3_len, new_len == d.z3_len + 1))

            new_dict = d.copy()
            new_dict.z3_len = new_len
            if value_arg is not None:
                new_dict.z3_array = z3.Store(d.z3_array, key.z3_str, value.z3_int)
            new_dict.known_keys = z3.Concat(d.known_keys, z3.Unit(key.z3_str))

            side_effects["dict_mutation"] = {
                "operation": "setitem",
                "original_dict": d,
                "updated_dict": new_dict,
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints if d is not None else [],
            side_effects=side_effects,
        )


class DictDelitemModel(FunctionModel):
    """Model for del dict[key] - may raise KeyError.
    Relationship:
    - If key exists: length decreases by 1
    - If key doesn't exist: raises KeyError
    """

    name = "__delitem__"
    qualname = "dict.__delitem__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0], state) if args else None
        key = _get_symbolic_string(args[1]) if len(args) > 1 else None
        constraints: list[z3.BoolRef] = []
        side_effects: dict[str, object] = {}
        if d is not None:
            constraints.append(d.z3_len >= 1)
            if key is not None:
                side_effects["potential_exception"] = {
                    "type": "KeyError",
                    "message": "Key not found for deletion",
                    "condition": z3.Not(d.contains_key(key).z3_bool),
                }

            new_dict = d.copy()
            new_dict.z3_len = d.z3_len - 1

            side_effects["dict_mutation"] = {
                "operation": "delitem",
                "original_dict": d,
                "updated_dict": new_dict,
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


class DictKeysModel(FunctionModel):
    """Model for dict.keys() - returns view of keys.
    Relationship: len(keys) == len(dict)
    """

    name = "keys"
    qualname = "dict.keys"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"dict_keys_{state.pc}")
        constraints = [constraint]
        if d is not None:
            constraints.append(result.z3_len == d.z3_len)
        return ModelResult(value=result, constraints=constraints)


class DictValuesModel(FunctionModel):
    """Model for dict.values() - returns view of values.
    Relationship: len(values) == len(dict)
    """

    name = "values"
    qualname = "dict.values"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"dict_values_{state.pc}")
        constraints = [constraint]
        if d is not None:
            constraints.append(result.z3_len == d.z3_len)
        return ModelResult(value=result, constraints=constraints)


class DictItemsModel(FunctionModel):
    """Model for dict.items() - returns view of (key, value) pairs.
    Relationship: len(items) == len(dict)
    """

    name = "items"
    qualname = "dict.items"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"dict_items_{state.pc}")
        constraints = [constraint]
        if d is not None:
            constraints.append(result.z3_len == d.z3_len)
        return ModelResult(value=result, constraints=constraints)


class DictPopModel(FunctionModel):
    """Model for dict.pop(key, [default]) - remove and return value.
    Behavior:
    - If key exists: remove key, return value, length decreases
    - If key doesn't exist and default given: return default
    - If key doesn't exist and no default: raise KeyError
    """

    name = "pop"
    qualname = "dict.pop"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        key = _get_symbolic_string(args[1]) if len(args) > 1 else None
        has_default = len(args) > 2
        result, constraint = SymbolicValue.symbolic(f"dict_pop_{state.pc}")
        constraints: list[z3.BoolRef] = [constraint]
        side_effects: dict[str, object] = {}
        if d is not None:
            if not has_default and key is not None:
                side_effects["potential_exception"] = {
                    "type": "KeyError",
                    "message": "Key not found and no default provided",
                    "condition": z3.Not(d.contains_key(key).z3_bool),
                }

            key_present = d.contains_key(key).z3_bool if key is not None else z3.BoolVal(True)
            old_len = d.z3_len
            new_len = z3.If(key_present, old_len - 1, old_len)
            new_dict = d.copy()
            new_dict.z3_len = new_len
            side_effects["dict_mutation"] = {
                "operation": "pop",
                "original_dict": d,
                "updated_dict": new_dict,
                "dict_name": d.name,
                "old_length": old_len,
                "new_length": new_len,
            }
        return ModelResult(
            value=result,
            constraints=constraints,
            side_effects=side_effects,
        )


class DictPopitemModel(FunctionModel):
    """Model for dict.popitem() - remove and return (key, value) pair.
    Raises: KeyError if dict is empty.
    Relationship: After popitem, len(dict) == old_len - 1
    """

    name = "popitem"
    qualname = "dict.popitem"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"dict_popitem_{state.pc}")
        constraints: list[z3.BoolRef] = [constraint, result.z3_len == 2]
        side_effects: dict[str, object] = {}
        if d is not None:
            constraints.append(d.z3_len >= 1)
            side_effects["potential_exception"] = {
                "type": "KeyError",
                "message": "popitem(): dictionary is empty",
                "condition": d.z3_len == 0,
            }
            new_len = d.z3_len - 1
            d.z3_len = new_len
            side_effects["dict_mutation"] = {
                "operation": "popitem",
                "dict_name": d.name,
                "old_length": d.z3_len + 1,
                "new_length": new_len,
            }
        return ModelResult(
            value=result,
            constraints=constraints,
            side_effects=side_effects,
        )


class DictUpdateModel(FunctionModel):
    """Model for dict.update(other) - merge other into dict.
    Relationship: new_len >= old_len (may add new keys)
    """

    name = "update"
    qualname = "dict.update"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        other = _get_symbolic_dict(args[1]) if len(args) > 1 else None
        side_effects: dict[str, object] = {}
        if d is not None:
            if other is not None:
                side_effects["dict_mutation"] = {
                    "operation": "update",
                    "dict_name": d.name,
                    "old_length": d.z3_len,
                    "new_length_range": (d.z3_len, d.z3_len + other.z3_len),
                }
            else:
                side_effects["dict_mutation"] = {
                    "operation": "update",
                    "dict_name": d.name,
                    "old_length": d.z3_len,
                    "length_may_increase": True,
                }
        return ModelResult(
            value=SymbolicNone(),
            side_effects=side_effects,
        )


class DictClearModel(FunctionModel):
    """Model for dict.clear() - remove all items.
    Relationship: After clear, len(dict) == 0
    """

    name = "clear"
    qualname = "dict.clear"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        side_effects: dict[str, object] = {}
        if d is not None:
            d.z3_len = z3.IntVal(0)
            side_effects["dict_mutation"] = {
                "operation": "clear",
                "dict_name": d.name,
                "old_length": d.z3_len,
                "new_length": z3.IntVal(0),
            }
        return ModelResult(
            value=SymbolicNone(),
            side_effects=side_effects,
        )


class DictCopyModel(FunctionModel):
    """Model for dict.copy() - shallow copy.
    Relationship:
    - New dict has same length
    - New dict has same keys/values (shallow)
    """

    name = "copy"
    qualname = "dict.copy"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        result, constraint = SymbolicDict.symbolic(f"dict_copy_{state.pc}")
        constraints = [constraint]
        if d is not None:
            constraints.append(result.z3_len == d.z3_len)
        return ModelResult(value=result, constraints=constraints)


class DictSetdefaultModel(FunctionModel):
    """Model for dict.setdefault(key, default) - get or set key.
    Behavior:
    - If key exists: return dict[key]
    - If key doesn't exist: dict[key] = default, return default
    Relationship: new_len is either old_len (key existed) or old_len + 1
    """

    name = "setdefault"
    qualname = "dict.setdefault"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"dict_setdefault_{state.pc}")
        constraints: list[z3.BoolRef] = [constraint]
        side_effects: dict[str, object] = {}
        if d is not None:
            side_effects["dict_mutation"] = {
                "operation": "setdefault",
                "dict_name": d.name,
                "old_length": d.z3_len,
                "new_length_range": (d.z3_len, d.z3_len + 1),
            }
        return ModelResult(
            value=result,
            constraints=constraints,
            side_effects=side_effects,
        )


class DictContainsModel(FunctionModel):
    """Model for 'key in dict' operation.
    Relationship:
    - If dict is empty: result is False
    - Otherwise: symbolic boolean based on key membership
    """

    name = "__contains__"
    qualname = "dict.__contains__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        key = _get_symbolic_string(args[1]) if len(args) > 1 else None
        if d is not None and key is not None:
            result = d.contains_key(key)
            constraints = [z3.Implies(d.z3_len == 0, z3.Not(result.z3_bool))]
            return ModelResult(value=result, constraints=constraints)
        result, constraint = SymbolicValue.symbolic(f"dict_contains_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint, result.is_bool],
        )


class DictLenModel(FunctionModel):
    """Model for len(dict)."""

    name = "__len__"
    qualname = "dict.__len__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        if d is not None:
            result = SymbolicValue(
                _name=f"len({d.name})",
                z3_int=d.z3_len,
                is_int=z3.BoolVal(True),
                z3_bool=z3.BoolVal(False),
                is_bool=z3.BoolVal(False),
            )
            return ModelResult(value=result, constraints=[])
        result, constraint = SymbolicValue.symbolic(f"dict_len_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint, result.is_int, result.z3_int >= 0],
        )


class DictFromkeysModel(FunctionModel):
    """Model for dict.fromkeys(iterable, value)."""

    name = "fromkeys"
    qualname = "dict.fromkeys"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicDict.symbolic(f"fromkeys_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        if args:
            keys_arg = args[0]
            keys_len = getattr(keys_arg, "z3_len", None)
            if keys_len is not None:
                constraints.append(result.z3_len == keys_len)
        return ModelResult(value=result, constraints=constraints)


class DictEqModel(FunctionModel):
    """Model for dict.__eq__(other)."""

    name = "__eq__"
    qualname = "dict.__eq__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        other = _get_symbolic_dict(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicValue.symbolic(f"dict_eq_{state.pc}")
        constraints = [constraint, result.is_bool]
        if d is not None and other is not None:
            constraints.append(z3.Implies(result.z3_bool, d.z3_len == other.z3_len))
            constraints.append(z3.Implies(d.z3_len != other.z3_len, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class DictOrModel(FunctionModel):
    """Model for dict.__or__(other) - merge operator (Python 3.9+)."""

    name = "__or__"
    qualname = "dict.__or__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        other = _get_symbolic_dict(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicDict.symbolic(f"dict_or_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        if d is not None and other is not None:
            constraints.append(
                result.z3_len >= z3.If(d.z3_len > other.z3_len, d.z3_len, other.z3_len)
            )
            constraints.append(result.z3_len <= d.z3_len + other.z3_len)
        elif d is not None:
            constraints.append(result.z3_len >= d.z3_len)
        return ModelResult(value=result, constraints=constraints)


class DictIorModel(FunctionModel):
    """Model for dict.__ior__(other) - in-place merge via |=."""

    name = "__ior__"
    qualname = "dict.__ior__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        other = _get_symbolic_dict(args[1]) if len(args) > 1 else None
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        side_effects: dict[str, object] = {}
        if d is not None:
            new_len = z3.Int(f"dict_len_{state.pc}")
            constraints.append(new_len >= d.z3_len)
            if other is not None:
                constraints.append(new_len <= d.z3_len + other.z3_len)
            d.z3_len = new_len
            side_effects["dict_mutation"] = {
                "operation": "ior",
                "dict_name": getattr(d, "name", "dict"),
            }
        return ModelResult(
            value=args[0] if args else SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


DICT_MODELS = [
    DictGetModel(),
    DictGetitemModel(),
    DictSetitemModel(),
    DictDelitemModel(),
    DictKeysModel(),
    DictValuesModel(),
    DictItemsModel(),
    DictPopModel(),
    DictPopitemModel(),
    DictUpdateModel(),
    DictClearModel(),
    DictCopyModel(),
    DictSetdefaultModel(),
    DictContainsModel(),
    DictLenModel(),
    DictFromkeysModel(),
    DictEqModel(),
    DictOrModel(),
    DictIorModel(),
]
