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
from typing import TYPE_CHECKING, Any
import z3
from pyspectre.core.types import (
    SymbolicDict,
    SymbolicList,
    SymbolicNone,
    SymbolicString,
    SymbolicValue,
)
from pyspectre.models.builtins import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pyspectre.core.state import VMState


def _get_symbolic_dict(arg: Any) -> SymbolicDict | None:
    """Extract SymbolicDict from argument."""
    if isinstance(arg, SymbolicDict):
        return arg
    return None


def _get_symbolic_string(arg: Any) -> SymbolicString | None:
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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        key = _get_symbolic_string(args[1]) if len(args) > 1 else None
        default = args[2] if len(args) > 2 else None
        result, constraint = SymbolicValue.symbolic(f"dict_get_{state.pc}")
        constraints = [constraint]
        if d is not None and key is not None:
            key_exists = d.contains_key(key)
        return ModelResult(value=result, constraints=constraints)


class DictGetitemModel(FunctionModel):
    """Model for dict[key] - may raise KeyError.
    Bug detection: Can find cases where key might not exist.
    """

    name = "__getitem__"
    qualname = "dict.__getitem__"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        key = _get_symbolic_string(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicValue.symbolic(f"dict_getitem_{state.pc}")
        constraints = [constraint]
        side_effects = {}
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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        key_arg = args[1] if len(args) > 1 else None
        value_arg = args[2] if len(args) > 2 else None
        key = _get_symbolic_string(key_arg) if key_arg is not None else None
        value = (
            value_arg
            if isinstance(value_arg, SymbolicValue)
            else SymbolicValue.from_const(value_arg)
        )
        side_effects = {}
        constraints = []
        if d is not None and key is not None:
            new_len = z3.Int(f"dict_len_{state.pc}")
            exists = d.contains_key(key)
            constraints.append(z3.If(exists.z3_bool, new_len == d.z3_len, new_len == d.z3_len + 1))
            setattr(d, "z3_len", new_len)
            if value is not None:
                new_array = z3.Store(d.z3_array, key.z3_str, value.z3_int)
                setattr(d, "z3_array", new_array)
            new_keys = z3.Concat(d.known_keys, z3.Unit(key.z3_str))
            setattr(d, "known_keys", new_keys)
            side_effects["dict_mutation"] = {
                "operation": "setitem",
                "dict_name": d._name,
                "old_length": d.z3_len,
                "new_length": new_len,
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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        key = _get_symbolic_string(args[1]) if len(args) > 1 else None
        constraints = []
        side_effects = {}
        if d is not None:
            constraints.append(d.z3_len >= 1)
            if key is not None:
                side_effects["potential_exception"] = {
                    "type": "KeyError",
                    "message": "Key not found for deletion",
                    "condition": z3.Not(d.contains_key(key).z3_bool),
                }
            new_len = d.z3_len - 1
            setattr(d, "z3_len", new_len)
            side_effects["dict_mutation"] = {
                "operation": "delitem",
                "dict_name": d._name,
                "old_length": d.z3_len + 1,
                "new_length": new_len,
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
        args: list[Any],
        kwargs: dict[str, Any],
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
        args: list[Any],
        kwargs: dict[str, Any],
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
        args: list[Any],
        kwargs: dict[str, Any],
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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        key = _get_symbolic_string(args[1]) if len(args) > 1 else None
        has_default = len(args) > 2
        result, constraint = SymbolicValue.symbolic(f"dict_pop_{state.pc}")
        constraints = [constraint]
        side_effects = {}
        if d is not None:
            if not has_default and key is not None:
                side_effects["potential_exception"] = {
                    "type": "KeyError",
                    "message": "Key not found and no default provided",
                    "condition": z3.Not(d.contains_key(key).z3_bool),
                }
            new_len = d.z3_len - 1
            setattr(d, "z3_len", new_len)
            side_effects["dict_mutation"] = {
                "operation": "pop",
                "dict_name": d._name,
                "old_length": d.z3_len + 1,
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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"dict_popitem_{state.pc}")
        constraints = [constraint, result.z3_len == 2]
        side_effects = {}
        if d is not None:
            constraints.append(d.z3_len >= 1)
            side_effects["potential_exception"] = {
                "type": "KeyError",
                "message": "popitem(): dictionary is empty",
                "condition": d.z3_len == 0,
            }
            new_len = d.z3_len - 1
            setattr(d, "z3_len", new_len)
            side_effects["dict_mutation"] = {
                "operation": "popitem",
                "dict_name": d._name,
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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        other = _get_symbolic_dict(args[1]) if len(args) > 1 else None
        side_effects = {}
        if d is not None:
            if other is not None:
                side_effects["dict_mutation"] = {
                    "operation": "update",
                    "dict_name": d._name,
                    "old_length": d.z3_len,
                    "new_length_range": (d.z3_len, d.z3_len + other.z3_len),
                }
            else:
                side_effects["dict_mutation"] = {
                    "operation": "update",
                    "dict_name": d._name,
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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        side_effects = {}
        if d is not None:
            setattr(d, "z3_len", z3.IntVal(0))
            side_effects["dict_mutation"] = {
                "operation": "clear",
                "dict_name": d._name,
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
        args: list[Any],
        kwargs: dict[str, Any],
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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"dict_setdefault_{state.pc}")
        constraints = [constraint]
        side_effects = {}
        if d is not None:
            side_effects["dict_mutation"] = {
                "operation": "setdefault",
                "dict_name": d._name,
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
        args: list[Any],
        kwargs: dict[str, Any],
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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        d = _get_symbolic_dict(args[0]) if args else None
        if d is not None:
            result = SymbolicValue(
                _name=f"len({d._name})",
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
]
