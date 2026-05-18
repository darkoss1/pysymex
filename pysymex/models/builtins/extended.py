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

"""Extended builtin function models.

Contains models for less-commonly-used Python builtins:
iter, next, super, issubclass, globals, locals, dict, set, reversed,
all, any, ord, chr, pow, round, divmod, hasattr, getattr, setattr,
id, hash, callable, repr, format, input, open.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast
from collections.abc import Callable

import z3

from pysymex._typing import is_list_of_objects, is_tuple_of_objects

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState

from pysymex.core.types import (
    SymbolicNone,
    SymbolicObject,
    SymbolicValue,
)
from pysymex.core.types import (
    SymbolicDict,
    SymbolicList,
    SymbolicString,
)
from pysymex.core.solver.constraints import simplify_expr
from pysymex.core.solver.engine import is_satisfiable

from .base import FunctionModel, ModelResult, NoneResultFunctionModel, SideEffectValue


def _constructor_len_expr(value: object) -> z3.ArithRef | None:
    """Return the length expression for sequence constructors that preserve input length."""
    if isinstance(value, SymbolicList):
        return value.z3_len
    if isinstance(value, SymbolicValue):
        if isinstance(value.value, int):
            return value.z3_int
        payload: object = value.value
        if is_list_of_objects(payload) or is_tuple_of_objects(payload):
            return z3.IntVal(len(payload))
        if isinstance(payload, (bytes, bytearray)):
            return z3.IntVal(len(payload))
    if isinstance(value, int):
        return z3.IntVal(value)
    if is_list_of_objects(value) or is_tuple_of_objects(value):
        return z3.IntVal(len(value))
    if isinstance(value, (bytes, bytearray)):
        return z3.IntVal(len(value))
    return None


def _resolve_heap_object(value: object, state: VMState) -> object:
    if isinstance(value, SymbolicObject) and value.address != -1:
        resolved = state.memory.get(value.address)
        if resolved is not None:
            return resolved
    return value


def _must_be_none(value: SymbolicValue, constraints: list[z3.BoolRef]) -> bool:
    """Return whether current path constraints force a symbolic value to be None."""
    return not is_satisfiable([*constraints, z3.Not(value.is_none)])


def _type_error_side_effect(source: str, message: str) -> dict[str, SideEffectValue]:
    return {
        "raised_exception": {
            "issue_kind": "TYPE_ERROR",
            "exception_type": "TypeError",
            "message": message,
            "source": source,
        }
    }


def _known_iter_type_error(value: object) -> bool:
    if isinstance(value, (int, float, bool)) or value is None:
        return True
    if isinstance(value, SymbolicValue):
        return value.affinity_type in {"int", "float", "bool", "none", "NoneType"}
    return False


def _symbolic_builtin_has_attr(value: SymbolicValue, attr_name: str) -> bool | None:
    """Return attribute presence for concretely-typed symbolic builtins, else None."""
    probes: tuple[tuple[z3.BoolRef, object], ...] = (
        (value.is_int, 0),
        (value.is_bool, False),
        (value.is_float, 0.0),
        (value.is_str, ""),
    )
    for type_flag, probe_value in probes:
        if z3.is_true(simplify_expr(type_flag)):
            return hasattr(probe_value, attr_name)
    return None


def _enhanced_object_get_attribute(obj: object, attr_name: str) -> tuple[object, bool] | None:
    get_attribute = getattr(obj, "get_attribute", None)
    if not callable(get_attribute):
        return None
    typed_get_attribute = cast("Callable[[str], tuple[object, bool]]", get_attribute)
    value, found = typed_get_attribute(attr_name)
    return value, bool(found)


def _enhanced_object_has_dynamic_attribute_hook(obj: object) -> bool:
    enhanced_class = getattr(obj, "enhanced_class", None)
    if enhanced_class is None:
        return False
    get_method = getattr(enhanced_class, "get_method", None)
    if not callable(get_method):
        return False
    return get_method("__getattr__") is not None or get_method("__getattribute__") is not None


def _literal_string_value(value: StackValue) -> str | None:
    """Extract a concrete string from raw or symbolic string values."""
    if isinstance(value, str):
        return value
    if isinstance(value, SymbolicString):
        try:
            if not z3.is_string_value(value.z3_str):
                return None
            return value.z3_str.as_string()
        except (AttributeError, z3.Z3Exception):
            return None
    return None


class IterModel(FunctionModel):
    """Model for iter()."""

    name = "iter"
    qualname = "builtins.iter"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"iter_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        val = _resolve_heap_object(args[0], state)
        if isinstance(val, (str, SymbolicList, SymbolicString)):
            return ModelResult(value=val)
        if isinstance(val, (list, tuple)):
            return ModelResult(value=val)  # type: ignore[arg-type]  # val is StackValue, narrowed to list/tuple but still valid
        if _known_iter_type_error(val):
            result, constraint = SymbolicValue.symbolic(f"iter_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=_type_error_side_effect(
                    "builtins.iter",
                    f"'{getattr(val, 'type_tag', type(val).__name__)}' object is not iterable",
                ),
            )
        result, constraint = SymbolicValue.symbolic(f"iter_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class NextModel(FunctionModel):
    """Model for next()."""

    name = "next"
    qualname = "builtins.next"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if args:
            iterator = _resolve_heap_object(args[0], state)
            default = args[1] if len(args) > 1 else None
            if isinstance(iterator, SymbolicList):
                concrete_items = iterator.concrete_items
                if concrete_items:
                    return ModelResult(value=cast("StackValue", concrete_items[0]))
                if concrete_items == [] or (
                    z3.is_int_value(iterator.z3_len) and iterator.z3_len.as_long() == 0
                ):
                    if len(args) > 1:
                        return ModelResult(value=default)
                    result, constraint = SymbolicValue.symbolic(f"next_{state.pc}")
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects={
                            "raised_exception": {
                                "issue_kind": "UNHANDLED_EXCEPTION",
                                "exception_type": "StopIteration",
                                "message": "",
                                "source": "builtins.next",
                            }
                        },
                    )
            if isinstance(iterator, (list, tuple)):
                if iterator:
                    first = cast("list[StackValue] | tuple[StackValue, ...]", iterator)[0]
                    return ModelResult(value=first)
                if len(args) > 1:
                    return ModelResult(value=default)
                result, constraint = SymbolicValue.symbolic(f"next_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects={
                        "raised_exception": {
                            "issue_kind": "UNHANDLED_EXCEPTION",
                            "exception_type": "StopIteration",
                            "message": "",
                            "source": "builtins.next",
                        }
                    },
                )
        result, constraint = SymbolicValue.symbolic(f"next_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class SuperModel(FunctionModel):
    """Model for super()."""

    name = "super"
    qualname = "builtins.super"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"super_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class IssubclassModel(FunctionModel):
    """Model for issubclass()."""

    name = "issubclass"
    qualname = "builtins.issubclass"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"issubclass_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class GlobalsModel(FunctionModel):
    """Model for globals()."""

    name = "globals"
    qualname = "builtins.globals"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicDict.symbolic(f"globals_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class LocalsModel(FunctionModel):
    """Model for locals()."""

    name = "locals"
    qualname = "builtins.locals"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicDict.symbolic(f"locals_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class DictModel(FunctionModel):
    """Model for dict()."""

    name = "dict"
    qualname = "builtins.dict"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args and not kwargs:
            result, constraint = SymbolicDict.symbolic(f"dict_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        if kwargs and not args:
            result, constraint = SymbolicDict.symbolic(f"dict_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        result, constraint = SymbolicDict.symbolic(f"dict_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class SetModel(FunctionModel):
    """Model for set()."""

    name = "set"
    qualname = "builtins.set"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"set_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.z3_int == 0])
        val = args[0]
        if isinstance(val, (list, tuple, set)):
            result, constraint = SymbolicValue.symbolic(f"set_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.z3_int
                    == len(set(cast("list[object] | tuple[object, ...] | set[object]", val))),
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"set_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class ReversedModel(FunctionModel):
    """Model for reversed()."""

    name = "reversed"
    qualname = "builtins.reversed"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicList.symbolic(f"reversed_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        val = args[0]
        if isinstance(val, SymbolicList):
            result, constraint = SymbolicList.symbolic(f"reversed_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.z3_len == val.z3_len])
        if isinstance(val, (list, tuple, str)):
            return ModelResult(value=list(reversed(val)))  # type: ignore[arg-type]  # val is StackValue, narrowed but still valid for reversed
        result, constraint = SymbolicList.symbolic(f"reversed_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class AllModel(FunctionModel):
    """Model for all()."""

    name = "all"
    qualname = "builtins.all"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            return ModelResult(value=SymbolicValue.from_const(True))
        val = args[0]
        if isinstance(val, (list, tuple)):
            if not val:
                return ModelResult(value=SymbolicValue.from_const(True))
            val_seq: list[object] | tuple[object, ...] = cast(
                "list[object] | tuple[object, ...]", val
            )
            if all(isinstance(x, SymbolicValue) for x in val_seq):
                sv_list: list[SymbolicValue] = cast("list[SymbolicValue]", list(val_seq))
                conditions: list[z3.BoolRef] = [x.could_be_truthy() for x in sv_list]
                result, constraint = SymbolicValue.symbolic(f"all_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.is_bool, result.z3_bool == z3.And(*conditions)],
                )
            return ModelResult(value=SymbolicValue.from_const(all(val_seq)))
        result, constraint = SymbolicValue.symbolic(f"all_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class AnyModel(FunctionModel):
    """Model for any()."""

    name = "any"
    qualname = "builtins.any"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            return ModelResult(value=SymbolicValue.from_const(False))
        val = args[0]
        if isinstance(val, (list, tuple)):
            if not val:
                return ModelResult(value=SymbolicValue.from_const(False))
            val_seq: list[object] | tuple[object, ...] = cast(
                "list[object] | tuple[object, ...]", val
            )
            if all(isinstance(x, SymbolicValue) for x in val_seq):
                sv_list: list[SymbolicValue] = cast("list[SymbolicValue]", list(val_seq))
                conditions: list[z3.BoolRef] = [x.could_be_truthy() for x in sv_list]
                result, constraint = SymbolicValue.symbolic(f"any_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.is_bool, result.z3_bool == z3.Or(*conditions)],
                )
            return ModelResult(value=SymbolicValue.from_const(any(val_seq)))
        result, constraint = SymbolicValue.symbolic(f"any_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class OrdModel(FunctionModel):
    """Model for ord()."""

    name = "ord"
    qualname = "builtins.ord"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"ord_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.is_int])
        val = args[0]
        if isinstance(val, str) and len(val) == 1:
            return ModelResult(value=SymbolicValue.from_const(ord(val)))
        if isinstance(val, SymbolicString):
            result, constraint = SymbolicValue.symbolic(f"ord_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_int,
                    result.z3_int >= 0,
                    result.z3_int < 0x110000,
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"ord_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class ChrModel(FunctionModel):
    """Model for chr()."""

    name = "chr"
    qualname = "builtins.chr"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicString.symbolic(f"chr_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        val = args[0]
        if isinstance(val, int) and 0 <= val < 0x110000:
            return ModelResult(value=SymbolicString.from_const(chr(val)))
        if isinstance(val, SymbolicValue):
            result, constraint = SymbolicString.symbolic(f"chr_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    val.z3_int >= 0,
                    val.z3_int < 0x110000,
                    result.z3_len == 1,
                ],
            )
        result, constraint = SymbolicString.symbolic(f"chr_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_len == 1])


class PowModel(FunctionModel):
    """Model for pow()."""

    name = "pow"
    qualname = "builtins.pow"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) < 2:
            result, constraint = SymbolicValue.symbolic(f"pow_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        base: StackValue = args[0]
        exp: StackValue = args[1]
        mod: StackValue | None = args[2] if len(args) > 2 else None
        if isinstance(base, (int, float)) and isinstance(exp, (int, float)):
            if mod is not None and isinstance(mod, int):
                return ModelResult(
                    value=SymbolicValue.from_const(pow(cast("int", base), cast("int", exp), mod))
                )
            return ModelResult(value=SymbolicValue.from_const(pow(base, exp)))
        result, constraint = SymbolicValue.symbolic(f"pow_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class RoundModel(FunctionModel):
    """Model for round()."""

    name = "round"
    qualname = "builtins.round"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"round_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        val = args[0]
        ndigits: int | None = cast("int | None", args[1] if len(args) > 1 else None)
        if isinstance(val, (int, float)):
            rounded_result: int | float = round(val, ndigits)
            return ModelResult(value=rounded_result)
        result, constraint = SymbolicValue.symbolic(f"round_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class DivmodModel(FunctionModel):
    """Model for divmod()."""

    name = "divmod"
    qualname = "builtins.divmod"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) < 2:
            return ModelResult(value=(SymbolicValue.from_const(0), SymbolicValue.from_const(0)))
        a: StackValue = args[0]
        b: StackValue = args[1]
        if isinstance(a, (int, float)) and isinstance(b, (int, float)):
            q, r = divmod(a, b)
            return ModelResult(value=(SymbolicValue.from_const(q), SymbolicValue.from_const(r)))
        if isinstance(a, SymbolicValue) and isinstance(b, SymbolicValue):
            quotient, c1 = SymbolicValue.symbolic(f"divmod_q_{state.pc}")
            remainder, c2 = SymbolicValue.symbolic(f"divmod_r_{state.pc}")
            return ModelResult(
                value=(quotient, remainder),
                constraints=[
                    c1,
                    c2,
                    quotient.is_int,
                    remainder.is_int,
                    a.z3_int == b.z3_int * quotient.z3_int + remainder.z3_int,
                    z3.If(
                        b.z3_int > 0,
                        z3.And(remainder.z3_int >= 0, remainder.z3_int < b.z3_int),
                        z3.And(remainder.z3_int <= 0, remainder.z3_int > b.z3_int),
                    ),
                    b.z3_int != 0,
                ],
            )
        quotient, c1 = SymbolicValue.symbolic(f"divmod_q_{state.pc}")
        remainder, c2 = SymbolicValue.symbolic(f"divmod_r_{state.pc}")
        return ModelResult(value=(quotient, remainder), constraints=[c1, c2])


class HasattrModel(FunctionModel):
    """Model for hasattr()."""

    name = "hasattr"
    qualname = "builtins.hasattr"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) < 2:
            result, constraint = SymbolicValue.symbolic(f"hasattr_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.is_bool])
        obj: StackValue = args[0]
        name = _literal_string_value(args[1])
        if not isinstance(obj, SymbolicValue) and isinstance(name, str):
            return ModelResult(value=SymbolicValue.from_const(hasattr(obj, name)))
        result, constraint = SymbolicValue.symbolic(f"hasattr_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class GetattrModel(FunctionModel):
    """Model for getattr()."""

    name = "getattr"
    qualname = "builtins.getattr"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) < 2:
            result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        obj: StackValue = args[0]
        name = _literal_string_value(args[1])
        default: StackValue | None = args[2] if len(args) > 2 else None
        if not isinstance(obj, SymbolicValue) and isinstance(name, str):
            try:
                return ModelResult(value=getattr(obj, name))
            except AttributeError:
                if default is not None:
                    return ModelResult(value=default)
                result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
                side_effects: dict[str, SideEffectValue] = {
                    "raised_exception": {
                        "issue_kind": "ATTRIBUTE_ERROR",
                        "exception_type": "AttributeError",
                        "message": f"Attribute access '{name}' failed",
                        "source": "builtins.getattr",
                    }
                }
                return ModelResult(
                    value=result, constraints=[constraint], side_effects=side_effects
                )
        if default is None and isinstance(name, str):
            if obj is None or isinstance(obj, SymbolicNone):
                result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
                side_effects = {
                    "raised_exception": {
                        "issue_kind": "ATTRIBUTE_ERROR",
                        "exception_type": "AttributeError",
                        "message": f"Attribute access '{name}' on None",
                        "source": "builtins.getattr",
                    }
                }
                return ModelResult(
                    value=result, constraints=[constraint], side_effects=side_effects
                )
            if isinstance(obj, SymbolicValue) and _must_be_none(obj, list(state.path_constraints)):
                result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
                side_effects = {
                    "raised_exception": {
                        "issue_kind": "ATTRIBUTE_ERROR",
                        "exception_type": "AttributeError",
                        "message": f"Attribute access '{name}' on symbolic None",
                        "source": "builtins.getattr",
                    }
                }
                return ModelResult(
                    value=result, constraints=[constraint], side_effects=side_effects
                )
            if isinstance(obj, SymbolicValue):
                enhanced_obj = getattr(obj, "_enhanced_object", None)
                if enhanced_obj is not None:
                    enhanced_attr = _enhanced_object_get_attribute(enhanced_obj, name)
                    if enhanced_attr is not None:
                        attr_value, found = enhanced_attr
                        if found:
                            return ModelResult(value=cast("StackValue", attr_value))
                        if _enhanced_object_has_dynamic_attribute_hook(enhanced_obj):
                            result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
                            return ModelResult(value=result, constraints=[constraint])

                has_attr = _symbolic_builtin_has_attr(obj, name)
                if has_attr is False:
                    result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
                    side_effects = {
                        "raised_exception": {
                            "issue_kind": "ATTRIBUTE_ERROR",
                            "exception_type": "AttributeError",
                            "message": f"Attribute access '{name}' unsupported on symbolic builtin type",
                            "source": "builtins.getattr",
                        }
                    }
                    return ModelResult(
                        value=result, constraints=[constraint], side_effects=side_effects
                    )
                if not name.startswith("__"):
                    result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
                    side_effects = {
                        "raised_exception": {
                            "issue_kind": "ATTRIBUTE_ERROR",
                            "exception_type": "AttributeError",
                            "message": f"Attribute access '{name}' may fail on symbolic receiver",
                            "source": "builtins.getattr",
                        }
                    }
                    return ModelResult(
                        value=result, constraints=[constraint], side_effects=side_effects
                    )
        result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class SetattrModel(FunctionModel):
    """Model for setattr()."""

    name = "setattr"
    qualname = "builtins.setattr"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        side_effects: dict[str, SideEffectValue] = {"mutates_arg": 0}
        if len(args) >= 2:
            obj = args[0]
            attr_name = args[1]
            attr_name_str = _literal_string_value(attr_name) or "<dynamic>"
            if obj is None or isinstance(obj, SymbolicNone):
                side_effects["raised_exception"] = {
                    "issue_kind": "ATTRIBUTE_ERROR",
                    "exception_type": "AttributeError",
                    "message": f"Cannot set attribute '{attr_name_str}' on None",
                    "source": "builtins.setattr",
                }
                return ModelResult(value=SymbolicNone("none"), side_effects=side_effects)
            if isinstance(obj, SymbolicValue) and _must_be_none(obj, list(state.path_constraints)):
                side_effects["raised_exception"] = {
                    "issue_kind": "ATTRIBUTE_ERROR",
                    "exception_type": "AttributeError",
                    "message": f"Cannot set attribute '{attr_name_str}' on symbolic None",
                    "source": "builtins.setattr",
                }
                return ModelResult(value=SymbolicNone("none"), side_effects=side_effects)
            if isinstance(obj, SymbolicValue) and is_satisfiable(
                [*list(state.path_constraints), obj.is_none]
            ):
                side_effects["raised_exception"] = {
                    "issue_kind": "ATTRIBUTE_ERROR",
                    "exception_type": "AttributeError",
                    "message": f"Cannot safely set attribute '{attr_name_str}' when receiver may be None",
                    "source": "builtins.setattr",
                }
                return ModelResult(value=SymbolicNone("none"), side_effects=side_effects)
            if isinstance(obj, SymbolicValue):
                side_effects["raised_exception"] = {
                    "issue_kind": "ATTRIBUTE_ERROR",
                    "exception_type": "AttributeError",
                    "message": f"Cannot prove setattr target is valid for attribute '{attr_name_str}'",
                    "source": "builtins.setattr",
                }
                return ModelResult(value=SymbolicNone("none"), side_effects=side_effects)
            if not isinstance(obj, SymbolicValue) and isinstance(attr_name, str):
                if len(args) >= 3:
                    try:
                        setattr(obj, attr_name, args[2])
                        side_effects["attribute_mutation"] = {
                            "target_index": 0,
                            "attr_name": attr_name,
                            "status": "applied",
                            "source": "builtins.setattr",
                        }
                    except (AttributeError, TypeError) as exc:
                        side_effects["raised_exception"] = {
                            "issue_kind": "ATTRIBUTE_ERROR",
                            "exception_type": type(exc).__name__,
                            "message": str(exc),
                            "source": "builtins.setattr",
                        }
        return ModelResult(value=SymbolicNone("none"), side_effects=side_effects)


class DelattrModel(FunctionModel):
    """Model for delattr()."""

    name = "delattr"
    qualname = "builtins.delattr"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return ModelResult(value=SymbolicNone("none"), side_effects={"mutates_arg": 0})


class AiterModel(FunctionModel):
    """Model for aiter() - async iterator."""

    name = "aiter"
    qualname = "builtins.aiter"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"aiter_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        result, constraint = SymbolicValue.symbolic(f"aiter_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class AnextModel(FunctionModel):
    """Model for anext() - async next."""

    name = "anext"
    qualname = "builtins.anext"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"anext_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        result, constraint = SymbolicValue.symbolic(f"anext_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class IdModel(FunctionModel):
    """Model for id()."""

    name = "id"
    qualname = "builtins.id"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if args:
            result, constraint = SymbolicValue.symbolic(f"id_{state.pc}")
            return ModelResult(
                value=result, constraints=[constraint, result.is_int, result.z3_int >= 0]
            )
        result, constraint = SymbolicValue.symbolic(f"id_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class HashModel(FunctionModel):
    """Model for hash()."""

    name = "hash"
    qualname = "builtins.hash"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if args:
            obj: StackValue = args[0]
            if isinstance(obj, (int, str, float, tuple, frozenset, type(None))):
                return ModelResult(
                    value=SymbolicValue.from_const(
                        hash(
                            cast(
                                "int | str | float | tuple[object, ...] | frozenset[object] | None",
                                obj,
                            )
                        )
                    )
                )
        result, constraint = SymbolicValue.symbolic(f"hash_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class CallableModel(FunctionModel):
    """Model for callable()."""

    name = "callable"
    qualname = "builtins.callable"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if args:
            obj: StackValue = args[0]
            if not isinstance(obj, SymbolicValue):
                return ModelResult(value=SymbolicValue.from_const(callable(obj)))
        result, constraint = SymbolicValue.symbolic(f"callable_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class ReprModel(FunctionModel):
    """Model for repr()."""

    name = "repr"
    qualname = "builtins.repr"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if args:
            obj: StackValue = args[0]
            if not isinstance(obj, SymbolicValue):
                return ModelResult(value=SymbolicString.from_const(repr(obj)))
        result, constraint = SymbolicString.symbolic(f"repr_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class FormatModel(FunctionModel):
    """Model for format()."""

    name = "format"
    qualname = "builtins.format"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if args:
            obj: StackValue = args[0]
            spec: StackValue = args[1] if len(args) > 1 else ""
            if not isinstance(obj, SymbolicValue) and isinstance(spec, str):
                return ModelResult(value=SymbolicString.from_const(format(obj, spec)))
        result, constraint = SymbolicString.symbolic(f"format_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class InputModel(FunctionModel):
    """Model for input()."""

    name = "input"
    qualname = "builtins.input"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"input_{state.pc}")
        return ModelResult(value=result, constraints=[constraint], side_effects={"io": True})


class OpenModel(FunctionModel):
    """Model for open()."""

    name = "open"
    qualname = "builtins.open"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"file_{state.pc}")
        result.is_none = z3.BoolVal(False)
        result.is_obj = z3.BoolVal(True)
        result.affinity_type = "file"
        return ModelResult(value=result, constraints=[constraint], side_effects={"io": True})


class ExecModel(FunctionModel):
    """Model for exec() - code injection sink."""

    name = "exec"
    qualname = "builtins.exec"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        sink_severity = "info"
        if args:
            code_arg: StackValue = args[0]
            if isinstance(code_arg, (SymbolicString, SymbolicValue)):
                sink_severity = "critical"
        side_effects: dict[str, SideEffectValue] = {
            "sink_event": {
                "sink_type": "exec",
                "severity": sink_severity,
                "source": "builtins.exec",
            },
        }
        return ModelResult(
            value=SymbolicNone(),
            side_effects=side_effects,
        )


class EvalModel(FunctionModel):
    """Model for eval() - code injection sink."""

    name = "eval"
    qualname = "builtins.eval"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        sink_severity = "info"
        if args:
            code_arg: StackValue = args[0]
            if isinstance(code_arg, (SymbolicString, SymbolicValue)):
                sink_severity = "critical"
        side_effects: dict[str, SideEffectValue] = {
            "sink_event": {
                "sink_type": "eval",
                "severity": sink_severity,
                "source": "builtins.eval",
            },
        }
        result, constraint = SymbolicValue.symbolic(f"eval_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            side_effects=side_effects,
        )


class CompileModel(FunctionModel):
    """Model for compile()."""

    name = "compile"
    qualname = "builtins.compile"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        sink_severity = (
            "critical" if args and isinstance(args[0], (SymbolicString, SymbolicValue)) else "info"
        )
        side_effects: dict[str, SideEffectValue] = {
            "sink_event": {
                "sink_type": "compile",
                "severity": sink_severity,
                "source": "builtins.compile",
            }
        }
        result, constraint = SymbolicValue.symbolic(f"code_{state.pc}")
        return ModelResult(value=result, constraints=[constraint], side_effects=side_effects)


class BinModel(FunctionModel):
    """Model for bin()."""

    name = "bin"
    qualname = "builtins.bin"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"bin_{state.pc}")
        constraints: list[z3.BoolRef] = [constraint]
        if args:
            val: z3.ArithRef | None = getattr(args[0], "z3_int", None)
            if val is not None:
                constraints.append(result.z3_len >= 3)
        return ModelResult(value=result, constraints=constraints)


class OctModel(FunctionModel):
    """Model for oct()."""

    name = "oct"
    qualname = "builtins.oct"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"oct_{state.pc}")
        constraints: list[z3.BoolRef] = [constraint]
        if args:
            val: z3.ArithRef | None = getattr(args[0], "z3_int", None)
            if val is not None:
                constraints.append(result.z3_len >= 3)
        return ModelResult(value=result, constraints=constraints)


class HexModel(FunctionModel):
    """Model for hex()."""

    name = "hex"
    qualname = "builtins.hex"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"hex_{state.pc}")
        constraints: list[z3.BoolRef] = [constraint]
        if args:
            val: z3.ArithRef | None = getattr(args[0], "z3_int", None)
            if val is not None:
                constraints.append(result.z3_len >= 3)
        return ModelResult(value=result, constraints=constraints)


class BytesModel(FunctionModel):
    """Model for bytes() constructor."""

    name = "bytes"
    qualname = "builtins.bytes"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"bytes_{state.pc}")
        constraints: list[z3.BoolRef] = [constraint]
        if not args:
            constraints.append(result.z3_len == 0)
        elif args:
            val = _constructor_len_expr(_resolve_heap_object(args[0], state))
            if val is not None:
                constraints.append(result.z3_len == val)
                constraints.append(val >= 0)
        return ModelResult(value=result, constraints=constraints)


class BytearrayModel(FunctionModel):
    """Model for bytearray() constructor."""

    name = "bytearray"
    qualname = "builtins.bytearray"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"bytearray_{state.pc}")
        constraints: list[z3.BoolRef] = [constraint]
        if not args:
            constraints.append(result.z3_len == 0)
        elif args:
            val = _constructor_len_expr(_resolve_heap_object(args[0], state))
            if val is not None:
                constraints.append(result.z3_len == val)
                constraints.append(val >= 0)
        return ModelResult(value=result, constraints=constraints)


class FrozensetModel(FunctionModel):
    """Model for frozenset() constructor."""

    name = "frozenset"
    qualname = "builtins.frozenset"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"frozenset_{state.pc}")
        setattr(result, "_type", "frozenset")
        constraints: list[z3.BoolRef] = [constraint]
        if not args:
            constraints.append(result.z3_len == 0)
        return ModelResult(value=result, constraints=constraints)


class MemoryviewModel(FunctionModel):
    """Model for memoryview()."""

    name = "memoryview"
    qualname = "builtins.memoryview"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"memoryview_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class ObjectModel(FunctionModel):
    """Model for object()."""

    name = "object"
    qualname = "builtins.object"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"object_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class PropertyModel(FunctionModel):
    """Model for property()."""

    name = "property"
    qualname = "builtins.property"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"property_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class ClassmethodModel(FunctionModel):
    """Model for classmethod()."""

    name = "classmethod"
    qualname = "builtins.classmethod"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return ModelResult(value=args[0] if args else SymbolicNone())


class StaticmethodModel(FunctionModel):
    """Model for staticmethod()."""

    name = "staticmethod"
    qualname = "builtins.staticmethod"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return ModelResult(value=args[0] if args else SymbolicNone())


class VarsModel(FunctionModel):
    """Model for vars()."""

    name = "vars"
    qualname = "builtins.vars"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicDict.symbolic(f"vars_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class DirModel(FunctionModel):
    """Model for dir()."""

    name = "dir"
    qualname = "builtins.dir"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"dir_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class AsciiModel(FunctionModel):
    """Model for ascii()."""

    name = "ascii"
    qualname = "builtins.ascii"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"ascii_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class BreakpointModel(NoneResultFunctionModel):
    """Model for breakpoint()."""

    name = "breakpoint"
    qualname = "builtins.breakpoint"


class __import__Model(FunctionModel):
    """Model for __import__()."""

    name = "__import__"
    qualname = "builtins.__import__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"import_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class MemoryviewTobytesModel(FunctionModel):
    name = "tobytes"
    qualname = "memoryview.tobytes"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"tobytes_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class MemoryviewTolistModel(FunctionModel):
    name = "tolist"
    qualname = "memoryview.tolist"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"tolist_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_len == 0])


class MemoryviewHexModel(FunctionModel):
    name = "hex"
    qualname = "memoryview.hex"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"hex_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class MemoryviewReleaseModel(FunctionModel):
    name = "release"
    qualname = "memoryview.release"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return ModelResult(value=None, constraints=[])


class MemoryviewCastModel(FunctionModel):
    name = "cast"
    qualname = "memoryview.cast"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            return ModelResult(value=None, constraints=[])
        return ModelResult(value=args[0], constraints=[])


class ComplexRealModel(FunctionModel):
    name = "real"
    qualname = "complex.real"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            return ModelResult(0.0, [], {})
        return ModelResult(args[0], [], {})


class ComplexImagModel(FunctionModel):
    name = "imag"
    qualname = "complex.imag"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return ModelResult(0.0, [], {})


class ComplexConjugateModel(FunctionModel):
    name = "conjugate"
    qualname = "complex.conjugate"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            return ModelResult(0.0, [], {})
        return ModelResult(args[0], [], {})


EXTENDED_MODELS = [
    AllModel(),
    AnyModel(),
    AsciiModel(),
    BreakpointModel(),
    BinModel(),
    BytearrayModel(),
    BytesModel(),
    CallableModel(),
    ChrModel(),
    ClassmethodModel(),
    CompileModel(),
    DelattrModel(),
    DictModel(),
    DirModel(),
    DivmodModel(),
    EvalModel(),
    ExecModel(),
    FormatModel(),
    FrozensetModel(),
    GetattrModel(),
    GlobalsModel(),
    HasattrModel(),
    HashModel(),
    HexModel(),
    IdModel(),
    InputModel(),
    IssubclassModel(),
    IterModel(),
    LocalsModel(),
    MemoryviewModel(),
    NextModel(),
    ObjectModel(),
    OctModel(),
    OpenModel(),
    OrdModel(),
    PowModel(),
    PropertyModel(),
    ReprModel(),
    ReversedModel(),
    RoundModel(),
    SetattrModel(),
    SetModel(),
    StaticmethodModel(),
    SuperModel(),
    VarsModel(),
    __import__Model(),
    AiterModel(),
    AnextModel(),
    MemoryviewTobytesModel(),
    MemoryviewTolistModel(),
    MemoryviewHexModel(),
    MemoryviewReleaseModel(),
    MemoryviewCastModel(),
    ComplexRealModel(),
    ComplexImagModel(),
    ComplexConjugateModel(),
]
