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

"""Core builtin function models.

Contains models for the most commonly used Python builtins:
len, range, abs, min, max, int, str, bool, print, type, isinstance,
sorted, sum, enumerate, zip, map, filter, float, list, tuple, None.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, cast

import z3

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState

from pysymex._typing import (
    is_list_of_objects,
    is_tuple_of_objects,
)

from pysymex.core.types import (
    SymbolicNone,
    SymbolicObject,
    SymbolicString,
    SymbolicType,
    SymbolicValue,
)
from pysymex.core.types import SymbolicDict, SymbolicList
from pysymex.models.typed_results import (
    model_bool_result,
    model_int_result,
    symbolic_bool_result,
    symbolic_int_result,
)

from .base import FunctionModel, ModelResult, NoneResultFunctionModel


def _safe_min_concrete(values: Sequence[StackValue]) -> StackValue:
    if all(isinstance(x, (int, float, bool)) for x in values):
        return min(cast("Sequence[int | float | bool]", values))
    if all(isinstance(x, str) for x in values):
        return min(cast("Sequence[str]", values))
    if all(isinstance(x, bytes) for x in values):
        return min(cast("Sequence[bytes]", values))
    return None


def _safe_max_concrete(values: Sequence[StackValue]) -> StackValue:
    if all(isinstance(x, (int, float, bool)) for x in values):
        return max(cast("Sequence[int | float | bool]", values))
    if all(isinstance(x, str) for x in values):
        return max(cast("Sequence[str]", values))
    if all(isinstance(x, bytes) for x in values):
        return max(cast("Sequence[bytes]", values))
    return None


def _value_error_side_effect(source: str, message: str) -> dict[str, object]:
    return {
        "raised_exception": {
            "issue_kind": "VALUE_ERROR",
            "exception_type": "ValueError",
            "message": message,
            "source": source,
        }
    }


def _type_error_side_effect(source: str, message: str) -> dict[str, object]:
    return {
        "raised_exception": {
            "issue_kind": "TYPE_ERROR",
            "exception_type": "TypeError",
            "message": message,
            "source": source,
        }
    }


def _symbolic_list_len_is_zero(value: SymbolicList) -> bool:
    return z3.is_true(z3.simplify(value.z3_len == 0))


def _known_len_type_error(value: object) -> bool:
    if isinstance(value, (int, float, bool)) or value is None:
        return True
    if isinstance(value, SymbolicValue):
        if "[" in value.name or "]" in value.name:
            return False
        return value.affinity_type in {"int", "float", "bool", "none", "NoneType"}
    return False


def _resolve_heap_object(value: object, state: VMState) -> object:
    if isinstance(value, SymbolicObject) and value.address != -1:
        resolved = state.memory.get(value.address)
        if resolved is not None:
            return resolved
    return value


def _safe_sum_concrete(values: Sequence[StackValue], start: StackValue) -> StackValue:
    if not isinstance(start, (int, float, bool)):
        return None
    if not all(isinstance(x, (int, float, bool)) for x in values):
        return None
    numeric_values = cast("Sequence[int | float | bool]", values)
    return sum(numeric_values, start)


def _constant_len(value: object) -> int | None:
    """Return CPython length for concrete payloads, including symbolic constants."""
    if isinstance(value, SymbolicValue):
        value = value.value
    if isinstance(value, (str, bytes, range)):
        return len(value)
    if is_list_of_objects(value) or is_tuple_of_objects(value):
        return len(value)
    if isinstance(value, dict):
        return len(cast("dict[object, object]", value))
    if isinstance(value, (set, frozenset)):
        return len(cast("set[object] | frozenset[object]", value))
    return None


class LenModel(FunctionModel):
    """Model for len()."""

    name = "len"
    qualname = "builtins.len"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply len() model."""
        if not args:
            return ModelResult(SymbolicValue.symbolic(f"len_{state.pc}")[0])
        obj = _resolve_heap_object(args[0], state)
        concrete_len = _constant_len(obj)
        if concrete_len is not None:
            return ModelResult(value=concrete_len)
        if _known_len_type_error(obj):
            result, constraint = SymbolicValue.symbolic(f"len_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=_type_error_side_effect(
                    "builtins.len",
                    f"object of type '{getattr(obj, 'type_tag', type(obj).__name__)}' has no len()",
                ),
            )
        if isinstance(obj, SymbolicList):
            result, constraints = symbolic_int_result(f"len_{obj.name}")
            constraints.extend([result.z3_int == obj.z3_len, result.z3_int >= 0])
            return ModelResult(
                value=result,
                constraints=constraints,
            )
        if isinstance(obj, SymbolicString):
            result, constraints = symbolic_int_result(f"len_{obj.name}")
            constraints.extend([result.z3_int == obj.z3_len, result.z3_int >= 0])
            return ModelResult(
                value=result,
                constraints=constraints,
            )
        if (
            getattr(obj, "_type", "") == "set"
            or "set" in getattr(obj, "_name", "").lower()
            or getattr(obj, "type_tag", "") == "dict"
            or isinstance(obj, SymbolicDict)
        ):
            z3_len = getattr(obj, "z3_len", getattr(obj, "z3_int", None))
            if z3_len is not None:
                result, constraints = symbolic_int_result(
                    f"len_{getattr(obj, '_name', 'container')}"
                )
                constraints.append(result.z3_int == z3_len)
                return ModelResult(
                    value=result,
                    constraints=constraints,
                )
        result, base_constraints = symbolic_int_result(f"len_{state.pc}")
        extra_constraints: list[z3.ExprRef | z3.BoolRef] = [
            *base_constraints,
            result.z3_int >= 0,
        ]

        if isinstance(obj, SymbolicValue):
            extra_constraints.append(z3.Implies(obj.could_be_truthy(), result.z3_int > 0))
            extra_constraints.append(z3.Implies(obj.could_be_falsy(), result.z3_int == 0))
        return ModelResult(
            value=result,
            constraints=extra_constraints,
        )


class RangeModel(FunctionModel):
    """Model for range()."""

    name = "range"
    qualname = "builtins.range"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply range() model."""

        def _const_int(value: StackValue) -> int | None:
            if isinstance(value, int):
                return value
            if isinstance(value, SymbolicValue) and isinstance(value.value, int):
                return value.value
            return None

        def _bounded_range_entries(
            range_args: list[StackValue],
        ) -> tuple[int, tuple[int, ...]] | None:
            concrete_values = [_const_int(arg) for arg in range_args]
            if any(value is None for value in concrete_values):
                return None

            values = [value for value in concrete_values if value is not None]
            if len(values) == 1:
                seq = tuple(range(values[0]))
            elif len(values) == 2:
                seq = tuple(range(values[0], values[1]))
            elif len(values) >= 3:
                seq = tuple(range(values[0], values[1], values[2]))
            else:
                return None
            return len(seq), seq

        bounded_entries = _bounded_range_entries(args)
        if bounded_entries is not None and bounded_entries[0] <= 10:
            _, entries = bounded_entries
            return ModelResult(value=SymbolicList.from_const(list(entries)))

        result, constraint = SymbolicList.symbolic(f"range_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        if bounded_entries is not None:
            _, entries = bounded_entries
            setattr(result, "_concrete_items", list(entries))

        if len(args) == 1 and isinstance(args[0], SymbolicValue):
            stop = args[0]
            constraints.append(result.z3_len == z3.If(stop.z3_int > 0, stop.z3_int, 0))
        elif len(args) >= 2:
            start = (
                args[0] if isinstance(args[0], SymbolicValue) else SymbolicValue.from_const(args[0])
            )
            stop = (
                args[1] if isinstance(args[1], SymbolicValue) else SymbolicValue.from_const(args[1])
            )
            if len(args) >= 3:
                step = (
                    args[2]
                    if isinstance(args[2], SymbolicValue)
                    else SymbolicValue.from_const(args[2])
                )
                diff = stop.z3_int - start.z3_int

                abs_diff = z3.If(diff * step.z3_int > 0, diff, z3.IntVal(0))
                abs_step = z3.If(step.z3_int > 0, step.z3_int, -step.z3_int)
                length = z3.If(abs_step == 0, z3.IntVal(0), (abs_diff + abs_step - 1) / abs_step)
                constraints.append(result.z3_len == z3.If(length > 0, length, z3.IntVal(0)))

                i = z3.Int(f"range_idx_{state.pc}")
                if bounded_entries is not None and bounded_entries[0] <= 10:
                    _, entries = bounded_entries
                    for idx, value in enumerate(entries):
                        constraints.append(
                            z3.Select(result.z3_array, z3.IntVal(idx)) == z3.IntVal(value)
                        )
                else:
                    constraints.append(
                        result.z3_array == z3.Lambda([i], start.z3_int + i * step.z3_int)
                    )
            else:
                length = z3.If(stop.z3_int > start.z3_int, stop.z3_int - start.z3_int, 0)
                constraints.append(result.z3_len == length)

                i = z3.Int(f"range_idx_{state.pc}")
                if bounded_entries is not None and bounded_entries[0] <= 10:
                    _, entries = bounded_entries
                    for idx, value in enumerate(entries):
                        constraints.append(
                            z3.Select(result.z3_array, z3.IntVal(idx)) == z3.IntVal(value)
                        )
                else:
                    constraints.append(result.z3_array == z3.Lambda([i], start.z3_int + i))
        if len(args) == 1 and isinstance(args[0], SymbolicValue):
            stop = args[0]
            length = z3.If(stop.z3_int > 0, stop.z3_int, 0)
            constraints.append(result.z3_len == length)
            i = z3.Int(f"range_idx_{state.pc}")
            constraints.append(result.z3_array == z3.Lambda([i], i))
        elif len(args) == 1:
            stop_val = _const_int(args[0])
            if stop_val is not None:
                entries = tuple(range(stop_val))
                constraints.append(result.z3_len == z3.IntVal(len(entries)))
                if len(entries) <= 10:
                    for idx, value in enumerate(entries):
                        constraints.append(
                            z3.Select(result.z3_array, z3.IntVal(idx)) == z3.IntVal(value)
                        )
                else:
                    i = z3.Int(f"range_idx_{state.pc}")
                    constraints.append(result.z3_array == z3.Lambda([i], i))
        return ModelResult(value=result, constraints=constraints)


class AbsModel(FunctionModel):
    """Model for abs()."""

    name = "abs"
    qualname = "builtins.abs"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply abs() model."""
        if not args:
            return ModelResult(SymbolicValue.symbolic(f"abs_{state.pc}")[0])
        x = args[0]
        if isinstance(x, SymbolicValue):
            result, constraints = symbolic_int_result(f"abs_{x.name}")
            constraints.append(result.z3_int == z3.If(x.z3_int >= 0, x.z3_int, -x.z3_int))
            return ModelResult(
                value=result,
                constraints=constraints,
            )
        if isinstance(x, (int, float, bool)):
            return ModelResult(value=abs(x))
        return ModelResult(value=SymbolicValue.symbolic(f"abs_{state.pc}")[0])


class MinModel(FunctionModel):
    """Model for min()."""

    name = "min"
    qualname = "builtins.min"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply min() model."""
        if not args:
            return ModelResult(SymbolicValue.symbolic(f"min_{state.pc}")[0])

        first_arg = _resolve_heap_object(args[0], state) if len(args) == 1 else args[0]
        has_default = "default" in kwargs

        if (
            len(args) == 1
            and isinstance(first_arg, SymbolicList)
            and _symbolic_list_len_is_zero(first_arg)
        ):
            if has_default:
                return ModelResult(value=kwargs["default"])
            result, constraint = SymbolicValue.symbolic(f"min_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=_value_error_side_effect(
                    "builtins.min", "min() arg is an empty sequence"
                ),
            )
        if len(args) == 1 and is_list_of_objects(first_arg):
            seq = first_arg
            if not seq:
                if has_default:
                    return ModelResult(value=kwargs["default"])
                result, constraint = SymbolicValue.symbolic(f"min_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=_value_error_side_effect(
                        "builtins.min", "min() arg is an empty sequence"
                    ),
                )
            if all(
                not isinstance(x, (SymbolicValue, SymbolicType)) for x in seq
            ):  # x is object from list[object]
                concrete_min = _safe_min_concrete(cast("Sequence[StackValue]", seq))
                if concrete_min is not None:
                    return ModelResult(value=concrete_min)
        elif len(args) == 1 and is_tuple_of_objects(first_arg):
            seq = first_arg
            if not seq:
                if has_default:
                    return ModelResult(value=kwargs["default"])
                result, constraint = SymbolicValue.symbolic(f"min_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=_value_error_side_effect(
                        "builtins.min", "min() arg is an empty sequence"
                    ),
                )
            if all(
                not isinstance(x, (SymbolicValue, SymbolicType)) for x in seq
            ):  # x is object from tuple[object, ...]
                concrete_min = _safe_min_concrete(cast("Sequence[StackValue]", seq))
                if concrete_min is not None:
                    return ModelResult(value=concrete_min)
            result, constraint = SymbolicValue.symbolic(f"min_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])

        if len(args) >= 2:
            if all(not isinstance(x, (SymbolicValue, SymbolicType)) for x in args):
                concrete_min = _safe_min_concrete(cast("Sequence[StackValue]", args))
                if concrete_min is not None:
                    return ModelResult(value=concrete_min)

            sym_args = [
                arg if isinstance(arg, SymbolicValue) else SymbolicValue.from_const(arg)
                for arg in args
            ]

            result, constraints = symbolic_int_result(f"min_{state.pc}")

            expr = sym_args[0].z3_int
            for i in range(1, len(sym_args)):
                expr = z3.If(sym_args[i].z3_int < expr, sym_args[i].z3_int, expr)

            constraints.append(result.z3_int == expr)
            return ModelResult(
                value=result,
                constraints=constraints,
            )

        result, constraint = SymbolicValue.symbolic(f"min_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class MaxModel(FunctionModel):
    """Model for max()."""

    name = "max"
    qualname = "builtins.max"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply max() model."""
        if not args:
            return ModelResult(SymbolicValue.symbolic(f"max_{state.pc}")[0])

        first_arg = _resolve_heap_object(args[0], state) if len(args) == 1 else args[0]
        has_default = "default" in kwargs

        if (
            len(args) == 1
            and isinstance(first_arg, SymbolicList)
            and _symbolic_list_len_is_zero(first_arg)
        ):
            if has_default:
                return ModelResult(value=kwargs["default"])
            result, constraint = SymbolicValue.symbolic(f"max_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=_value_error_side_effect(
                    "builtins.max", "max() arg is an empty sequence"
                ),
            )
        if len(args) == 1 and is_list_of_objects(first_arg):
            seq = first_arg
            if not seq:
                if has_default:
                    return ModelResult(value=kwargs["default"])
                result, constraint = SymbolicValue.symbolic(f"max_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=_value_error_side_effect(
                        "builtins.max", "max() arg is an empty sequence"
                    ),
                )
            if all(not isinstance(x, (SymbolicValue, SymbolicType)) for x in seq):
                concrete_max = _safe_max_concrete(cast("Sequence[StackValue]", seq))
                if concrete_max is not None:
                    return ModelResult(value=concrete_max)
        elif len(args) == 1 and is_tuple_of_objects(first_arg):
            seq = first_arg
            if not seq:
                if has_default:
                    return ModelResult(value=kwargs["default"])
                result, constraint = SymbolicValue.symbolic(f"max_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=_value_error_side_effect(
                        "builtins.max", "max() arg is an empty sequence"
                    ),
                )
            if all(not isinstance(x, (SymbolicValue, SymbolicType)) for x in seq):
                concrete_max = _safe_max_concrete(cast("Sequence[StackValue]", seq))
                if concrete_max is not None:
                    return ModelResult(value=concrete_max)
            result, constraint = SymbolicValue.symbolic(f"max_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])

        if len(args) >= 2:
            if all(not isinstance(x, (SymbolicValue, SymbolicType)) for x in args):
                concrete_max = _safe_max_concrete(cast("Sequence[StackValue]", args))
                if concrete_max is not None:
                    return ModelResult(value=concrete_max)

            sym_args = [
                arg if isinstance(arg, SymbolicValue) else SymbolicValue.from_const(arg)
                for arg in args
            ]

            result, constraints = symbolic_int_result(f"max_{state.pc}")
            expr = sym_args[0].z3_int
            for i in range(1, len(sym_args)):
                expr = z3.If(sym_args[i].z3_int > expr, sym_args[i].z3_int, expr)

            constraints.append(result.z3_int == expr)
            return ModelResult(
                value=result,
                constraints=constraints,
            )

        result, constraint = SymbolicValue.symbolic(f"max_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class IntModel(FunctionModel):
    """Model for int()."""

    name = "int"
    qualname = "builtins.int"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply int() model."""
        if not args:
            return ModelResult(value=0)
        x = args[0]
        if isinstance(x, SymbolicValue):
            result, constraints = symbolic_int_result(f"int_{x.name}")
            constraints.append(result.z3_int == x.z3_int)
            return ModelResult(
                value=result,
                constraints=constraints,
            )
        if isinstance(x, SymbolicString):
            result, constraints = symbolic_int_result(f"int_{x.name}")
            constraints.append(result.z3_int == z3.StrToInt(x.z3_str))
            return ModelResult(
                value=result,
                constraints=constraints,
            )
        if isinstance(x, (int, bool, float, str, bytes)):
            try:
                return ModelResult(value=int(x))
            except (TypeError, ValueError):
                pass
        result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class StrModel(FunctionModel):
    """Model for str()."""

    name = "str"
    qualname = "builtins.str"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply str() model."""
        if not args:
            return ModelResult(value="")
        x = args[0]
        if isinstance(x, SymbolicValue):
            z3_expr = z3.If(
                x.is_int,
                x.z3_int,
                z3.If(x.is_bool, z3.If(x.z3_bool, z3.IntVal(1), z3.IntVal(0)), z3.IntVal(0)),
            )
            z3_str_expr = z3.If(
                z3_expr < 0, z3.Concat("-", z3.IntToStr(-z3_expr)), z3.IntToStr(z3_expr)
            )

            result, constraint = SymbolicString.symbolic(f"str_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.z3_str == z3_str_expr,
                ],
            )
        try:
            return ModelResult(value=str(x))
        except (TypeError, RecursionError):
            result, constraint = SymbolicString.symbolic(f"str_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])


class BoolModel(FunctionModel):
    """Model for bool()."""

    name = "bool"
    qualname = "builtins.bool"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply bool() model."""
        if not args:
            return ModelResult(value=False)
        x = args[0]
        if isinstance(x, SymbolicValue):
            result, constraints = symbolic_bool_result(f"bool_{x.name}")
            constraints.append(
                result.z3_bool
                == z3.If(
                    x.is_int,
                    x.z3_int != 0,
                    x.z3_bool,
                )
            )
            return ModelResult(
                value=result,
                constraints=constraints,
            )
        try:
            return ModelResult(value=bool(x))
        except (TypeError, ValueError, RecursionError):
            return model_bool_result(f"bool_{state.pc}")


class PrintModel(NoneResultFunctionModel):
    """Model for print() - side effect only."""

    name = "print"
    qualname = "builtins.print"


class TypeModel(FunctionModel):
    """Model for type()."""

    name = "type"
    qualname = "builtins.type"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            return ModelResult(value=type)
        result, constraint = SymbolicValue.symbolic(f"type_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class IsinstanceModel(FunctionModel):
    """Model for isinstance()."""

    name = "isinstance"
    qualname = "builtins.isinstance"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) < 2:
            return ModelResult(value=False)
        obj, types = args[0], args[1]

        # Determine the target Z3 constraint for the type check
        type_expr = None
        if isinstance(obj, SymbolicValue):
            if types is int:
                type_expr = obj.is_int
            elif types is bool:
                type_expr = obj.is_bool
            elif types is str:
                type_expr = obj.is_str
            elif types is float:
                type_expr = obj.is_float
            elif types is list:
                type_expr = obj.is_list
            elif types is dict:
                type_expr = obj.is_dict

        if type_expr is not None:
            # We return a new symbolic boolean, but we tie its truth value
            # EXACTLY to the type constraint of the object.
            obj_name = str(getattr(obj, "name")) if hasattr(obj, "name") else "obj"
            result, constraints = symbolic_bool_result(f"isinstance_check_{obj_name}_{state.pc}")
            constraints.append(result.z3_bool == type_expr)
            return ModelResult(
                value=result,
                constraints=constraints,
            )

        if isinstance(obj, SymbolicString) and types is str:
            return ModelResult(value=True)
        if isinstance(obj, SymbolicList) and types is list:
            return ModelResult(value=True)

        return model_bool_result(f"isinstance_{state.pc}")


class SortedModel(FunctionModel):
    """Model for sorted()."""

    name = "sorted"
    qualname = "builtins.sorted"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicList.symbolic(f"sorted_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        obj = args[0]
        if isinstance(obj, SymbolicList):
            result, constraint = SymbolicList.symbolic(f"sorted_{obj.name}")
            return ModelResult(
                value=result,
                constraints=[constraint, result.z3_len == obj.z3_len],
            )
        result, constraint = SymbolicList.symbolic(f"sorted_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class SumModel(FunctionModel):
    """Model for sum()."""

    name = "sum"
    qualname = "builtins.sum"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply sum() model."""
        if not args:
            return ModelResult(value=0)

        iterable = args[0]
        start = args[1] if len(args) > 1 else 0

        if is_list_of_objects(iterable):
            if all(
                not isinstance(x, (SymbolicValue, SymbolicType))
                for x in iterable  # x is object from list[object]
            ) and not isinstance(start, (SymbolicValue, SymbolicType)):
                concrete_sum = _safe_sum_concrete(
                    cast("Sequence[StackValue]", iterable), cast("StackValue", start)
                )
                if concrete_sum is not None:
                    return ModelResult(value=concrete_sum)
        elif is_tuple_of_objects(iterable):
            if all(
                not isinstance(x, (SymbolicValue, SymbolicType))
                for x in iterable  # x is object from tuple[object, ...]
            ) and not isinstance(start, (SymbolicValue, SymbolicType)):
                concrete_sum = _safe_sum_concrete(
                    cast("Sequence[StackValue]", iterable), cast("StackValue", start)
                )
                if concrete_sum is not None:
                    return ModelResult(value=concrete_sum)

        return model_int_result(f"sum_{state.pc}")


class EnumerateModel(FunctionModel):
    """Model for enumerate()."""

    name = "enumerate"
    qualname = "builtins.enumerate"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"enumerate_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class ZipModel(FunctionModel):
    """Model for zip()."""

    name = "zip"
    qualname = "builtins.zip"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"zip_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class MapModel(FunctionModel):
    """Model for map()."""

    name = "map"
    qualname = "builtins.map"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"map_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class FilterModel(FunctionModel):
    """Model for filter()."""

    name = "filter"
    qualname = "builtins.filter"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"filter_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class FloatModel(FunctionModel):
    """Model for float()."""

    name = "float"
    qualname = "builtins.float"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            return ModelResult(value=SymbolicValue.from_const(0.0))
        val = args[0]
        if isinstance(val, SymbolicValue):
            if val.type_tag == "float":
                return ModelResult(value=val)
            elif val.type_tag == "int" or z3.is_true(val.is_int):
                from pysymex.core.types.floats import AdvancedSymbolicFloat
                from pysymex.core.types.floats import get_fp_sort

                result = AdvancedSymbolicFloat(f"float_{state.pc}")
                rm = result.config.get_rounding_mode()
                sort = get_fp_sort(result.config.precision)
                fp_val = z3.fpToFP(rm, z3.ToReal(val.z3_int), sort)
                return ModelResult(
                    value=result,
                    constraints=[z3.fpEQ(result.z3_expr, fp_val)],
                )
        if isinstance(val, (int, float)):
            from pysymex.core.types.floats import AdvancedSymbolicFloat

            return ModelResult(value=AdvancedSymbolicFloat(value=float(val)))
        from pysymex.core.types.floats import AdvancedSymbolicFloat

        result = AdvancedSymbolicFloat(f"float_{state.pc}")
        return ModelResult(value=result)


class ComplexModel(FunctionModel):
    """Model for complex()."""

    name = "complex"
    qualname = "builtins.complex"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"complex_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        result, constraint = SymbolicValue.symbolic(f"complex_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class SliceModel(FunctionModel):
    """Model for slice()."""

    name = "slice"
    qualname = "builtins.slice"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"slice_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class ListModel(FunctionModel):
    """Model for list()."""

    name = "list"
    qualname = "builtins.list"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            return ModelResult(value=SymbolicList.from_const([]))
        val = args[0]
        if isinstance(val, SymbolicList):
            return ModelResult(value=val)
        int_values: list[int] = []
        all_int = True
        if is_list_of_objects(val):
            for item in val:  # item is object from list[object]
                if isinstance(item, int):
                    int_values.append(item)
                else:
                    all_int = False
                    break
        elif is_tuple_of_objects(val):
            for item in val:  # item is object from tuple[object, ...]
                if isinstance(item, int):
                    int_values.append(item)
                else:
                    all_int = False
                    break
        else:
            all_int = False
        if all_int:
            return ModelResult(value=SymbolicList.from_const(int_values))
        result, constraint = SymbolicList.symbolic(f"list_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class TupleModel(FunctionModel):
    """Model for tuple()."""

    name = "tuple"
    qualname = "builtins.tuple"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            return ModelResult(value=())
        val = args[0]
        if isinstance(val, tuple):
            return ModelResult(value=val)  # type: ignore[return-value]  # tuple element type unknown
        if isinstance(val, (list, SymbolicList)):
            if isinstance(val, list):
                return ModelResult(value=tuple(cast("list[StackValue]", val)))
            result, constraint = SymbolicList.symbolic(f"tuple_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        result, constraint = SymbolicList.symbolic(f"tuple_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class NoneModel(FunctionModel):
    """Model for NoneType/None."""

    name = "NoneType"
    qualname = "builtins.NoneType"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return ModelResult(value=SymbolicNone("none"))
