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

from pysymex.core.types import (
    SymbolicNone,
    SymbolicString,
    SymbolicType,
    SymbolicValue,
)
from pysymex.core.types_containers import SymbolicDict, SymbolicList

from .builtins_base import FunctionModel, ModelResult


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


def _safe_sum_concrete(values: Sequence[StackValue], start: StackValue) -> StackValue:
    if not isinstance(start, (int, float, bool)):
        return None
    if not all(isinstance(x, (int, float, bool)) for x in values):
        return None
    numeric_values = cast("Sequence[int | float | bool]", values)
    return sum(numeric_values, start)


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
        obj = args[0]
        if isinstance(obj, SymbolicList):
            result, constraint = SymbolicValue.symbolic(f"len_{obj.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_int,
                    result.z3_int == obj.z3_len,
                    result.z3_int >= 0,
                ],
            )
        if isinstance(obj, SymbolicString):
            result, constraint = SymbolicValue.symbolic(f"len_{obj.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_int,
                    result.z3_int == obj.z3_len,
                    result.z3_int >= 0,
                ],
            )
        if (
            getattr(obj, "_type", "") == "set"
            or "set" in getattr(obj, "_name", "").lower()
            or getattr(obj, "type_tag", "") == "dict"
            or isinstance(obj, SymbolicDict)
        ):
            z3_len = getattr(obj, "z3_len", getattr(obj, "z3_int", None))
            if z3_len is not None:
                result, constraint = SymbolicValue.symbolic(
                    f"len_{getattr(obj, '_name', 'container')}"
                )
                return ModelResult(
                    value=result,
                    constraints=[
                        constraint,
                        result.is_int,
                        result.z3_int == z3_len,
                    ],
                )
        result, constraint = SymbolicValue.symbolic(f"len_{state.pc}")
        extra_constraints: list[z3.ExprRef | z3.BoolRef] = [
            constraint,
            result.is_int,
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
        result, constraint = SymbolicList.symbolic(f"range_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
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
                constraints.append(
                    z3.ForAll(
                        [i],
                        z3.Implies(
                            z3.And(i >= 0, i < result.z3_len),
                            z3.Select(result.z3_array, i) == start.z3_int + i * step.z3_int,
                        ),
                    )
                )
            else:
                length = z3.If(stop.z3_int > start.z3_int, stop.z3_int - start.z3_int, 0)
                constraints.append(result.z3_len == length)

                i = z3.Int(f"range_idx_{state.pc}")
                constraints.append(
                    z3.ForAll(
                        [i],
                        z3.Implies(
                            z3.And(i >= 0, i < result.z3_len),
                            z3.Select(result.z3_array, i) == start.z3_int + i,
                        ),
                    )
                )
        if len(args) == 1 and isinstance(args[0], SymbolicValue):
            stop = args[0]
            length = z3.If(stop.z3_int > 0, stop.z3_int, 0)
            constraints.append(result.z3_len == length)
            i = z3.Int(f"range_idx_{state.pc}")
            constraints.append(
                z3.ForAll(
                    [i],
                    z3.Implies(
                        z3.And(i >= 0, i < result.z3_len), z3.Select(result.z3_array, i) == i
                    ),
                )
            )
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
            result, constraint = SymbolicValue.symbolic(f"abs_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_int,
                    result.z3_int == z3.If(x.z3_int >= 0, x.z3_int, -x.z3_int),
                ],
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

        if len(args) == 1 and isinstance(args[0], (list, tuple)):
            seq = args[0]
            if all(not isinstance(x, (SymbolicValue, SymbolicType)) for x in seq):
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

            if len(args) == 2:
                a, b = args
                if isinstance(a, SymbolicValue) and isinstance(b, SymbolicValue):
                    result, constraint = SymbolicValue.symbolic(f"min_{a.name}_{b.name}")
                    return ModelResult(
                        value=result,
                        constraints=[
                            constraint,
                            result.is_int,
                            result.z3_int == z3.If(a.z3_int <= b.z3_int, a.z3_int, b.z3_int),
                        ],
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

        if len(args) == 1 and isinstance(args[0], (list, tuple)):
            seq = args[0]
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

            if len(args) == 2:
                a, b = args
                if isinstance(a, SymbolicValue) and isinstance(b, SymbolicValue):
                    result, constraint = SymbolicValue.symbolic(f"max_{a.name}_{b.name}")
                    return ModelResult(
                        value=result,
                        constraints=[
                            constraint,
                            result.is_int,
                            result.z3_int == z3.If(a.z3_int >= b.z3_int, a.z3_int, b.z3_int),
                        ],
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
            result, constraint = SymbolicValue.symbolic(f"int_{x.name}")
            return ModelResult(
                value=result,
                constraints=[constraint, result.is_int, result.z3_int == x.z3_int],
            )
        if isinstance(x, SymbolicString):
            result, constraint = SymbolicValue.symbolic(f"int_{x.name}")
            return ModelResult(
                value=result,
                constraints=[constraint, result.is_int, result.z3_int == z3.StrToInt(x.z3_str)],
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
            result, constraint = SymbolicValue.symbolic(f"bool_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_bool,
                    result.z3_bool
                    == z3.If(
                        x.is_int,
                        x.z3_int != 0,
                        x.z3_bool,
                    ),
                ],
            )
        try:
            return ModelResult(value=bool(x))
        except (TypeError, ValueError, RecursionError):
            result, constraint = SymbolicValue.symbolic(f"bool_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])


class PrintModel(FunctionModel):
    """Model for print() - side effect only."""

    name = "print"
    qualname = "builtins.print"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return ModelResult(value=SymbolicNone())


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
        if isinstance(obj, SymbolicValue):
            if types is int:
                result, constraint = SymbolicValue.symbolic(f"isinstance_int_{obj.name}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.is_bool, result.z3_bool == obj.is_int],
                )
            elif types is bool:
                result, constraint = SymbolicValue.symbolic(f"isinstance_bool_{obj.name}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.is_bool, result.z3_bool == obj.is_bool],
                )
        if isinstance(obj, SymbolicString) and types is str:
            return ModelResult(value=True)
        if isinstance(obj, SymbolicList) and types is list:
            return ModelResult(value=True)
        result, constraint = SymbolicValue.symbolic(f"isinstance_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


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

        if isinstance(iterable, (list, tuple)):
            if all(
                not isinstance(x, (SymbolicValue, SymbolicType)) for x in iterable
            ) and not isinstance(start, (SymbolicValue, SymbolicType)):
                concrete_sum = _safe_sum_concrete(
                    cast("Sequence[StackValue]", iterable), cast("StackValue", start)
                )

                if concrete_sum is not None:
                    return ModelResult(value=concrete_sum)

        result, constraint = SymbolicValue.symbolic(f"sum_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


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
            elif val.type_tag == "int" or val.is_int:
                from pysymex.core.floats import SymbolicFloat, get_fp_sort

                result = SymbolicFloat(f"float_{state.pc}")
                rm = result.config.get_rounding_mode()
                sort = get_fp_sort(result.config.precision)
                fp_val = z3.fpToFP(rm, z3.ToReal(val.z3_int), sort)
                return ModelResult(
                    value=result,
                    constraints=[z3.fpEQ(result.z3_expr, fp_val)],
                )
        if isinstance(val, (int, float)):
            from pysymex.core.floats import SymbolicFloat

            return ModelResult(value=SymbolicFloat(value=float(val)))
        from pysymex.core.floats import SymbolicFloat

        result = SymbolicFloat(f"float_{state.pc}")
        return ModelResult(value=result)


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
        if isinstance(val, (list, tuple)):
            int_values: list[int] = []
            all_int = True
            for item in val:
                if isinstance(item, int):
                    int_values.append(item)
                else:
                    all_int = False
                    break
            if all_int:
                return ModelResult(value=SymbolicList.from_const(int_values))
            result, constraint = SymbolicList.symbolic(f"list_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
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
            return ModelResult(value=val)
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
