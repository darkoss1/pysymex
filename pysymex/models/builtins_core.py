"""Core builtin function models.

Contains models for the most commonly used Python builtins:
len, range, abs, min, max, int, str, bool, print, type, isinstance,
sorted, sum, enumerate, zip, map, filter, float, list, tuple, None.
"""

from __future__ import annotations


from typing import TYPE_CHECKING, Any, cast


import z3

if TYPE_CHECKING:
    from pysymex.core.state import VMState

from pysymex.core.types import (
    SymbolicList,
    SymbolicNone,
    SymbolicString,
    SymbolicValue,
)


from .builtins_base import FunctionModel, ModelResult


class LenModel(FunctionModel):
    """Model for len()."""

    name = "len"

    qualname = "builtins.len"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
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

        if getattr(obj, "_type", "") == "set" or "set" in getattr(obj, "_name", "").lower():
            z3_len = getattr(obj, "z3_len", getattr(obj, "z3_int", None))

            if z3_len is not None:
                result, constraint = SymbolicValue.symbolic(f"len_{getattr(obj, '_name', 'set')}")

                return ModelResult(
                    value=result,
                    constraints=[
                        constraint,
                        result.is_int,
                        result.z3_int == z3_len,
                    ],
                )

        result, constraint = SymbolicValue.symbolic(f"len_{state.pc}")

        return ModelResult(
            value=result,
            constraints=[constraint, result.is_int, result.z3_int >= 0],
        )


class RangeModel(FunctionModel):
    """Model for range()."""

    name = "range"

    qualname = "builtins.range"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
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

            else:
                constraints.append(
                    result.z3_len
                    == z3.If(stop.z3_int > start.z3_int, stop.z3_int - start.z3_int, 0)
                )

        return ModelResult(value=result, constraints=constraints)


class AbsModel(FunctionModel):
    """Model for abs()."""

    name = "abs"

    qualname = "builtins.abs"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
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

        try:
            return ModelResult(value=abs(x))

        except Exception:
            return ModelResult(value=SymbolicValue.symbolic(f"abs_{state.pc}")[0])


class MinModel(FunctionModel):
    """Model for min()."""

    name = "min"

    qualname = "builtins.min"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        """Apply min() model."""

        if not args:
            return ModelResult(SymbolicValue.symbolic(f"min_{state.pc}")[0])

        if len(args) == 1 and isinstance(args[0], (list, SymbolicList)):
            result, constraint = SymbolicValue.symbolic(f"min_{state.pc}")

            return ModelResult(value=result, constraints=[constraint])

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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        """Apply max() model."""

        if not args:
            return ModelResult(SymbolicValue.symbolic(f"max_{state.pc}")[0])

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
        args: list[Any],
        kwargs: dict[str, Any],
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

            return ModelResult(value=result, constraints=[constraint, result.is_int])

        try:
            return ModelResult(value=int(x))

        except Exception:
            result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")

            return ModelResult(value=result, constraints=[constraint])


class StrModel(FunctionModel):
    """Model for str()."""

    name = "str"

    qualname = "builtins.str"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        """Apply str() model."""

        if not args:
            return ModelResult(value="")

        x = args[0]

        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicString.symbolic(f"str_{x.name}")

            return ModelResult(value=result, constraints=[constraint])

        try:
            return ModelResult(value=str(x))

        except Exception:
            result, constraint = SymbolicString.symbolic(f"str_{state.pc}")

            return ModelResult(value=result, constraints=[constraint])


class BoolModel(FunctionModel):
    """Model for bool()."""

    name = "bool"

    qualname = "builtins.bool"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
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

        except Exception:
            result, constraint = SymbolicValue.symbolic(f"bool_{state.pc}")

            return ModelResult(value=result, constraints=[constraint])


class PrintModel(FunctionModel):
    """Model for print() - side effect only."""

    name = "print"

    qualname = "builtins.print"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        return ModelResult(value=SymbolicNone())


class TypeModel(FunctionModel):
    """Model for type()."""

    name = "type"

    qualname = "builtins.type"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
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
        args: list[Any],
        kwargs: dict[str, Any],
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
        args: list[Any],
        kwargs: dict[str, Any],
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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"sum_{state.pc}")

        return ModelResult(value=result, constraints=[constraint, result.is_int])


class EnumerateModel(FunctionModel):
    """Model for enumerate()."""

    name = "enumerate"

    qualname = "builtins.enumerate"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
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
        args: list[Any],
        kwargs: dict[str, Any],
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
        args: list[Any],
        kwargs: dict[str, Any],
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
        args: list[Any],
        kwargs: dict[str, Any],
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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        if not args:
            return ModelResult(value=SymbolicValue.from_const(0.0))

        val = args[0]

        if isinstance(val, SymbolicValue):
            if val.type_tag == "float":
                return ModelResult(value=val)

            elif val.type_tag == "int" or val.is_int:
                result, constraint = SymbolicValue.symbolic(f"float_{state.pc}")

                return ModelResult(
                    value=result,
                    constraints=[
                        constraint,
                        result.is_float,
                        result.z3_real == z3.ToReal(val.z3_int),
                    ],
                )

        if isinstance(val, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(float(val)))

        result, constraint = SymbolicValue.symbolic(f"float_{state.pc}")

        return ModelResult(value=result, constraints=[constraint, result.is_float])


class ListModel(FunctionModel):
    """Model for list()."""

    name = "list"

    qualname = "builtins.list"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        if not args:
            return ModelResult(value=SymbolicList.from_const([]))

        val = args[0]

        if isinstance(val, SymbolicList):
            return ModelResult(value=val)

        if isinstance(val, (list, tuple)):
            if all(isinstance(x, int) for x in cast(list[Any] | tuple[Any, ...], val)):
                return ModelResult(
                    value=SymbolicList.from_const(list(cast(list[Any] | tuple[Any, ...], val)))
                )

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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        if not args:
            return ModelResult(value=())

        val = args[0]

        if isinstance(val, tuple):
            return ModelResult(value=val)

        if isinstance(val, (list, SymbolicList)):
            if isinstance(val, list):
                return ModelResult(value=tuple(cast(list[Any], val)))

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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        return ModelResult(value=SymbolicNone.instance())
