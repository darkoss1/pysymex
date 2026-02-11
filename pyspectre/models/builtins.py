"""Symbolic models for Python builtin functions.

This module provides symbolic handlers for core Python builtins like len,
int, str, etc. It integrates with Z3 to track constraints and side effects.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
import z3
from pyspectre.core.solver import get_model, is_satisfiable
from pyspectre.core.types import (
    SymbolicDict,
    SymbolicList,
    SymbolicNone,
    SymbolicString,
    SymbolicValue,
)


@dataclass
class ModelResult:
    """Result of a model application."""

    value: Any
    constraints: list[z3.ExprRef] = None
    side_effects: dict[str, Any] = None

    def __post_init__(self):
        if self.constraints is None:
            self.constraints = []
        if self.side_effects is None:
            self.side_effects = {}


class FunctionModel(ABC):
    """Base class for function models."""

    name: str = "unknown"
    qualname: str = "unknown"

    @abstractmethod
    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        """
        Apply the function model.
        Args:
            args: Positional arguments
            kwargs: Keyword arguments
            state: Current VM state
        Returns:
            ModelResult with symbolic result and any constraints
        """

    def matches(self, func: Any) -> bool:
        """Check if this model matches a given function."""
        if hasattr(func, "__name__"):
            return func.__name__ == self.name
        return str(func) == self.name


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
            if isinstance(start, SymbolicValue) and isinstance(stop, SymbolicValue):
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
            if all(isinstance(x, int) for x in val):
                return ModelResult(value=SymbolicList.from_const(list(val)))
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
                return ModelResult(value=tuple(val))
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


class IterModel(FunctionModel):
    """Model for iter()."""

    name = "iter"
    qualname = "builtins.iter"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"iter_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        val = args[0]
        if isinstance(val, (list, tuple, str, SymbolicList, SymbolicString)):
            return ModelResult(value=val)
        result, constraint = SymbolicValue.symbolic(f"iter_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class NextModel(FunctionModel):
    """Model for next()."""

    name = "next"
    qualname = "builtins.next"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"next_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class SuperModel(FunctionModel):
    """Model for super()."""

    name = "super"
    qualname = "builtins.super"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
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
        args: list[Any],
        kwargs: dict[str, Any],
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
        args: list[Any],
        kwargs: dict[str, Any],
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
        args: list[Any],
        kwargs: dict[str, Any],
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
        args: list[Any],
        kwargs: dict[str, Any],
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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"set_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.z3_int == 0])
        val = args[0]
        if isinstance(val, (list, tuple, set)):
            result, constraint = SymbolicValue.symbolic(f"set_{state.pc}")
            return ModelResult(
                value=result, constraints=[constraint, result.z3_int == len(set(val))]
            )
        result, constraint = SymbolicValue.symbolic(f"set_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class ReversedModel(FunctionModel):
    """Model for reversed()."""

    name = "reversed"
    qualname = "builtins.reversed"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
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
            return ModelResult(value=list(reversed(val)))
        result, constraint = SymbolicList.symbolic(f"reversed_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class AllModel(FunctionModel):
    """Model for all()."""

    name = "all"
    qualname = "builtins.all"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        if not args:
            return ModelResult(value=SymbolicValue.from_const(True))
        val = args[0]
        if isinstance(val, (list, tuple)):
            if not val:
                return ModelResult(value=SymbolicValue.from_const(True))
            if all(isinstance(x, SymbolicValue) for x in val):
                conditions = [x.is_truthy() for x in val]
                result, constraint = SymbolicValue.symbolic(f"all_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.is_bool, result.z3_bool == z3.And(*conditions)],
                )
            return ModelResult(value=SymbolicValue.from_const(all(val)))
        result, constraint = SymbolicValue.symbolic(f"all_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class AnyModel(FunctionModel):
    """Model for any()."""

    name = "any"
    qualname = "builtins.any"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        if not args:
            return ModelResult(value=SymbolicValue.from_const(False))
        val = args[0]
        if isinstance(val, (list, tuple)):
            if not val:
                return ModelResult(value=SymbolicValue.from_const(False))
            if all(isinstance(x, SymbolicValue) for x in val):
                conditions = [x.is_truthy() for x in val]
                result, constraint = SymbolicValue.symbolic(f"any_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.is_bool, result.z3_bool == z3.Or(*conditions)],
                )
            return ModelResult(value=SymbolicValue.from_const(any(val)))
        result, constraint = SymbolicValue.symbolic(f"any_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class OrdModel(FunctionModel):
    """Model for ord()."""

    name = "ord"
    qualname = "builtins.ord"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
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
        args: list[Any],
        kwargs: dict[str, Any],
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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        if len(args) < 2:
            result, constraint = SymbolicValue.symbolic(f"pow_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        base, exp = args[0], args[1]
        mod = args[2] if len(args) > 2 else None
        if isinstance(base, (int, float)) and isinstance(exp, (int, float)):
            if mod is not None and isinstance(mod, int):
                return ModelResult(value=SymbolicValue.from_const(pow(base, exp, mod)))
            return ModelResult(value=SymbolicValue.from_const(pow(base, exp)))
        result, constraint = SymbolicValue.symbolic(f"pow_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class RoundModel(FunctionModel):
    """Model for round()."""

    name = "round"
    qualname = "builtins.round"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"round_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        val = args[0]
        ndigits = args[1] if len(args) > 1 else None
        if isinstance(val, (int, float)):
            result = round(val, ndigits)
            return ModelResult(value=result)
        result, constraint = SymbolicValue.symbolic(f"round_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class DivmodModel(FunctionModel):
    """Model for divmod()."""

    name = "divmod"
    qualname = "builtins.divmod"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        if len(args) < 2:
            return ModelResult(value=(SymbolicValue.from_const(0), SymbolicValue.from_const(0)))
        a, b = args[0], args[1]
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
                    remainder.z3_int >= 0,
                    z3.If(b.z3_int > 0, remainder.z3_int < b.z3_int, remainder.z3_int < -b.z3_int),
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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        if len(args) < 2:
            result, constraint = SymbolicValue.symbolic(f"hasattr_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.is_bool])
        obj, name = args[0], args[1]
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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        if len(args) < 2:
            result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        obj, name = args[0], args[1]
        default = args[2] if len(args) > 2 else None
        if not isinstance(obj, SymbolicValue) and isinstance(name, str):
            try:
                return ModelResult(value=getattr(obj, name))
            except AttributeError:
                if default is not None:
                    return ModelResult(value=default)
        result, constraint = SymbolicValue.symbolic(f"getattr_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class SetattrModel(FunctionModel):
    """Model for setattr()."""

    name = "setattr"
    qualname = "builtins.setattr"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        return ModelResult(value=SymbolicNone.instance(), side_effects={"mutates_arg": 0})


class IdModel(FunctionModel):
    """Model for id()."""

    name = "id"
    qualname = "builtins.id"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        if args:
            obj = args[0]
            if isinstance(obj, (int, str, float, tuple, frozenset, type(None))):
                return ModelResult(value=SymbolicValue.from_const(hash(obj)))
        result, constraint = SymbolicValue.symbolic(f"hash_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class CallableModel(FunctionModel):
    """Model for callable()."""

    name = "callable"
    qualname = "builtins.callable"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        if args:
            obj = args[0]
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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        if args:
            obj = args[0]
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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        if args:
            obj = args[0]
            spec = args[1] if len(args) > 1 else ""
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
        args: list[Any],
        kwargs: dict[str, Any],
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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"file_{state.pc}")
        return ModelResult(value=result, constraints=[constraint], side_effects={"io": True})


class ModelRegistry:
    """Registry for function models."""

    def __init__(self):
        self._models: dict[str, FunctionModel] = {}
        self._register_defaults()

    def _register_defaults(self):
        """Register default builtin models and standard library models."""
        from pyspectre.models.dicts import DICT_MODELS
        from pyspectre.models.lists import LIST_MODELS
        from pyspectre.models.sets import SET_MODELS
        from pyspectre.models.stdlib import (
            collections_models,
            datetime_models,
            functools_models,
            itertools_models,
            json_models,
            math_models,
            ospath_models,
            random_models,
            re_models,
        )
        from pyspectre.models.strings import STRING_MODELS

        all_models = (
            [
                IntModel(),
                FloatModel(),
                BoolModel(),
                StrModel(),
                ListModel(),
                DictModel(),
                TupleModel(),
                NoneModel(),
                TypeModel(),
                PrintModel(),
                AbsModel(),
                MinModel(),
                MaxModel(),
                SumModel(),
                AnyModel(),
                AllModel(),
                ZipModel(),
                RangeModel(),
                EnumerateModel(),
                FilterModel(),
                MapModel(),
                IterModel(),
                NextModel(),
                SuperModel(),
                GetattrModel(),
                SetattrModel(),
                HasattrModel(),
                IsinstanceModel(),
                IssubclassModel(),
                IdModel(),
                HashModel(),
                GlobalsModel(),
                LocalsModel(),
                LenModel(),
                SetModel(),
                SortedModel(),
                ReversedModel(),
                PowModel(),
                RoundModel(),
                DivmodModel(),
                CallableModel(),
                OrdModel(),
                ChrModel(),
                ReprModel(),
                FormatModel(),
                InputModel(),
                OpenModel(),
            ]
            + math_models
            + collections_models
            + itertools_models
            + functools_models
            + ospath_models
            + json_models
            + re_models
            + random_models
            + datetime_models
            + DICT_MODELS
            + LIST_MODELS
            + STRING_MODELS
            + SET_MODELS
        )
        for model in all_models:
            self.register(model)

    def register(self, model: FunctionModel) -> None:
        """Register a function model."""
        self._models[model.name] = model
        if model.qualname != model.name:
            self._models[model.qualname] = model

    def get(self, name: str) -> FunctionModel | None:
        """Get a model by name."""
        return self._models.get(name)

    def apply(
        self,
        func: Any,
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult | None:
        """Try to apply a model for a function."""
        if hasattr(func, "__name__"):
            model = self.get(func.__name__)
            if model:
                return model.apply(args, kwargs, state)
        model = self.get(str(func))
        if model:
            return model.apply(args, kwargs, state)
        return None

    def has_model(self, func: Any) -> bool:
        """Check if a model exists for a function."""
        if hasattr(func, "__name__"):
            return func.__name__ in self._models
        return str(func) in self._models

    def list_models(self) -> list[str]:
        """List all registered model names."""
        return list(set(m.name for m in self._models.values()))


default_model_registry = ModelRegistry()
