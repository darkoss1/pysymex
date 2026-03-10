"""Symbolic models for collections, itertools, and functools modules.

Models:
- collections: Counter, defaultdict, deque, OrderedDict, namedtuple
- itertools: chain, islice, cycle, repeat, takewhile, dropwhile, product,
             permutations, combinations
- functools: reduce, partial, lru_cache
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex.core.types import SymbolicDict, SymbolicList, SymbolicValue
from pysymex.models.builtins import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState


class CounterModel(FunctionModel):
    """Model for collections.Counter()."""

    name = "Counter"
    qualname = "collections.Counter"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicDict.symbolic(f"counter_{state .pc }")
        return ModelResult(value=result, constraints=[constraint])


class DefaultdictModel(FunctionModel):
    """Model for collections.defaultdict()."""

    name = "defaultdict"
    qualname = "collections.defaultdict"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicDict.symbolic(f"defaultdict_{state .pc }")
        return ModelResult(value=result, constraints=[constraint])


class DequeModel(FunctionModel):
    """Model for collections.deque()."""

    name = "deque"
    qualname = "collections.deque"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"deque_{state .pc }")
        if args and isinstance(args[0], (list, tuple)):
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.z3_len == len(cast("list[object] | tuple[object, ...]", args[0])),
                ],
            )
        maxlen = kwargs.get("maxlen")
        if maxlen is not None and isinstance(maxlen, int):
            return ModelResult(
                value=result,
                constraints=[constraint, result.z3_len >= 0, result.z3_len <= maxlen],
            )
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class OrderedDictModel(FunctionModel):
    """Model for collections.OrderedDict()."""

    name = "OrderedDict"
    qualname = "collections.OrderedDict"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicDict.symbolic(f"ordereddict_{state .pc }")
        return ModelResult(value=result, constraints=[constraint])


class NamedtupleModel(FunctionModel):
    """Model for collections.namedtuple()."""

    name = "namedtuple"
    qualname = "collections.namedtuple"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"namedtuple_{state .pc }")
        return ModelResult(value=result, constraints=[constraint])


class ItertoolsChainModel(FunctionModel):
    """Model for itertools.chain()."""

    name = "chain"
    qualname = "itertools.chain"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"chain_{state .pc }")
        total_len = z3.IntVal(0)
        for arg in args:
            if isinstance(arg, SymbolicList):
                total_len = total_len + arg.z3_len
            elif isinstance(arg, (list, tuple)):
                total_len = total_len + len(cast("list[object] | tuple[object, ...]", arg))
        return ModelResult(
            value=result,
            constraints=[constraint, result.z3_len == total_len],
        )


class ItertoolsIsliceModel(FunctionModel):
    """Model for itertools.islice()."""

    name = "islice"
    qualname = "itertools.islice"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"islice_{state .pc }")
        if len(args) >= 3:

            stop = args[2]
            if isinstance(stop, int):
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.z3_len >= 0, result.z3_len <= stop],
                )
        elif len(args) >= 2:

            stop = args[1]
            if isinstance(stop, int):
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.z3_len >= 0, result.z3_len <= stop],
                )
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class ItertoolsCycleModel(FunctionModel):
    """Model for itertools.cycle()."""

    name = "cycle"
    qualname = "itertools.cycle"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"cycle_{state .pc }")
        return ModelResult(value=result, constraints=[constraint])


class ItertoolsRepeatModel(FunctionModel):
    """Model for itertools.repeat()."""

    name = "repeat"
    qualname = "itertools.repeat"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"repeat_{state .pc }")
        if len(args) >= 2:
            times = args[1]
            if isinstance(times, int):
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.z3_len == times],
                )
        return ModelResult(value=result, constraints=[constraint])


class ItertoolsTakewhileModel(FunctionModel):
    """Model for itertools.takewhile()."""

    name = "takewhile"
    qualname = "itertools.takewhile"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"takewhile_{state .pc }")
        if len(args) >= 2 and isinstance(args[1], SymbolicList):
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.z3_len >= 0,
                    result.z3_len <= args[1].z3_len,
                ],
            )
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class ItertoolsDropwhileModel(FunctionModel):
    """Model for itertools.dropwhile()."""

    name = "dropwhile"
    qualname = "itertools.dropwhile"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"dropwhile_{state .pc }")
        if len(args) >= 2 and isinstance(args[1], SymbolicList):
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.z3_len >= 0,
                    result.z3_len <= args[1].z3_len,
                ],
            )
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class ItertoolsProductModel(FunctionModel):
    """Model for itertools.product()."""

    name = "product"
    qualname = "itertools.product"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"product_{state .pc }")
        product_len = z3.IntVal(1)
        for arg in args:
            if isinstance(arg, SymbolicList):
                product_len = product_len * arg.z3_len
            elif isinstance(arg, (list, tuple)):
                product_len = product_len * len(cast("list[object] | tuple[object, ...]", arg))
        repeat = kwargs.get("repeat", 1)
        if isinstance(repeat, int) and repeat > 1:
            base_len = product_len
            for _ in range(repeat - 1):
                product_len = product_len * base_len
        return ModelResult(
            value=result,
            constraints=[constraint, result.z3_len == product_len],
        )


class ItertoolsPermutationsModel(FunctionModel):
    """Model for itertools.permutations()."""

    name = "permutations"
    qualname = "itertools.permutations"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"permutations_{state .pc }")
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class ItertoolsCombinationsModel(FunctionModel):
    """Model for itertools.combinations()."""

    name = "combinations"
    qualname = "itertools.combinations"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"combinations_{state .pc }")
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class FunctoolsReduceModel(FunctionModel):
    """Model for functools.reduce()."""

    name = "reduce"
    qualname = "functools.reduce"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"reduce_{state .pc }")
        return ModelResult(value=result, constraints=[constraint])


class FunctoolsPartialModel(FunctionModel):
    """Model for functools.partial()."""

    name = "partial"
    qualname = "functools.partial"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"partial_{state .pc }")
        return ModelResult(value=result, constraints=[constraint])


class FunctoolsLruCacheModel(FunctionModel):
    """Model for functools.lru_cache()."""

    name = "lru_cache"
    qualname = "functools.lru_cache"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"lru_cache_{state .pc }")
        return ModelResult(value=result, constraints=[constraint])


collections_models = [
    CounterModel(),
    DefaultdictModel(),
    DequeModel(),
    OrderedDictModel(),
    NamedtupleModel(),
]
itertools_models = [
    ItertoolsChainModel(),
    ItertoolsIsliceModel(),
    ItertoolsCycleModel(),
    ItertoolsRepeatModel(),
    ItertoolsTakewhileModel(),
    ItertoolsDropwhileModel(),
    ItertoolsProductModel(),
    ItertoolsPermutationsModel(),
    ItertoolsCombinationsModel(),
]
functools_models = [
    FunctoolsReduceModel(),
    FunctoolsPartialModel(),
    FunctoolsLruCacheModel(),
]
