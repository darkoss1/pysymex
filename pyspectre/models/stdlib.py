"""
Extended Standard Library Models for PySpectre v1.2.
Provides symbolic models for commonly used stdlib modules:
- math: Mathematical functions (sqrt, ceil, floor, sin, cos, etc.)
- collections: Counter, defaultdict, deque, OrderedDict
- itertools: islice, chain, cycle, repeat, takewhile, dropwhile
- functools: reduce, partial
- os.path: exists, join, dirname, basename, isfile, isdir
- json: loads, dumps
- re: match, search, findall, sub
- datetime: date, time, datetime, timedelta
- random: random, randint, choice, shuffle
"""

from __future__ import annotations
import math as _math
from typing import TYPE_CHECKING, Any
import z3
from pyspectre.core.types import (
    SymbolicDict,
    SymbolicList,
    SymbolicNone,
    SymbolicString,
    SymbolicValue,
    SymbolicObject,
)
from pyspectre.models.builtins import FunctionModel, ModelResult
from pyspectre.models.regex import (
    ReCompileModel,
    ReEscapeModel,
    ReFindallModel,
    ReMatchModel,
    ReSearchModel,
    ReSplitModel,
    ReSubModel,
)
from pyspectre.models.strings import STRING_MODELS

if TYPE_CHECKING:
    from pyspectre.core.state import VMState


class MathSqrtModel(FunctionModel):
    """Model for math.sqrt()."""

    name = "sqrt"
    qualname = "math.sqrt"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"sqrt_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        if isinstance(x, (int, float)) and x >= 0:
            return ModelResult(value=SymbolicValue.from_const(_math.sqrt(x)))
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"sqrt_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_float,
                    x.z3_int >= 0,
                    result.z3_real >= 0,
                    result.z3_real * result.z3_real == z3.ToReal(x.z3_int),
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"sqrt_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_float])


class MathCeilModel(FunctionModel):
    """Model for math.ceil()."""

    name = "ceil"
    qualname = "math.ceil"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"ceil_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.is_int])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.ceil(x)))
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"ceil_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_int,
                    result.z3_int >= x.z3_int,
                    result.z3_int <= x.z3_int + 1,
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"ceil_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class MathFloorModel(FunctionModel):
    """Model for math.floor()."""

    name = "floor"
    qualname = "math.floor"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"floor_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.is_int])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.floor(x)))
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"floor_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_int,
                    result.z3_int <= x.z3_int,
                    result.z3_int >= x.z3_int - 1,
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"floor_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class MathLogModel(FunctionModel):
    """Model for math.log()."""

    name = "log"
    qualname = "math.log"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"log_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        base = args[1] if len(args) > 1 else _math.e
        if isinstance(x, (int, float)) and x > 0:
            if isinstance(base, (int, float)) and base > 0:
                return ModelResult(value=SymbolicValue.from_const(_math.log(x, base)))
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"log_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_float,
                    x.z3_int > 0,
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"log_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_float])


class MathExpModel(FunctionModel):
    """Model for math.exp()."""

    name = "exp"
    qualname = "math.exp"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"exp_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.exp(x)))
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"exp_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_float,
                    result.z3_real > 0,
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"exp_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_float])


class MathSinModel(FunctionModel):
    """Model for math.sin()."""

    name = "sin"
    qualname = "math.sin"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"sin_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.sin(x)))
        result, constraint = SymbolicValue.symbolic(f"sin_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[
                constraint,
                result.is_float,
                result.z3_real >= -1,
                result.z3_real <= 1,
            ],
        )


class MathCosModel(FunctionModel):
    """Model for math.cos()."""

    name = "cos"
    qualname = "math.cos"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"cos_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.cos(x)))
        result, constraint = SymbolicValue.symbolic(f"cos_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[
                constraint,
                result.is_float,
                result.z3_real >= -1,
                result.z3_real <= 1,
            ],
        )


class MathTanModel(FunctionModel):
    """Model for math.tan()."""

    name = "tan"
    qualname = "math.tan"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"tan_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.tan(x)))
        result, constraint = SymbolicValue.symbolic(f"tan_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_float])


class MathFabsModel(FunctionModel):
    """Model for math.fabs()."""

    name = "fabs"
    qualname = "math.fabs"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"fabs_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.fabs(x)))
        if isinstance(x, SymbolicValue):
            result, constraint = SymbolicValue.symbolic(f"fabs_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.is_float,
                    result.z3_real
                    == z3.If(z3.ToReal(x.z3_int) >= 0, z3.ToReal(x.z3_int), -z3.ToReal(x.z3_int)),
                    result.z3_real >= 0,
                ],
            )
        result, constraint = SymbolicValue.symbolic(f"fabs_{state.pc}")
        return ModelResult(
            value=result, constraints=[constraint, result.is_float, result.z3_real >= 0]
        )


class MathGcdModel(FunctionModel):
    """Model for math.gcd()."""

    name = "gcd"
    qualname = "math.gcd"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if len(args) < 2:
            result, constraint = SymbolicValue.symbolic(f"gcd_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.is_int])
        a, b = args[0], args[1]
        if isinstance(a, int) and isinstance(b, int):
            return ModelResult(value=SymbolicValue.from_const(_math.gcd(a, b)))
        result, constraint = SymbolicValue.symbolic(f"gcd_{state.pc}")
        constraints = [constraint, result.is_int, result.z3_int >= 0]
        if isinstance(a, SymbolicValue):
            constraints.append(result.z3_int <= z3.If(a.z3_int >= 0, a.z3_int, -a.z3_int))
        if isinstance(b, SymbolicValue):
            constraints.append(result.z3_int <= z3.If(b.z3_int >= 0, b.z3_int, -b.z3_int))
        return ModelResult(value=result, constraints=constraints)


class MathIsfiniteModel(FunctionModel):
    """Model for math.isfinite()."""

    name = "isfinite"
    qualname = "math.isfinite"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            result, constraint = SymbolicValue.symbolic(f"isfinite_{state.pc}")
            return ModelResult(value=result, constraints=[constraint, result.is_bool])
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.isfinite(x)))
        if isinstance(x, SymbolicValue) and hasattr(x, "is_int"):
            result, constraint = SymbolicValue.symbolic(f"isfinite_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint, result.is_bool, result.z3_bool == x.is_int],
            )
        result, constraint = SymbolicValue.symbolic(f"isfinite_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class MathIsCloseModel(FunctionModel):
    """Model for math.isclose()."""

    name = "isclose"
    qualname = "math.isclose"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"isclose_{state.pc}")
        if (
            len(args) >= 2
            and isinstance(args[0], (int, float))
            and isinstance(args[1], (int, float))
        ):
            return ModelResult(value=SymbolicValue.from_const(_math.isclose(args[0], args[1])))
        constraints = [constraint, result.is_bool]
        if len(args) >= 2:
            a, b = args[0], args[1]
            rel_tol = kwargs.get("rel_tol", 1e-09)
            abs_tol = kwargs.get("abs_tol", 0.0)
            if isinstance(a, SymbolicValue) and isinstance(b, SymbolicValue):
                diff = z3.If(a.z3_real >= b.z3_real, a.z3_real - b.z3_real, b.z3_real - a.z3_real)
                constraints.append(result.z3_bool == (diff <= abs_tol))
        return ModelResult(value=result, constraints=constraints)


class MathIsinfModel(FunctionModel):
    """Model for math.isinf()."""

    name = "isinf"
    qualname = "math.isinf"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            return ModelResult(value=SymbolicValue.from_const(False))
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.isinf(x)))
        if isinstance(x, SymbolicValue):
            return ModelResult(value=SymbolicValue.from_const(False))
        result, constraint = SymbolicValue.symbolic(f"isinf_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class MathIsnanModel(FunctionModel):
    """Model for math.isnan()."""

    name = "isnan"
    qualname = "math.isnan"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if not args:
            return ModelResult(value=SymbolicValue.from_const(False))
        x = args[0]
        if isinstance(x, (int, float)):
            return ModelResult(value=SymbolicValue.from_const(_math.isnan(x)))
        if isinstance(x, SymbolicValue):
            return ModelResult(value=SymbolicValue.from_const(False))
        result, constraint = SymbolicValue.symbolic(f"isnan_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class CounterModel(FunctionModel):
    """Model for collections.Counter()."""

    name = "Counter"
    qualname = "collections.Counter"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicDict.symbolic(f"counter_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class DefaultdictModel(FunctionModel):
    """Model for collections.defaultdict()."""

    name = "defaultdict"
    qualname = "collections.defaultdict"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicDict.symbolic(f"defaultdict_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class DequeModel(FunctionModel):
    """Model for collections.deque()."""

    name = "deque"
    qualname = "collections.deque"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"deque_{state.pc}")
        if args and isinstance(args[0], (list, tuple)):
            return ModelResult(
                value=result,
                constraints=[constraint, result.z3_len == len(args[0])],
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

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicDict.symbolic(f"ordereddict_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class NamedtupleModel(FunctionModel):
    """Model for collections.namedtuple()."""

    name = "namedtuple"
    qualname = "collections.namedtuple"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"namedtuple_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class ItertoolsChainModel(FunctionModel):
    """Model for itertools.chain()."""

    name = "chain"
    qualname = "itertools.chain"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"chain_{state.pc}")
        total_len = z3.IntVal(0)
        for arg in args:
            if isinstance(arg, SymbolicList):
                total_len = total_len + arg.z3_len
            elif isinstance(arg, (list, tuple)):
                total_len = total_len + len(arg)
        return ModelResult(
            value=result,
            constraints=[constraint, result.z3_len == total_len],
        )


class ItertoolsIsliceModel(FunctionModel):
    """Model for itertools.islice()."""

    name = "islice"
    qualname = "itertools.islice"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"islice_{state.pc}")
        if len(args) >= 2:
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

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"cycle_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class ItertoolsRepeatModel(FunctionModel):
    """Model for itertools.repeat()."""

    name = "repeat"
    qualname = "itertools.repeat"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"repeat_{state.pc}")
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

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"takewhile_{state.pc}")
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

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"dropwhile_{state.pc}")
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

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"product_{state.pc}")
        product_len = z3.IntVal(1)
        for arg in args:
            if isinstance(arg, SymbolicList):
                product_len = product_len * arg.z3_len
            elif isinstance(arg, (list, tuple)):
                product_len = product_len * len(arg)
        repeat = kwargs.get("repeat", 1)
        if isinstance(repeat, int) and repeat > 1:
            for _ in range(repeat - 1):
                product_len = product_len * product_len
        return ModelResult(
            value=result,
            constraints=[constraint, result.z3_len == product_len],
        )


class ItertoolsPermutationsModel(FunctionModel):
    """Model for itertools.permutations()."""

    name = "permutations"
    qualname = "itertools.permutations"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"permutations_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class ItertoolsCombinationsModel(FunctionModel):
    """Model for itertools.combinations()."""

    name = "combinations"
    qualname = "itertools.combinations"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"combinations_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class FunctoolsReduceModel(FunctionModel):
    """Model for functools.reduce()."""

    name = "reduce"
    qualname = "functools.reduce"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"reduce_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class FunctoolsPartialModel(FunctionModel):
    """Model for functools.partial()."""

    name = "partial"
    qualname = "functools.partial"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"partial_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class FunctoolsLruCacheModel(FunctionModel):
    """Model for functools.lru_cache()."""

    name = "lru_cache"
    qualname = "functools.lru_cache"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"lru_cache_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OsPathExistsModel(FunctionModel):
    """Model for os.path.exists()."""

    name = "exists"
    qualname = "os.path.exists"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"exists_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class OsPathIsfileModel(FunctionModel):
    """Model for os.path.isfile()."""

    name = "isfile"
    qualname = "os.path.isfile"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"isfile_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class OsPathIsdirModel(FunctionModel):
    """Model for os.path.isdir()."""

    name = "isdir"
    qualname = "os.path.isdir"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"isdir_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class OsPathJoinModel(FunctionModel):
    """Model for os.path.join()."""

    name = "join"
    qualname = "os.path.join"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if all(isinstance(a, str) for a in args):
            import os.path

            return ModelResult(value=SymbolicString.from_const(os.path.join(*args)))
        result, constraint = SymbolicString.symbolic(f"pathjoin_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OsPathDirnameModel(FunctionModel):
    """Model for os.path.dirname()."""

    name = "dirname"
    qualname = "os.path.dirname"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if args and isinstance(args[0], str):
            import os.path

            return ModelResult(value=SymbolicString.from_const(os.path.dirname(args[0])))
        result, constraint = SymbolicString.symbolic(f"dirname_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OsPathBasenameModel(FunctionModel):
    """Model for os.path.basename()."""

    name = "basename"
    qualname = "os.path.basename"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if args and isinstance(args[0], str):
            import os.path

            return ModelResult(value=SymbolicString.from_const(os.path.basename(args[0])))
        result, constraint = SymbolicString.symbolic(f"basename_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OsPathSplitModel(FunctionModel):
    """Model for os.path.split()."""

    name = "split"
    qualname = "os.path.split"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if args and isinstance(args[0], str):
            import os.path

            head, tail = os.path.split(args[0])
            return ModelResult(
                value=(
                    SymbolicString.from_const(head),
                    SymbolicString.from_const(tail),
                )
            )
        head, c1 = SymbolicString.symbolic(f"split_head_{state.pc}")
        tail, c2 = SymbolicString.symbolic(f"split_tail_{state.pc}")
        return ModelResult(value=(head, tail), constraints=[c1, c2])


class OsPathAbspathModel(FunctionModel):
    """Model for os.path.abspath()."""

    name = "abspath"
    qualname = "os.path.abspath"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"abspath_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 1])


class JsonLoadsModel(FunctionModel):
    """Model for json.loads()."""

    name = "loads"
    qualname = "json.loads"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"json_loads_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class JsonDumpsModel(FunctionModel):
    """Model for json.dumps()."""

    name = "dumps"
    qualname = "json.dumps"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"json_dumps_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 2])


class JsonLoadModel(FunctionModel):
    """Model for json.load()."""

    name = "load"
    qualname = "json.load"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"json_load_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            side_effects={"io": True},
        )


class JsonDumpModel(FunctionModel):
    """Model for json.dump()."""

    name = "dump"
    qualname = "json.dump"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        return ModelResult(
            value=SymbolicNone.instance(),
            side_effects={"io": True},
        )


class DatetimeNowModel(FunctionModel):
    """Model for datetime.now()."""

    name = "now"
    qualname = "datetime.datetime.now"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"now_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint, result.is_int, result.z3_int > 1672531200],
        )


class DatetimeConstructorModel(FunctionModel):
    """Model for datetime() constructor."""

    name = "datetime"
    qualname = "datetime.datetime"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"datetime_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class TimedeltaConstructorModel(FunctionModel):
    """Model for timedelta() constructor."""

    name = "timedelta"
    qualname = "datetime.timedelta"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"timedelta_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class RandomRandomModel(FunctionModel):
    """Model for random.random()."""

    name = "random"
    qualname = "random.random"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"random_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[
                constraint,
                result.is_float,
                result.z3_real >= 0,
                result.z3_real < 1,
            ],
        )


class RandomRandintModel(FunctionModel):
    """Model for random.randint()."""

    name = "randint"
    qualname = "random.randint"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"randint_{state.pc}")
        constraints = [constraint, result.is_int]
        if len(args) >= 2:
            a, b = args[0], args[1]
            if isinstance(a, int):
                constraints.append(result.z3_int >= a)
            elif isinstance(a, SymbolicValue):
                constraints.append(result.z3_int >= a.z3_int)
            if isinstance(b, int):
                constraints.append(result.z3_int <= b)
            elif isinstance(b, SymbolicValue):
                constraints.append(result.z3_int <= b.z3_int)
        return ModelResult(value=result, constraints=constraints)


class RandomChoiceModel(FunctionModel):
    """Model for random.choice()."""

    name = "choice"
    qualname = "random.choice"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if args and isinstance(args[0], (list, tuple)) and args[0]:
            result, constraint = SymbolicValue.symbolic(f"choice_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        if args and isinstance(args[0], SymbolicList):
            result, constraint = SymbolicValue.symbolic(f"choice_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint, args[0].z3_len > 0],
            )
        result, constraint = SymbolicValue.symbolic(f"choice_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class RandomShuffleModel(FunctionModel):
    """Model for random.shuffle()."""

    name = "shuffle"
    qualname = "random.shuffle"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        return ModelResult(
            value=SymbolicNone.instance(),
            side_effects={"mutates_arg": 0},
        )


class RandomSampleModel(FunctionModel):
    """Model for random.sample()."""

    name = "sample"
    qualname = "random.sample"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"sample_{state.pc}")
        if len(args) >= 2:
            k = args[1]
            if isinstance(k, int):
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.z3_len == k],
                )
            elif isinstance(k, SymbolicValue):
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.z3_len == k.z3_int],
                )
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class RandomUniformModel(FunctionModel):
    """Model for random.uniform()."""

    name = "uniform"
    qualname = "random.uniform"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"uniform_{state.pc}")
        constraints = [constraint, result.is_float]
        if len(args) >= 2:
            a, b = args[0], args[1]
            if isinstance(a, (int, float)):
                constraints.append(result.z3_real >= a)
            if isinstance(b, (int, float)):
                constraints.append(result.z3_real <= b)
        return ModelResult(value=result, constraints=constraints)


class SimpleNamespaceModel(FunctionModel):
    """Model for types.SimpleNamespace()."""

    name = "SimpleNamespace"
    qualname = "types.SimpleNamespace"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        addr = id(object())
        result, constraint = SymbolicObject.symbolic(f"namespace_{state.pc}", addr)
        obj_state = {}
        if kwargs:
            for k, v in kwargs.items():
                obj_state[k] = v
        state.memory[addr] = obj_state
        return ModelResult(value=result, constraints=[constraint])


class EnumModel(FunctionModel):
    """Model for enum.Enum class construction."""

    name = "Enum"
    qualname = "enum.Enum"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"enum_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class IntEnumModel(FunctionModel):
    """Model for enum.IntEnum class construction."""

    name = "IntEnum"
    qualname = "enum.IntEnum"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"intenum_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class EnumAutoModel(FunctionModel):
    """Model for enum.auto() to generate enum values."""

    name = "auto"
    qualname = "enum.auto"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"enum_auto_{state.pc}")
        return ModelResult(
            value=result, constraints=[constraint, result.is_int, result.z3_int >= 1]
        )


class EnumValueModel(FunctionModel):
    """Model for accessing Enum.value property."""

    name = "value"
    qualname = "enum.Enum.value"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"enum_value_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class EnumNameModel(FunctionModel):
    """Model for accessing Enum.name property."""

    name = "name"
    qualname = "enum.Enum.name"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"enum_name_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class DataclassModel(FunctionModel):
    """Model for @dataclass decorator."""

    name = "dataclass"
    qualname = "dataclasses.dataclass"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if args:
            return ModelResult(value=args[0])
        result, constraint = SymbolicValue.symbolic(f"dataclass_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class DataclassFieldModel(FunctionModel):
    """Model for dataclasses.field() function."""

    name = "field"
    qualname = "dataclasses.field"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        default = kwargs.get("default")
        default_factory = kwargs.get("default_factory")
        if default is not None:
            return ModelResult(value=default)
        if default_factory is not None:
            result, constraint = SymbolicValue.symbolic(f"field_factory_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        result, constraint = SymbolicValue.symbolic(f"field_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class AsDataclassModel(FunctionModel):
    """Model for dataclasses.asdict() function."""

    name = "asdict"
    qualname = "dataclasses.asdict"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicDict.symbolic(f"asdict_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class AstupleModel(FunctionModel):
    """Model for dataclasses.astuple() function."""

    name = "astuple"
    qualname = "dataclasses.astuple"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"astuple_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class FieldsModel(FunctionModel):
    """Model for dataclasses.fields() function."""

    name = "fields"
    qualname = "dataclasses.fields"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"fields_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class ReplaceModel(FunctionModel):
    """Model for dataclasses.replace() function."""

    name = "replace"
    qualname = "dataclasses.replace"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if args:
            addr = id(object())
            result, constraint = SymbolicObject.symbolic(f"replaced_{state.pc}", addr)
            obj_state = {}
            if kwargs:
                for k, v in kwargs.items():
                    obj_state[k] = v
            state.memory[addr] = obj_state
            return ModelResult(value=result, constraints=[constraint])
        result, constraint = SymbolicValue.symbolic(f"replace_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OperatorItemgetterModel(FunctionModel):
    """Model for operator.itemgetter()."""

    name = "itemgetter"
    qualname = "operator.itemgetter"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"itemgetter_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OperatorAttrgetterModel(FunctionModel):
    """Model for operator.attrgetter()."""

    name = "attrgetter"
    qualname = "operator.attrgetter"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"attrgetter_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OperatorAddModel(FunctionModel):
    """Model for operator.add()."""

    name = "add"
    qualname = "operator.add"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if len(args) >= 2:
            a, b = args[0], args[1]
            if isinstance(a, SymbolicValue) and isinstance(b, SymbolicValue):
                return ModelResult(value=a + b)
            if isinstance(a, (int, float)) and isinstance(b, (int, float)):
                return ModelResult(value=SymbolicValue.from_const(a + b))
        result, constraint = SymbolicValue.symbolic(f"op_add_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OperatorSubModel(FunctionModel):
    """Model for operator.sub()."""

    name = "sub"
    qualname = "operator.sub"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if len(args) >= 2:
            a, b = args[0], args[1]
            if isinstance(a, SymbolicValue) and isinstance(b, SymbolicValue):
                return ModelResult(value=a - b)
            if isinstance(a, (int, float)) and isinstance(b, (int, float)):
                return ModelResult(value=SymbolicValue.from_const(a - b))
        result, constraint = SymbolicValue.symbolic(f"op_sub_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OperatorMulModel(FunctionModel):
    """Model for operator.mul()."""

    name = "mul"
    qualname = "operator.mul"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if len(args) >= 2:
            a, b = args[0], args[1]
            if isinstance(a, SymbolicValue) and isinstance(b, SymbolicValue):
                return ModelResult(value=a * b)
            if isinstance(a, (int, float)) and isinstance(b, (int, float)):
                return ModelResult(value=SymbolicValue.from_const(a * b))
        result, constraint = SymbolicValue.symbolic(f"op_mul_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OperatorTruedivModel(FunctionModel):
    """Model for operator.truediv()."""

    name = "truediv"
    qualname = "operator.truediv"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if len(args) >= 2:
            a, b = args[0], args[1]
            if isinstance(a, SymbolicValue) and isinstance(b, SymbolicValue):
                return ModelResult(value=a / b)
        result, constraint = SymbolicValue.symbolic(f"op_truediv_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OperatorFloordivModel(FunctionModel):
    """Model for operator.floordiv()."""

    name = "floordiv"
    qualname = "operator.floordiv"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if len(args) >= 2:
            a, b = args[0], args[1]
            if isinstance(a, SymbolicValue) and isinstance(b, SymbolicValue):
                return ModelResult(value=a // b)
        result, constraint = SymbolicValue.symbolic(f"op_floordiv_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OperatorModModel(FunctionModel):
    """Model for operator.mod()."""

    name = "mod"
    qualname = "operator.mod"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if len(args) >= 2:
            a, b = args[0], args[1]
            if isinstance(a, SymbolicValue) and isinstance(b, SymbolicValue):
                return ModelResult(value=a % b)
        result, constraint = SymbolicValue.symbolic(f"op_mod_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OperatorNegModel(FunctionModel):
    """Model for operator.neg()."""

    name = "neg"
    qualname = "operator.neg"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if args and isinstance(args[0], SymbolicValue):
            return ModelResult(value=-args[0])
        result, constraint = SymbolicValue.symbolic(f"op_neg_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class CopyModel(FunctionModel):
    """Model for copy.copy()."""

    name = "copy"
    qualname = "copy.copy"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if args:
            return ModelResult(value=args[0])
        result, constraint = SymbolicValue.symbolic(f"copy_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class DeepcopyModel(FunctionModel):
    """Model for copy.deepcopy()."""

    name = "deepcopy"
    qualname = "copy.deepcopy"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if args:
            val = args[0]
            if isinstance(val, SymbolicValue):
                result, constraint = SymbolicValue.symbolic(f"deepcopy_{val.name}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.z3_int == val.z3_int],
                )
            if isinstance(val, SymbolicString):
                result, constraint = SymbolicString.symbolic(f"deepcopy_{val.name}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.z3_str == val.z3_str],
                )
            if isinstance(val, SymbolicList):
                result, constraint = SymbolicList.symbolic(f"deepcopy_{val._name}")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.z3_len == val.z3_len],
                )
        result, constraint = SymbolicValue.symbolic(f"deepcopy_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class StringIOModel(FunctionModel):
    """Model for io.StringIO()."""

    name = "StringIO"
    qualname = "io.StringIO"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"stringio_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class BytesIOModel(FunctionModel):
    """Model for io.BytesIO()."""

    name = "BytesIO"
    qualname = "io.BytesIO"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"bytesio_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class IOReadModel(FunctionModel):
    """Model for file.read() / StringIO.read()."""

    name = "read"
    qualname = "io.read"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"io_read_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class IOWriteModel(FunctionModel):
    """Model for file.write() / StringIO.write()."""

    name = "write"
    qualname = "io.write"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        if args and isinstance(args[0], SymbolicString):
            return ModelResult(
                value=SymbolicValue(
                    _name=f"written_{state.pc}",
                    z3_int=args[0].z3_len,
                    is_int=z3.BoolVal(True),
                    z3_bool=z3.BoolVal(False),
                    is_bool=z3.BoolVal(False),
                )
            )
        result, constraint = SymbolicValue.symbolic(f"io_write_{state.pc}")
        return ModelResult(
            value=result, constraints=[constraint, result.is_int, result.z3_int >= 0]
        )


class IOGetvalueModel(FunctionModel):
    """Model for StringIO.getvalue()."""

    name = "getvalue"
    qualname = "io.StringIO.getvalue"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"io_getvalue_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class HeappushModel(FunctionModel):
    """Model for heapq.heappush()."""

    name = "heappush"
    qualname = "heapq.heappush"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        return ModelResult(
            value=SymbolicNone.instance(),
            side_effects={"mutates_arg": 0},
        )


class HeappopModel(FunctionModel):
    """Model for heapq.heappop()."""

    name = "heappop"
    qualname = "heapq.heappop"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"heappop_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            side_effects={"mutates_arg": 0},
        )


class HeapifyModel(FunctionModel):
    """Model for heapq.heapify()."""

    name = "heapify"
    qualname = "heapq.heapify"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        return ModelResult(
            value=SymbolicNone.instance(),
            side_effects={"mutates_arg": 0},
        )


class HeapreplaceModel(FunctionModel):
    """Model for heapq.heapreplace()."""

    name = "heapreplace"
    qualname = "heapq.heapreplace"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"heapreplace_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            side_effects={"mutates_arg": 0},
        )


class HeappushpopModel(FunctionModel):
    """Model for heapq.heappushpop()."""

    name = "heappushpop"
    qualname = "heapq.heappushpop"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"heappushpop_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            side_effects={"mutates_arg": 0},
        )


class NlargestModel(FunctionModel):
    """Model for heapq.nlargest()."""

    name = "nlargest"
    qualname = "heapq.nlargest"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"nlargest_{state.pc}")
        if args and isinstance(args[0], int):
            return ModelResult(
                value=result,
                constraints=[constraint, result.z3_len == args[0]],
            )
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class NsmallestModel(FunctionModel):
    """Model for heapq.nsmallest()."""

    name = "nsmallest"
    qualname = "heapq.nsmallest"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"nsmallest_{state.pc}")
        if args and isinstance(args[0], int):
            return ModelResult(
                value=result,
                constraints=[constraint, result.z3_len == args[0]],
            )
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class BisectLeftModel(FunctionModel):
    """Model for bisect.bisect_left()."""

    name = "bisect_left"
    qualname = "bisect.bisect_left"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"bisect_left_{state.pc}")
        constraints = [constraint, result.is_int, result.z3_int >= 0]
        if len(args) >= 1:
            lst = args[0]
            if isinstance(lst, SymbolicList):
                constraints.append(result.z3_int <= lst.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BisectRightModel(FunctionModel):
    """Model for bisect.bisect_right()."""

    name = "bisect_right"
    qualname = "bisect.bisect_right"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"bisect_right_{state.pc}")
        constraints = [constraint, result.is_int, result.z3_int >= 0]
        if len(args) >= 1:
            lst = args[0]
            if isinstance(lst, SymbolicList):
                constraints.append(result.z3_int <= lst.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BisectModel(FunctionModel):
    """Model for bisect.bisect() (alias for bisect_right)."""

    name = "bisect"
    qualname = "bisect.bisect"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"bisect_{state.pc}")
        constraints = [constraint, result.is_int, result.z3_int >= 0]
        if len(args) >= 1:
            lst = args[0]
            if isinstance(lst, SymbolicList):
                constraints.append(result.z3_int <= lst.z3_len)
        return ModelResult(value=result, constraints=constraints)


class InsortLeftModel(FunctionModel):
    """Model for bisect.insort_left()."""

    name = "insort_left"
    qualname = "bisect.insort_left"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        return ModelResult(
            value=SymbolicNone.instance(),
            side_effects={"mutates_arg": 0},
        )


class InsortRightModel(FunctionModel):
    """Model for bisect.insort_right()."""

    name = "insort_right"
    qualname = "bisect.insort_right"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        return ModelResult(
            value=SymbolicNone.instance(),
            side_effects={"mutates_arg": 0},
        )


class InsortModel(FunctionModel):
    """Model for bisect.insort() (alias for insort_right)."""

    name = "insort"
    qualname = "bisect.insort"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        return ModelResult(
            value=SymbolicNone.instance(),
            side_effects={"mutates_arg": 0},
        )


math_models = [
    MathSqrtModel(),
    MathCeilModel(),
    MathFloorModel(),
    MathLogModel(),
    MathExpModel(),
    MathSinModel(),
    MathCosModel(),
    MathTanModel(),
    MathFabsModel(),
    MathGcdModel(),
    MathIsfiniteModel(),
    MathIsinfModel(),
    MathIsnanModel(),
    MathIsCloseModel(),
]
types_models = [
    SimpleNamespaceModel(),
]
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
ospath_models = [
    OsPathExistsModel(),
    OsPathIsfileModel(),
    OsPathIsdirModel(),
    OsPathJoinModel(),
    OsPathDirnameModel(),
    OsPathBasenameModel(),
    OsPathSplitModel(),
    OsPathAbspathModel(),
]
json_models = [
    JsonLoadsModel(),
    JsonDumpsModel(),
    JsonLoadModel(),
    JsonDumpModel(),
]
re_models = [
    ReMatchModel(),
    ReSearchModel(),
    ReFindallModel(),
    ReSubModel(),
    ReSplitModel(),
    ReCompileModel(),
    ReEscapeModel(),
]
random_models = [
    RandomRandomModel(),
    RandomRandintModel(),
    RandomChoiceModel(),
    RandomShuffleModel(),
    RandomSampleModel(),
    RandomUniformModel(),
]
datetime_models = [
    DatetimeNowModel(),
    DatetimeConstructorModel(),
    TimedeltaConstructorModel(),
]
operator_models = [
    OperatorItemgetterModel(),
    OperatorAttrgetterModel(),
    OperatorAddModel(),
    OperatorSubModel(),
    OperatorMulModel(),
    OperatorTruedivModel(),
    OperatorFloordivModel(),
    OperatorModModel(),
    OperatorNegModel(),
]
copy_models = [
    CopyModel(),
    DeepcopyModel(),
]
io_models = [
    StringIOModel(),
    BytesIOModel(),
    IOReadModel(),
    IOWriteModel(),
    IOGetvalueModel(),
]
heapq_models = [
    HeappushModel(),
    HeappopModel(),
    HeapifyModel(),
    HeapreplaceModel(),
    HeappushpopModel(),
    NlargestModel(),
    NsmallestModel(),
]
bisect_models = [
    BisectLeftModel(),
    BisectRightModel(),
    BisectModel(),
    InsortLeftModel(),
    InsortRightModel(),
    InsortModel(),
]
enum_models = [
    EnumModel(),
    IntEnumModel(),
    EnumAutoModel(),
    EnumValueModel(),
    EnumNameModel(),
]
dataclasses_models = [
    DataclassModel(),
    DataclassFieldModel(),
    AsDataclassModel(),
    AstupleModel(),
    FieldsModel(),
    ReplaceModel(),
]


class ExtendedStdlibRegistry:
    """Registry for extended stdlib models."""

    def __init__(self):
        self._models: dict[str, FunctionModel] = {}
        self._register_all()

    def _register_all(self):
        """Register all stdlib models."""
        from pyspectre.models.sets import SET_MODELS
        from pyspectre.models.pathlib_models import PATHLIB_MODELS

        all_models = (
            math_models
            + collections_models
            + itertools_models
            + functools_models
            + ospath_models
            + json_models
            + re_models
            + random_models
            + datetime_models
            + types_models
            + operator_models
            + copy_models
            + io_models
            + heapq_models
            + bisect_models
            + enum_models
            + dataclasses_models
            + SET_MODELS
            + STRING_MODELS
            + PATHLIB_MODELS
        )
        for model in all_models:
            self.register(model)

    def register(self, model: FunctionModel) -> None:
        """Register a model."""
        self._models[model.name] = model
        self._models[model.qualname] = model

    def get(self, name: str) -> FunctionModel | None:
        """Get a model by name."""
        return self._models.get(name)

    def list_models(self) -> list[str]:
        """List all registered model names."""
        return sorted(set(m.name for m in self._models.values()))

    def list_modules(self) -> dict[str, list[str]]:
        """List models grouped by module."""
        modules = {}
        for model in self._models.values():
            if "." in model.qualname:
                module = model.qualname.rsplit(".", 1)[0]
            else:
                module = "builtins"
            if module not in modules:
                modules[module] = []
            if model.name not in modules[module]:
                modules[module].append(model.name)
        return {k: sorted(v) for k, v in sorted(modules.items())}


extended_stdlib_registry = ExtendedStdlibRegistry()


def get_stdlib_model(name: str) -> FunctionModel | None:
    """Get a stdlib model by name."""
    return extended_stdlib_registry.get(name)


def list_stdlib_models() -> list[str]:
    """List all stdlib models."""
    return extended_stdlib_registry.list_models()


def list_stdlib_modules() -> dict[str, list[str]]:
    """List stdlib models by module."""
    return extended_stdlib_registry.list_modules()
