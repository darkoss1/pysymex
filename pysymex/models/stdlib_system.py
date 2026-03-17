"""Symbolic models for os.path, json, datetime, random, types modules.

Models:
- os.path: exists, isfile, isdir, join, dirname, basename, split, abspath
- json: loads, dumps, load, dump
- datetime: now, datetime, timedelta
- random: random, randint, choice, shuffle, sample, uniform
- types: SimpleNamespace
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.core.addressing import next_address
from pysymex.core.types import (
    SymbolicList,
    SymbolicNone,
    SymbolicObject,
    SymbolicString,
    SymbolicValue,
)
from pysymex.models.builtins import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState


class OsPathExistsModel(FunctionModel):
    """Model for os.path.exists()."""

    name = "exists"
    qualname = "os.path.exists"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"exists_{state .pc }")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class OsPathIsfileModel(FunctionModel):
    """Model for os.path.isfile()."""

    name = "isfile"
    qualname = "os.path.isfile"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"isfile_{state .pc }")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class OsPathIsdirModel(FunctionModel):
    """Model for os.path.isdir()."""

    name = "isdir"
    qualname = "os.path.isdir"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"isdir_{state .pc }")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class OsPathJoinModel(FunctionModel):
    """Model for os.path.join()."""

    name = "join"
    qualname = "os.path.join"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if all(isinstance(a, str) for a in args):
            import os.path
            from typing import cast

            return ModelResult(
                value=SymbolicString.from_const(os.path.join(*cast("list[str]", args)))
            )
        result, constraint = SymbolicString.symbolic(f"pathjoin_{state .pc }")
        return ModelResult(value=result, constraints=[constraint])


class OsPathDirnameModel(FunctionModel):
    """Model for os.path.dirname()."""

    name = "dirname"
    qualname = "os.path.dirname"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if args and isinstance(args[0], str):
            import os.path

            return ModelResult(value=SymbolicString.from_const(os.path.dirname(args[0])))
        result, constraint = SymbolicString.symbolic(f"dirname_{state .pc }")
        return ModelResult(value=result, constraints=[constraint])


class OsPathBasenameModel(FunctionModel):
    """Model for os.path.basename()."""

    name = "basename"
    qualname = "os.path.basename"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if args and isinstance(args[0], str):
            import os.path

            return ModelResult(value=SymbolicString.from_const(os.path.basename(args[0])))
        result, constraint = SymbolicString.symbolic(f"basename_{state .pc }")
        return ModelResult(value=result, constraints=[constraint])


class OsPathSplitModel(FunctionModel):
    """Model for os.path.split()."""

    name = "split"
    qualname = "os.path.split"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if args and isinstance(args[0], str):
            import os.path

            head, tail = os.path.split(args[0])
            return ModelResult(
                value=(
                    SymbolicString.from_const(head),
                    SymbolicString.from_const(tail),
                )
            )
        head, c1 = SymbolicString.symbolic(f"split_head_{state .pc }")
        tail, c2 = SymbolicString.symbolic(f"split_tail_{state .pc }")
        return ModelResult(value=(head, tail), constraints=[c1, c2])


class OsPathAbspathModel(FunctionModel):
    """Model for os.path.abspath()."""

    name = "abspath"
    qualname = "os.path.abspath"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"abspath_{state .pc }")
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 1])


class JsonLoadsModel(FunctionModel):
    """Model for json.loads()."""

    name = "loads"
    qualname = "json.loads"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"json_loads_{state .pc }")
        return ModelResult(value=result, constraints=[constraint])


class JsonDumpsModel(FunctionModel):
    """Model for json.dumps()."""

    name = "dumps"
    qualname = "json.dumps"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"json_dumps_{state .pc }")
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 2])


class JsonLoadModel(FunctionModel):
    """Model for json.load()."""

    name = "load"
    qualname = "json.load"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"json_load_{state .pc }")
        return ModelResult(
            value=result,
            constraints=[constraint],
            side_effects={"io": True},
        )


class JsonDumpModel(FunctionModel):
    """Model for json.dump()."""

    name = "dump"
    qualname = "json.dump"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        return ModelResult(
            value=SymbolicNone("none"),
            side_effects={"io": True},
        )


class DatetimeNowModel(FunctionModel):
    """Model for datetime.now()."""

    name = "now"
    qualname = "datetime.datetime.now"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"now_{state .pc }")
        return ModelResult(
            value=result,
            constraints=[constraint, result.is_int, result.z3_int > 1672531200],
        )


class DatetimeConstructorModel(FunctionModel):
    """Model for datetime() constructor."""

    name = "datetime"
    qualname = "datetime.datetime"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"datetime_{state .pc }")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class TimedeltaConstructorModel(FunctionModel):
    """Model for timedelta() constructor."""

    name = "timedelta"
    qualname = "datetime.timedelta"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"timedelta_{state .pc }")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class RandomRandomModel(FunctionModel):
    """Model for random.random()."""

    name = "random"
    qualname = "random.random"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"random_{state .pc }")
        return ModelResult(
            value=result,
            constraints=[
                constraint,
                result.is_float,
                z3.fpGEQ(result.z3_float, z3.FPVal(0.0, z3.Float64())),
                z3.fpLT(result.z3_float, z3.FPVal(1.0, z3.Float64())),
            ],
        )


class RandomRandintModel(FunctionModel):
    """Model for random.randint()."""

    name = "randint"
    qualname = "random.randint"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"randint_{state .pc }")
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

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if args and isinstance(args[0], (list, tuple)) and args[0]:
            result, constraint = SymbolicValue.symbolic(f"choice_{state .pc }")
            return ModelResult(value=result, constraints=[constraint])
        if args and isinstance(args[0], SymbolicList):
            result, constraint = SymbolicValue.symbolic(f"choice_{state .pc }")
            return ModelResult(
                value=result,
                constraints=[constraint, args[0].z3_len > 0],
            )
        result, constraint = SymbolicValue.symbolic(f"choice_{state .pc }")
        return ModelResult(value=result, constraints=[constraint])


class RandomShuffleModel(FunctionModel):
    """Model for random.shuffle()."""

    name = "shuffle"
    qualname = "random.shuffle"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        return ModelResult(
            value=SymbolicNone("none"),
            side_effects={"mutates_arg": 0},
        )


class RandomSampleModel(FunctionModel):
    """Model for random.sample()."""

    name = "sample"
    qualname = "random.sample"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"sample_{state .pc }")
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

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"uniform_{state .pc }")
        constraints: list[object] = [constraint, result.is_float]
        if len(args) >= 2:
            a, b = args[0], args[1]
            if isinstance(a, (int, float)):
                constraints.append(z3.fpGEQ(result.z3_float, z3.FPVal(float(a), z3.Float64())))
            if isinstance(b, (int, float)):
                constraints.append(z3.fpLEQ(result.z3_float, z3.FPVal(float(b), z3.Float64())))
        return ModelResult(value=result, constraints=constraints)


class SimpleNamespaceModel(FunctionModel):
    """Model for types.SimpleNamespace()."""

    name = "SimpleNamespace"
    qualname = "types.SimpleNamespace"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        addr = next_address()
        result, constraint = SymbolicObject.symbolic(f"namespace_{state .pc }", addr)
        obj_state = {}
        if kwargs:
            for k, v in kwargs.items():
                obj_state[k] = v
        state.memory[addr] = obj_state
        return ModelResult(value=result, constraints=[constraint])


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
datetime_models = [
    DatetimeNowModel(),
    DatetimeConstructorModel(),
    TimedeltaConstructorModel(),
]
random_models = [
    RandomRandomModel(),
    RandomRandintModel(),
    RandomChoiceModel(),
    RandomShuffleModel(),
    RandomSampleModel(),
    RandomUniformModel(),
]
types_models = [
    SimpleNamespaceModel(),
]