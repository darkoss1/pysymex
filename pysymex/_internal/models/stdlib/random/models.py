# pysymex: python symbolic execution & formal verification
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

"""Symbolic models for random."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class RandomRandomModel(FunctionModel):
    """Model for random.random()."""

    name = "random"
    qualname = "random.random"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"random_{state.pc}")
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
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic_int(f"randint_{state.pc}")
        constraints = [constraint]
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
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
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

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return ModelResult.none({"mutates_arg": 0})


class RandomSampleModel(FunctionModel):
    """Model for random.sample()."""

    name = "sample"
    qualname = "random.sample"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"sample_{state.pc}")
        if len(args) >= 2:
            k = args[1]
            if isinstance(k, int):
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.z3_len == k],
                )
            if isinstance(k, SymbolicValue):
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
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"uniform_{state.pc}")
        constraints: list[z3.BoolRef] = [constraint, result.is_float]
        if len(args) >= 2:
            a, b = args[0], args[1]
            if isinstance(a, (int, float)):
                constraints.append(z3.fpGEQ(result.z3_float, z3.FPVal(float(a), z3.Float64())))
            if isinstance(b, (int, float)):
                constraints.append(z3.fpLEQ(result.z3_float, z3.FPVal(float(b), z3.Float64())))
        return ModelResult(value=result, constraints=constraints)


random_models = [
    RandomRandomModel(),
    RandomRandintModel(),
    RandomChoiceModel(),
    RandomShuffleModel(),
    RandomSampleModel(),
    RandomUniformModel(),
]
