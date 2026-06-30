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

"""Models for the time standard-library module."""

from __future__ import annotations

import time as _time
from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult, SideEffects
from pysymex._internal.models.stdlib.coercion import const_float, symbolic_object

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class TimeTimeModel(FunctionModel):
    """Model for clock functions returning non-negative seconds."""

    aliases = ("time.monotonic", "time.perf_counter", "time.process_time")
    name = "time"
    qualname = "time.time"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del args, kwargs
        value, constraint = SymbolicValue.symbolic_float(f"time_{state.pc}")
        return ModelResult(
            value=value,
            constraints=[constraint, z3.fpGEQ(value.z3_float, z3.FPVal(0.0, z3.Float64()))],
        )


class TimeStructTimeModel(FunctionModel):
    """Model for localtime/gmtime returning a time.struct_time-like object."""

    aliases = ("time.gmtime",)
    name = "localtime"
    qualname = "time.localtime"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        if args:
            timestamp = const_float(args[0])
            if timestamp is not None:
                try:
                    return ModelResult(value=_time.localtime(timestamp))
                except (OverflowError, OSError, ValueError):
                    pass
        value, constraint = symbolic_object(f"struct_time_{state.pc}", "time.struct_time")
        return ModelResult(value=value, constraints=[constraint])


class TimeSleepModel(FunctionModel):
    """Validate ``time.sleep`` without delaying the analyzer process."""

    name = "sleep"
    qualname = "time.sleep"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del state
        if kwargs or len(args) != 1:
            return ModelResult.none(
                SideEffects.type_error(self.qualname, "sleep() takes one argument"),
            )
        delay = const_float(args[0])
        if delay is not None and delay < 0:
            return ModelResult.none(
                SideEffects.value_error(self.qualname, "sleep length must be non-negative"),
            )
        return ModelResult.none({"time": True})


time_models: list[FunctionModel] = [
    TimeTimeModel(),
    TimeStructTimeModel(),
    TimeSleepModel(),
]
