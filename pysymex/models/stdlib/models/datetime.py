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

"""Symbolic models for datetime."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


class DatetimeNowModel(FunctionModel):
    """Model for datetime.now()."""

    name = "now"
    qualname = "datetime.datetime.now"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"now_{state.pc}")
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
        result, constraint = SymbolicValue.symbolic(f"datetime_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


class TimedeltaConstructorModel(FunctionModel):
    """Model for timedelta() constructor."""

    name = "timedelta"
    qualname = "datetime.timedelta"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"timedelta_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


datetime_models = [
    DatetimeNowModel(),
    DatetimeConstructorModel(),
    TimedeltaConstructorModel(),
]


__all__ = [
    "DatetimeConstructorModel",
    "DatetimeNowModel",
    "TimedeltaConstructorModel",
    "datetime_models",
]
