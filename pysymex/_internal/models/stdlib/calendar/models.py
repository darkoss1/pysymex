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

"""Models for the calendar standard-library module."""

from __future__ import annotations

import calendar as _calendar
from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult
from pysymex._internal.models.stdlib.coercion import const_int, symbolic_int_range

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class CalendarIsLeapModel(FunctionModel):
    """Model for calendar.isleap()."""

    name = "isleap"
    qualname = "calendar.isleap"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        if args:
            year = const_int(args[0])
            if year is not None:
                return ModelResult(value=SymbolicValue.from_const(_calendar.isleap(year)))
        value, constraint = SymbolicValue.symbolic_bool(f"isleap_{state.pc}")
        return ModelResult(value=value, constraints=[constraint])


class CalendarMonthRangeModel(FunctionModel):
    """Model for calendar.monthrange()."""

    name = "monthrange"
    qualname = "calendar.monthrange"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        if len(args) >= 2:
            year = const_int(args[0])
            month = const_int(args[1])
            if year is not None and month is not None:
                try:
                    return ModelResult(value=_calendar.monthrange(year, month))
                except ValueError:
                    pass
        first = symbolic_int_range(f"monthrange_first_{state.pc}", 0, 6)
        days = symbolic_int_range(f"monthrange_days_{state.pc}", 28, 31)
        return ModelResult(
            value=(first.value, days.value),
            constraints=[*first.constraints, *days.constraints],
        )


class CalendarWeekdayModel(FunctionModel):
    """Model for calendar.weekday()."""

    name = "weekday"
    qualname = "calendar.weekday"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        if len(args) >= 3:
            year = const_int(args[0])
            month = const_int(args[1])
            day = const_int(args[2])
            if year is not None and month is not None and day is not None:
                try:
                    return ModelResult(
                        value=SymbolicValue.from_const(_calendar.weekday(year, month, day)),
                    )
                except ValueError:
                    pass
        return symbolic_int_range(f"weekday_{state.pc}", 0, 6)


calendar_models: list[FunctionModel] = [
    CalendarIsLeapModel(),
    CalendarMonthRangeModel(),
    CalendarWeekdayModel(),
]
