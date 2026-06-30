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

"""Symbolic models for datetime.

Dates are represented by their proleptic-Gregorian ordinal.  Datetimes are
represented by microseconds since ordinal zero.  Timedeltas are represented by
total microseconds.  This keeps common comparisons and arithmetic in linear
integer arithmetic and avoids eagerly encoding leap-year/month validity.
"""

from __future__ import annotations

import datetime as _datetime
from typing import TYPE_CHECKING, TypeGuard

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

_DATE_MIN_ORDINAL = _datetime.date.min.toordinal()
_DATE_MAX_ORDINAL = _datetime.date.max.toordinal()
_MICROS_PER_DAY = 86_400_000_000
_DATETIME_MAX_MICROS = _DATE_MAX_ORDINAL * _MICROS_PER_DAY + (_MICROS_PER_DAY - 1)


def _const_int(value: StackValue) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, SymbolicValue) and isinstance(value.value, int):
        return value.value
    return None


def _has_affinity(value: StackValue, *names: str) -> TypeGuard[SymbolicValue]:
    return isinstance(value, SymbolicValue) and value.affinity_type in names


def _date_ordinal(value: StackValue) -> int | None:
    if isinstance(value, _datetime.datetime):
        return value.date().toordinal()
    if isinstance(value, _datetime.date):
        return value.toordinal()
    if _has_affinity(value, "datetime.date", "date"):
        return _const_int(value)
    return None


def _datetime_micros(value: StackValue) -> int | None:
    if isinstance(value, _datetime.datetime):
        return _datetime_to_micros(value)
    if _has_affinity(value, "datetime.datetime", "datetime"):
        return _const_int(value)
    return None


def _timedelta_micros(value: StackValue) -> int | None:
    if isinstance(value, _datetime.timedelta):
        return _timedelta_to_micros(value)
    if _has_affinity(value, "datetime.timedelta", "timedelta"):
        return _const_int(value)
    return None


def _timedelta_to_micros(value: _datetime.timedelta) -> int:
    return value.days * _MICROS_PER_DAY + value.seconds * 1_000_000 + value.microseconds


def _datetime_to_micros(value: _datetime.datetime) -> int:
    return (
        value.toordinal() * _MICROS_PER_DAY
        + ((value.hour * 60 + value.minute) * 60 + value.second) * 1_000_000
        + value.microsecond
    )


def _bounded_int_model(
    name: str,
    lower: int,
    upper: int,
    affinity_type: str,
) -> ModelResult:
    value, constraint = SymbolicValue.symbolic_int(name)
    value.affinity_type = affinity_type
    value.min_val = lower
    value.max_val = upper
    return ModelResult(
        value=value,
        constraints=[constraint, value.z3_int >= lower, value.z3_int <= upper],
    )


def _date_value(name: str, ordinal: int | None = None) -> ModelResult:
    if ordinal is not None:
        value = SymbolicValue.from_const(ordinal)
        value.affinity_type = "datetime.date"
        value.min_val = ordinal
        value.max_val = ordinal
        return ModelResult(value=value)
    return _bounded_int_model(name, _DATE_MIN_ORDINAL, _DATE_MAX_ORDINAL, "datetime.date")


def _datetime_value(name: str, micros: int | None = None) -> ModelResult:
    if micros is not None:
        value = SymbolicValue.from_const(micros)
        value.affinity_type = "datetime.datetime"
        value.min_val = micros
        value.max_val = micros
        return ModelResult(value=value)
    return _bounded_int_model(name, 0, _DATETIME_MAX_MICROS, "datetime.datetime")


def _timedelta_value(name: str, micros: int | None = None) -> ModelResult:
    if micros is not None:
        value = SymbolicValue.from_const(micros)
        value.affinity_type = "datetime.timedelta"
        value.min_val = micros
        value.max_val = micros
        return ModelResult(value=value)
    value, constraint = SymbolicValue.symbolic_int(name)
    value.affinity_type = "datetime.timedelta"
    return ModelResult(value=value, constraints=[constraint])


class DateConstructorModel(FunctionModel):
    """Model for datetime.date(year, month, day)."""

    name = "date"
    qualname = "datetime.date"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        if len(args) >= 3:
            year = _const_int(args[0])
            month = _const_int(args[1])
            day = _const_int(args[2])
            if year is not None and month is not None and day is not None:
                try:
                    return _date_value("date", _datetime.date(year, month, day).toordinal())
                except ValueError:
                    pass
        return _date_value(f"date_{state.pc}")


class DateTodayModel(FunctionModel):
    """Model for datetime.date.today()."""

    name = "today"
    qualname = "datetime.date.today"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del args, kwargs
        return _date_value(f"today_{state.pc}")


class DateFromOrdinalModel(FunctionModel):
    """Model for datetime.date.fromordinal()."""

    name = "fromordinal"
    qualname = "datetime.date.fromordinal"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        ordinal = _const_int(args[0]) if args else None
        if ordinal is not None:
            try:
                _datetime.date.fromordinal(ordinal)
                return _date_value("fromordinal", ordinal)
            except ValueError:
                pass
        return _date_value(f"fromordinal_{state.pc}")


class DateToOrdinalModel(FunctionModel):
    """Model for date.toordinal()."""

    aliases = ("date.toordinal",)
    name = "toordinal"
    qualname = "datetime.date.toordinal"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs, state
        if args:
            receiver = args[0]
            if isinstance(receiver, _datetime.date):
                return ModelResult(value=SymbolicValue.from_const(receiver.toordinal()))
            if _has_affinity(receiver, "datetime.date", "date"):
                value = SymbolicValue(
                    _name=f"{receiver.name}.toordinal()",
                    z3_int=receiver.z3_int,
                    is_int=receiver.is_int,
                    z3_bool=receiver.z3_bool,
                    is_bool=receiver.is_bool,
                    z3_float=receiver.z3_float,
                    is_float=receiver.is_float,
                    z3_str=receiver.z3_str,
                    is_str=receiver.is_str,
                    z3_addr=receiver.z3_addr,
                    is_obj=receiver.is_obj,
                    z3_array=receiver.z3_array,
                    is_list=receiver.is_list,
                    is_dict=receiver.is_dict,
                    is_path=receiver.is_path,
                    is_none=receiver.is_none,
                    affinity_type="int",
                    min_val=receiver.min_val,
                    max_val=receiver.max_val,
                )
                return ModelResult(value=value)
        return _bounded_int_model("toordinal", _DATE_MIN_ORDINAL, _DATE_MAX_ORDINAL, "int")


class DatetimeNowModel(FunctionModel):
    """Model for datetime.datetime.now()."""

    name = "now"
    qualname = "datetime.datetime.now"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del args, kwargs
        return _datetime_value(f"now_{state.pc}")


class DatetimeModel(FunctionModel):
    """Model for datetime.datetime() constructor."""

    name = "datetime"
    qualname = "datetime.datetime"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        if len(args) >= 3:
            year = _const_int(args[0])
            month = _const_int(args[1])
            day = _const_int(args[2])
            hour = _const_int(args[3]) if len(args) > 3 else 0
            minute = _const_int(args[4]) if len(args) > 4 else 0
            second = _const_int(args[5]) if len(args) > 5 else 0
            microsecond = _const_int(args[6]) if len(args) > 6 else 0
            if (
                year is not None
                and month is not None
                and day is not None
                and hour is not None
                and minute is not None
                and second is not None
                and microsecond is not None
            ):
                try:
                    concrete = _datetime.datetime(
                        year,
                        month,
                        day,
                        hour,
                        minute,
                        second,
                        microsecond,
                    )
                    return _datetime_value("datetime", _datetime_to_micros(concrete))
                except ValueError:
                    pass
        return _datetime_value(f"datetime_{state.pc}")


class TimedeltaConstructorModel(FunctionModel):
    """Model for datetime.timedelta() constructor."""

    name = "timedelta"
    qualname = "datetime.timedelta"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        days = (
            _const_int(args[0])
            if args
            else _const_int(kwargs.get("days"))
            if "days" in kwargs
            else 0
        )
        seconds = (
            _const_int(args[1])
            if len(args) > 1
            else _const_int(kwargs.get("seconds"))
            if "seconds" in kwargs
            else 0
        )
        microseconds = (
            _const_int(args[2])
            if len(args) > 2
            else _const_int(kwargs.get("microseconds"))
            if "microseconds" in kwargs
            else 0
        )
        if days is not None and seconds is not None and microseconds is not None:
            try:
                concrete = _datetime.timedelta(
                    days=days,
                    seconds=seconds,
                    microseconds=microseconds,
                )
                return _timedelta_value("timedelta", _timedelta_to_micros(concrete))
            except OverflowError:
                pass
        return _timedelta_value(f"timedelta_{state.pc}")


class DateWeekdayModel(FunctionModel):
    """Model for date.weekday()."""

    aliases = ("date.weekday",)
    name = "date_weekday"
    qualname = "datetime.date.weekday"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        ordinal = _date_ordinal(args[0]) if args else None
        if ordinal is not None:
            try:
                return ModelResult(
                    value=SymbolicValue.from_const(_datetime.date.fromordinal(ordinal).weekday()),
                )
            except ValueError:
                pass
        return _bounded_int_model(f"date_weekday_{state.pc}", 0, 6, "int")


class DateIsoformatModel(FunctionModel):
    """Model for date.isoformat()."""

    aliases = ("date.isoformat",)
    name = "date_isoformat"
    qualname = "datetime.date.isoformat"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        ordinal = _date_ordinal(args[0]) if args else None
        if ordinal is not None:
            try:
                from pysymex._internal.core.types.scalars.strings import SymbolicString

                return ModelResult(
                    value=SymbolicString.from_const(
                        _datetime.date.fromordinal(ordinal).isoformat(),
                    ),
                )
            except ValueError:
                pass
        from pysymex._internal.core.types.scalars.strings import SymbolicString

        value, constraint = SymbolicString.symbolic(f"date_isoformat_{state.pc}")
        return ModelResult(value=value, constraints=[constraint, value.z3_len == 10])


class DateReplaceModel(FunctionModel):
    """Model for date.replace() with exact concrete receiver/fields."""

    aliases = ("date.replace",)
    name = "date_replace"
    qualname = "datetime.date.replace"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        ordinal = _date_ordinal(args[0]) if args else None
        if ordinal is not None:
            try:
                base = _datetime.date.fromordinal(ordinal)
                year = _const_int(kwargs.get("year")) if "year" in kwargs else base.year
                month = _const_int(kwargs.get("month")) if "month" in kwargs else base.month
                day = _const_int(kwargs.get("day")) if "day" in kwargs else base.day
                if year is not None and month is not None and day is not None:
                    return _date_value(
                        "date_replace",
                        base.replace(year=year, month=month, day=day).toordinal(),
                    )
            except ValueError:
                pass
        return _date_value(f"date_replace_{state.pc}")


class DatetimeDateModel(FunctionModel):
    """Model for datetime.date()."""

    aliases: tuple[str, ...] = ()
    name = "datetime_date"
    qualname = "datetime.datetime.date"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        micros = _datetime_micros(args[0]) if args else None
        if micros is not None:
            return _date_value("datetime_date", micros // _MICROS_PER_DAY)
        return _date_value(f"datetime_date_{state.pc}")


class DatetimeTimestampModel(FunctionModel):
    """Model for datetime.timestamp()."""

    aliases = ("datetime.timestamp",)
    name = "datetime_timestamp"
    qualname = "datetime.datetime.timestamp"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        micros = _datetime_micros(args[0]) if args else None
        if micros is not None:
            return ModelResult(value=SymbolicValue.from_const(micros / 1_000_000.0))
        value, constraint = SymbolicValue.symbolic_float(f"datetime_timestamp_{state.pc}")
        return ModelResult(value=value, constraints=[constraint])


class TotalSecondsModel(FunctionModel):
    """Model for timedelta.total_seconds()."""

    aliases = ("timedelta.total_seconds",)
    name = "timedelta_total_seconds"
    qualname = "datetime.timedelta.total_seconds"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        micros = _timedelta_micros(args[0]) if args else None
        if micros is not None:
            return ModelResult(value=SymbolicValue.from_const(micros / 1_000_000.0))
        value, constraint = SymbolicValue.symbolic_float(f"timedelta_total_seconds_{state.pc}")
        return ModelResult(value=value, constraints=[constraint])


datetime_models = [
    DateConstructorModel(),
    DateTodayModel(),
    DateFromOrdinalModel(),
    DateToOrdinalModel(),
    DateWeekdayModel(),
    DateIsoformatModel(),
    DateReplaceModel(),
    DatetimeNowModel(),
    DatetimeModel(),
    DatetimeDateModel(),
    DatetimeTimestampModel(),
    TimedeltaConstructorModel(),
    TotalSecondsModel(),
]
