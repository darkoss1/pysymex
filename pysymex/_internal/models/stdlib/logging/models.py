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

"""Symbolic models for the logging module."""

from __future__ import annotations

import logging as real_logging
from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class GetLoggerModel(FunctionModel):
    """Model for logging.getLogger()."""

    name = "getLogger"
    qualname = "logging.getLogger"

    def __init__(self) -> None:
        """Initialize loggers cache."""
        self.loggers: dict[str | None, SymbolicValue] = {}

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        name_val: str | None = None
        name_arg = kwargs.get("name")
        if name_arg is None and args:
            name_arg = args[0]

        is_none_arg = False
        if (
            name_arg is None
            or isinstance(name_arg, SymbolicNoneType)
            or (isinstance(name_arg, SymbolicValue) and name_arg.value is None)
        ):
            is_none_arg = True

        if is_none_arg:
            name_val = ""
        elif name_arg is not None:
            if isinstance(name_arg, str):
                name_val = name_arg
            elif isinstance(name_arg, SymbolicString):
                if z3.is_string_value(name_arg.z3_str):
                    name_val = name_arg.z3_str.as_string()
            elif isinstance(name_arg, SymbolicValue) and isinstance(name_arg.value, str):
                name_val = name_arg.value

        if name_val is not None:
            if name_val in self.loggers:
                return ModelResult(value=self.loggers[name_val])
            name_safe = name_val.replace(".", "_") if name_val else "root"
            result, constraint = SymbolicValue.symbolic(f"logger_{name_safe}_{state.pc}")
            result.affinity_type = "logging.Logger"
            self.loggers[name_val] = result
            return ModelResult(value=result, constraints=[constraint])

        result, constraint = SymbolicValue.symbolic(f"logger_{state.pc}")
        result.affinity_type = "logging.Logger"
        return ModelResult(value=result, constraints=[constraint])


class GetLoggerClassModel(FunctionModel):
    """Model for logging.getLoggerClass()."""

    name = "getLoggerClass"
    qualname = "logging.getLoggerClass"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"loggerclass_{state.pc}")
        result.affinity_type = "type"
        return ModelResult(value=result, constraints=[constraint])


class LogRecordFactoryModel(FunctionModel):
    """Model for logging.getLogRecordFactory()."""

    name = "getLogRecordFactory"
    qualname = "logging.getLogRecordFactory"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"logrecordfactory_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class ModuleLogModel(FunctionModel):
    """Model for module-level log function calls (debug, info, warning, etc.)."""

    name = "log"
    qualname = "logging.log"
    aliases = (
        "debug",
        "info",
        "warning",
        "warn",
        "error",
        "critical",
        "fatal",
        "exception",
        "logging.debug",
        "logging.info",
        "logging.warning",
        "logging.warn",
        "logging.error",
        "logging.critical",
        "logging.fatal",
        "logging.exception",
    )

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return ModelResult.none(side_effects={"io": True})


class ModuleVoidModel(FunctionModel):
    """Model for module-level logging configuration functions (disable, basicConfig, etc.)."""

    name = "disable"
    qualname = "logging.disable"
    aliases = (
        "addLevelName",
        "basicConfig",
        "shutdown",
        "setLoggerClass",
        "setLogRecordFactory",
        "captureWarnings",
        "logging.addLevelName",
        "logging.basicConfig",
        "logging.shutdown",
        "logging.setLoggerClass",
        "logging.setLogRecordFactory",
        "logging.captureWarnings",
    )

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return ModelResult.none()


class GetLevelNameModel(FunctionModel):
    """Model for logging.getLevelName()."""

    name = "getLevelName"
    qualname = "logging.getLevelName"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        concrete_level: int | str | None = None
        if args:
            arg = args[0]
            if isinstance(arg, (int, str)):
                concrete_level = arg
            elif isinstance(arg, SymbolicValue) and arg.value is not None:
                if isinstance(arg.value, (int, str)):
                    concrete_level = arg.value
            elif isinstance(arg, SymbolicString) and z3.is_string_value(arg.z3_str):
                concrete_level = arg.z3_str.as_string()

        if concrete_level is not None:
            level_names = real_logging.getLevelNamesMapping()
            if isinstance(concrete_level, int):
                resolved_name = next(
                    (name for name, level in level_names.items() if level == concrete_level),
                    None,
                )
                res_val: int | str = (
                    resolved_name if resolved_name is not None else f"Level {concrete_level}"
                )
            else:
                resolved_level = level_names.get(concrete_level)
                res_val = (
                    resolved_level if resolved_level is not None else f"Level {concrete_level}"
                )
            if isinstance(res_val, str):
                return ModelResult(value=SymbolicString.from_const(res_val))
            return ModelResult(value=SymbolicValue.from_const(res_val))

        result, constraint = SymbolicValue.symbolic(f"levelname_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class MakeLogRecordModel(FunctionModel):
    """Model for logging.makeLogRecord()."""

    name = "makeLogRecord"
    qualname = "logging.makeLogRecord"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"logrecord_{state.pc}")
        result.affinity_type = "logging.LogRecord"
        return ModelResult(value=result, constraints=[constraint])


class LoggerConstructorModel(FunctionModel):
    """Model for logging.Logger constructor."""

    name = "Logger"
    qualname = "logging.Logger"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"logger_{state.pc}")
        result.affinity_type = "logging.Logger"
        return ModelResult(value=result, constraints=[constraint])


class HandlerConstructorModel(FunctionModel):
    """Model for logging Handler classes (Handler, StreamHandler, FileHandler, NullHandler)."""

    name = "Handler"
    qualname = "logging.Handler"
    aliases = (
        "StreamHandler",
        "FileHandler",
        "NullHandler",
        "logging.StreamHandler",
        "logging.FileHandler",
        "logging.NullHandler",
    )

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"handler_{state.pc}")
        result.affinity_type = "logging.Handler"
        return ModelResult(value=result, constraints=[constraint])


class FormatterConstructorModel(FunctionModel):
    """Model for logging.Formatter constructor."""

    name = "Formatter"
    qualname = "logging.Formatter"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"formatter_{state.pc}")
        result.affinity_type = "logging.Formatter"
        return ModelResult(value=result, constraints=[constraint])


class FilterConstructorModel(FunctionModel):
    """Model for logging.Filter constructor."""

    name = "Filter"
    qualname = "logging.Filter"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"filter_{state.pc}")
        result.affinity_type = "logging.Filter"
        return ModelResult(value=result, constraints=[constraint])


class LogRecordConstructorModel(FunctionModel):
    """Model for logging.LogRecord constructor."""

    name = "LogRecord"
    qualname = "logging.LogRecord"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"logrecord_{state.pc}")
        result.affinity_type = "logging.LogRecord"
        return ModelResult(value=result, constraints=[constraint])


class LoggerLogMethodModel(FunctionModel):
    """Model for Logger logging methods (debug, info, error, critical, etc.)."""

    name = "Logger.log"
    qualname = "logging.Logger.log"
    aliases = (
        "logging.Logger.debug",
        "logging.Logger.info",
        "logging.Logger.warning",
        "logging.Logger.warn",
        "logging.Logger.error",
        "logging.Logger.critical",
        "logging.Logger.fatal",
        "logging.Logger.exception",
        "logging.Logger.log",
        "Logger.debug",
        "Logger.info",
        "Logger.warning",
        "Logger.warn",
        "Logger.error",
        "Logger.critical",
        "Logger.fatal",
        "Logger.exception",
        "Logger.log",
    )

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return ModelResult.none(side_effects={"io": True})


class LoggerSetLevelModel(FunctionModel):
    """Model for Logger.setLevel()."""

    name = "Logger.setLevel"
    qualname = "logging.Logger.setLevel"
    aliases = ("logging.Logger.setLevel", "Logger.setLevel")

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return ModelResult.none()


class LoggerIsEnabledForModel(FunctionModel):
    """Model for Logger.isEnabledFor()."""

    name = "Logger.isEnabledFor"
    qualname = "logging.Logger.isEnabledFor"
    aliases = ("logging.Logger.isEnabledFor", "Logger.isEnabledFor")

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic_bool(f"logger_isenabled_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class LoggerEffectiveLevelModel(FunctionModel):
    """Model for Logger.getEffectiveLevel()."""

    name = "Logger.getEffectiveLevel"
    qualname = "logging.Logger.getEffectiveLevel"
    aliases = ("logging.Logger.getEffectiveLevel", "Logger.getEffectiveLevel")

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic_int(f"logger_effectivelevel_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_int >= 0])


class LoggerAddHandlerModel(FunctionModel):
    """Model for Logger.addHandler() and Logger.removeHandler()."""

    name = "Logger.addHandler"
    qualname = "logging.Logger.addHandler"
    aliases = (
        "logging.Logger.addHandler",
        "logging.Logger.removeHandler",
        "Logger.addHandler",
        "Logger.removeHandler",
    )

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return ModelResult.none()


class LoggerHasHandlersModel(FunctionModel):
    """Model for Logger.hasHandlers()."""

    name = "Logger.hasHandlers"
    qualname = "logging.Logger.hasHandlers"
    aliases = ("logging.Logger.hasHandlers", "Logger.hasHandlers")

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic_bool(f"logger_hashandlers_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class HandlerMethodModel(FunctionModel):
    """Model for Handler instance configuration methods (setLevel, setFormatter, etc.)."""

    name = "Handler.method"
    qualname = "logging.Handler.method"
    aliases = (
        "logging.Handler.setLevel",
        "logging.Handler.setFormatter",
        "logging.Handler.addFilter",
        "logging.Handler.removeFilter",
        "Handler.setLevel",
        "Handler.setFormatter",
        "Handler.addFilter",
        "Handler.removeFilter",
    )

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return ModelResult.none()


logging_models = [
    GetLoggerModel(),
    GetLoggerClassModel(),
    LogRecordFactoryModel(),
    ModuleLogModel(),
    ModuleVoidModel(),
    GetLevelNameModel(),
    MakeLogRecordModel(),
    LoggerConstructorModel(),
    HandlerConstructorModel(),
    FormatterConstructorModel(),
    FilterConstructorModel(),
    LogRecordConstructorModel(),
    LoggerLogMethodModel(),
    LoggerSetLevelModel(),
    LoggerIsEnabledForModel(),
    LoggerEffectiveLevelModel(),
    LoggerAddHandlerModel(),
    LoggerHasHandlersModel(),
    HandlerMethodModel(),
]
