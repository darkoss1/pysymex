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

"""Unit tests for the stdlib logging models."""

import logging

import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.calls.model.dispatch import apply_model
from pysymex._internal.models.registry import RuntimeModelRegistry
from pysymex._internal.models.stdlib.logging.models import (
    FilterConstructorModel,
    FormatterConstructorModel,
    GetLevelNameModel,
    GetLoggerClassModel,
    GetLoggerModel,
    HandlerConstructorModel,
    HandlerMethodModel,
    LoggerAddHandlerModel,
    LoggerConstructorModel,
    LoggerEffectiveLevelModel,
    LoggerHasHandlersModel,
    LoggerIsEnabledForModel,
    LoggerLogMethodModel,
    LoggerSetLevelModel,
    LogRecordConstructorModel,
    LogRecordFactoryModel,
    MakeLogRecordModel,
    ModuleLogModel,
    ModuleVoidModel,
)


def _state() -> VMState:
    return VMState(pc=0)


def test_logging_family_is_canonical_for_lookup_and_concrete_dispatch() -> None:
    """Rich logging models own both named and concrete-callable resolution."""
    assert isinstance(RuntimeModelRegistry.default().resolve("logging.getLogger"), GetLoggerModel)

    result = apply_model(_state(), logging.getLogger, ["test"])

    assert result is not None
    assert len(result.new_states) == 1
    value = result.new_states[0].stack[-1]
    assert isinstance(value, SymbolicValue)
    assert value.affinity_type == "logging.Logger"


def test_get_logger_model_caching() -> None:
    """Test that GetLoggerModel caches loggers correctly by name."""
    model = GetLoggerModel()
    state = _state()

    # Get a logger with a concrete string name
    res1 = model.apply(["my_module"], {}, state)
    assert isinstance(res1.value, SymbolicValue)
    assert res1.value.affinity_type == "logging.Logger"

    # Get it again and check it returns the cached object
    res2 = model.apply(["my_module"], {}, state)
    assert res1.value is res2.value

    # Root logger
    res_root = model.apply([SymbolicNoneType()], {}, state)
    assert isinstance(res_root.value, SymbolicValue)
    assert res_root.value.affinity_type == "logging.Logger"

    # Get root logger again
    res_root2 = model.apply([], {}, state)
    assert res_root.value is res_root2.value


def test_get_logger_symbolic_name() -> None:
    """Test that GetLoggerModel handles symbolic name arguments gracefully."""
    model = GetLoggerModel()
    state = _state()

    sym_name, _ = SymbolicString.symbolic("sym_name")
    res = model.apply([sym_name], {}, state)
    assert isinstance(res.value, SymbolicValue)
    assert res.value.affinity_type == "logging.Logger"


def test_module_log_model() -> None:
    """Test that ModuleLogModel applies without exceptions and returns None."""
    model = ModuleLogModel()
    state = _state()

    res = model.apply(["message"], {}, state)
    assert isinstance(res.value, SymbolicNoneType)
    assert res.side_effects.get("io") is True


def test_module_void_model() -> None:
    """Test that ModuleVoidModel returns None with no side effects."""
    model = ModuleVoidModel()
    state = _state()

    res = model.apply([], {}, state)
    assert isinstance(res.value, SymbolicNoneType)
    assert not res.side_effects


def test_get_level_name_model_concrete() -> None:
    """Test that GetLevelNameModel resolves concrete values using stdlib mapping."""
    model = GetLevelNameModel()
    state = _state()

    # Int level -> String name
    res_info = model.apply([20], {}, state)
    assert isinstance(res_info.value, SymbolicString)
    assert z3.is_string_value(res_info.value.z3_str)
    assert res_info.value.z3_str.as_string() == "INFO"

    # String name -> Int level
    res_error = model.apply(["ERROR"], {}, state)
    assert isinstance(res_error.value, SymbolicValue)
    assert res_error.value.value == 40


def test_get_level_name_model_symbolic() -> None:
    """Test that GetLevelNameModel returns a symbolic value for symbolic level."""
    model = GetLevelNameModel()
    state = _state()
    sym_level, _ = SymbolicValue.symbolic("sym_level")
    res = model.apply([sym_level], {}, state)
    assert isinstance(res.value, SymbolicValue)
    assert res.value.type_tag == "object"


def test_logger_methods() -> None:
    """Test Logger log method, level setting, effective level and handlers models."""
    state = _state()

    # Log method
    log_model = LoggerLogMethodModel()
    res_log = log_model.apply(["msg"], {}, state)
    assert isinstance(res_log.value, SymbolicNoneType)
    assert res_log.side_effects.get("io") is True

    # SetLevel method
    set_level_model = LoggerSetLevelModel()
    res_set = set_level_model.apply([20], {}, state)
    assert isinstance(res_set.value, SymbolicNoneType)

    # IsEnabledFor method
    enabled_model = LoggerIsEnabledForModel()
    res_enabled = enabled_model.apply([20], {}, state)
    assert isinstance(res_enabled.value, SymbolicValue)
    assert res_enabled.value.is_bool is not None

    # GetEffectiveLevel method
    eff_model = LoggerEffectiveLevelModel()
    res_eff = eff_model.apply([], {}, state)
    assert isinstance(res_eff.value, SymbolicValue)
    assert res_eff.value.is_int is not None

    # AddHandler method
    add_hdlr_model = LoggerAddHandlerModel()
    res_add = add_hdlr_model.apply(["hdlr"], {}, state)
    assert isinstance(res_add.value, SymbolicNoneType)

    # HasHandlers method
    has_model = LoggerHasHandlersModel()
    res_has = has_model.apply([], {}, state)
    assert isinstance(res_has.value, SymbolicValue)
    assert res_has.value.is_bool is not None


def test_constructors() -> None:
    """Test constructors for Logger, Handler, Formatter, Filter, and LogRecord."""
    state = _state()

    # Logger constructor
    logger_res = LoggerConstructorModel().apply(["name"], {}, state)
    assert isinstance(logger_res.value, SymbolicValue)
    assert logger_res.value.affinity_type == "logging.Logger"

    # Handler constructor
    handler_res = HandlerConstructorModel().apply([], {}, state)
    assert isinstance(handler_res.value, SymbolicValue)
    assert handler_res.value.affinity_type == "logging.Handler"

    # Formatter constructor
    formatter_res = FormatterConstructorModel().apply([], {}, state)
    assert isinstance(formatter_res.value, SymbolicValue)
    assert formatter_res.value.affinity_type == "logging.Formatter"

    # Filter constructor
    filter_res = FilterConstructorModel().apply([], {}, state)
    assert isinstance(filter_res.value, SymbolicValue)
    assert filter_res.value.affinity_type == "logging.Filter"

    # LogRecord constructor
    logrecord_res = LogRecordConstructorModel().apply([], {}, state)
    assert isinstance(logrecord_res.value, SymbolicValue)
    assert logrecord_res.value.affinity_type == "logging.LogRecord"


def test_handler_method_model() -> None:
    """Test Handler instance configuration methods."""
    state = _state()
    model = HandlerMethodModel()
    res = model.apply([20], {}, state)
    assert isinstance(res.value, SymbolicNoneType)


def test_getLoggerClass_and_getLogRecordFactory() -> None:
    """Test logging.getLoggerClass and logging.getLogRecordFactory."""
    state = _state()

    res_cls = GetLoggerClassModel().apply([], {}, state)
    assert isinstance(res_cls.value, SymbolicValue)
    assert res_cls.value.affinity_type == "type"

    res_factory = LogRecordFactoryModel().apply([], {}, state)
    assert isinstance(res_factory.value, SymbolicValue)

    res_make = MakeLogRecordModel().apply([{}], {}, state)
    assert isinstance(res_make.value, SymbolicValue)
    assert res_make.value.affinity_type == "logging.LogRecord"
