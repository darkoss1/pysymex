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

"""Unit tests for stdlib time and datetime models and resolution."""

from __future__ import annotations

import time
import unittest.mock

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.calls.model.dispatch import apply_model
from pysymex._internal.execution.opcodes.common.functions.attribute.load.values import (
    load_symbolic_value_attribute,
)
from pysymex._internal.models.registry import RuntimeModelRegistry
from pysymex._internal.models.stdlib.datetime.models import (
    DatetimeDateModel,
    DatetimeNowModel,
    DateTodayModel,
    DateWeekdayModel,
    TimedeltaConstructorModel,
    TotalSecondsModel,
)
from pysymex._internal.models.stdlib.registry import get_stdlib_model
from pysymex._internal.models.stdlib.time.models import TimeStructTimeModel, TimeTimeModel


def _state() -> VMState:
    return VMState(pc=0)


def test_time_models_registered() -> None:
    """Test that time models are registered and resolvable."""
    assert get_stdlib_model("time.time") is not None
    assert get_stdlib_model("time.localtime") is not None
    assert get_stdlib_model("time.sleep") is not None


def test_concrete_time_callable_uses_registered_model() -> None:
    """Concrete stdlib callables use the same registered model family."""
    result = apply_model(_state(), time.time, [])

    assert result is not None
    assert len(result.new_states) == 1
    assert isinstance(result.new_states[0].stack[-1], SymbolicValue)


def test_time_time_model() -> None:
    """Test that TimeTimeModel returns a non-negative float."""
    model = TimeTimeModel()
    res = model.apply([], {}, _state())
    assert isinstance(res.value, SymbolicValue)
    assert res.value.is_float is not None
    # Verify the non-negative constraint is present
    assert len(res.constraints) >= 2


def test_time_struct_time_model_symbolic() -> None:
    """Test that TimeStructTimeModel returns a struct_time symbolic object."""
    model = TimeStructTimeModel()
    res = model.apply([], {}, _state())
    assert isinstance(res.value, SymbolicValue)
    assert res.value.type_tag == "time.struct_time"


def test_datetime_affinity_resolves_canonical_instance_models() -> None:
    """Datetime carriers preserve their canonical owner during method lookup."""
    mock_instr = unittest.mock.MagicMock()
    mock_state = _state()
    mock_ctx = unittest.mock.MagicMock()

    cases = [
        (DateTodayModel().apply([], {}, mock_state).value, "weekday", DateWeekdayModel),
        (DatetimeNowModel().apply([], {}, mock_state).value, "date", DatetimeDateModel),
        (
            TimedeltaConstructorModel().apply([], {}, mock_state).value,
            "total_seconds",
            TotalSecondsModel,
        ),
    ]
    for value, attribute, expected_model_type in cases:
        assert isinstance(value, SymbolicValue)
        loaded = load_symbolic_value_attribute(
            mock_instr,
            mock_state,
            mock_ctx,
            value,
            attribute,
            push_null=False,
        )
        model_name = f"{loaded.type_name}.{attribute}"
        assert loaded.type_name == value.affinity_type
        assert isinstance(RuntimeModelRegistry.default().resolve(model_name), expected_model_type)
