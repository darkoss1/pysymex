from __future__ import annotations

import pytest

from pysymex.core.state.record import VMState
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins import IsinstanceModel, TypeModel
from pysymex.typing import StackValue


def _state() -> VMState:
    return VMState(pc=0)


@pytest.mark.parametrize(
    ("receiver", "expected_type"),
    [
        (SymbolicList.from_const([1]), list),
        (SymbolicDict.from_const({"value": 1}), dict),
    ],
)
def test_type_decodes_container_carrier_type(receiver: StackValue, expected_type: type) -> None:
    result = TypeModel().apply([receiver], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is expected_type


def test_isinstance_recognizes_modeled_dict_carrier() -> None:
    result = IsinstanceModel().apply([SymbolicDict.from_const({"value": 1}), dict], {}, _state())

    assert result.value is True
