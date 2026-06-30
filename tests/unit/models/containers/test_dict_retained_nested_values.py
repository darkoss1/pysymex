from __future__ import annotations

from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.models.builtins.types.containers.dicts.access import DictGetitemModel
from pysymex._internal.models.contracts.function import FunctionModel as _FunctionModel

_ = _FunctionModel


def test_dict_getitem_returns_retained_nested_list_with_parent_root() -> None:
    from pysymex._internal.core.state.record import VMState

    source = SymbolicDict.from_const_named("data", {"items": []})

    result = DictGetitemModel().apply([source, "items"], {}, VMState())

    assert isinstance(result.value, SymbolicList)
    assert result.value.name == "data[*]"
    assert result.side_effects == {}
