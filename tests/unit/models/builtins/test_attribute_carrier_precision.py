from __future__ import annotations

import pytest

import pysymex._internal.models.builtins.common.dynamic as helpers
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.attributes.getattr import GetattrModel
from pysymex._internal.models.builtins.attributes.mutation import HasattrModel


def _state() -> VMState:
    return VMState(pc=0)


def test_attribute_queries_decode_literal_symbolic_string_receiver() -> None:
    receiver = SymbolicString.from_const("abc")
    hasattr_result = HasattrModel().apply([receiver, "upper"], {}, _state())
    getattr_result = GetattrModel().apply([receiver, "upper"], {}, _state())

    assert isinstance(hasattr_result.value, SymbolicValue)
    assert hasattr_result.value.value is True
    assert callable(getattr_result.value)
    assert "raised_exception" not in getattr_result.side_effects


def test_getattr_does_not_query_unknown_symbolic_string_carrier() -> None:
    receiver, _constraint = SymbolicString.symbolic("receiver")
    result = GetattrModel().apply([receiver, "upper"], {}, _state())

    assert "raised_exception" not in result.side_effects


def test_must_be_none_keeps_inconclusive_prefix_unproved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receiver, constraint = SymbolicValue.symbolic("inconclusive_none_receiver")

    def fail_path_query(*_args: object, **_kwargs: object) -> bool:
        raise AssertionError("inconclusive path prefix should not be queried as proof")

    monkeypatch.setattr(helpers, "path_may_be_feasible", fail_path_query)

    assert (
        helpers.must_be_none(
            receiver,
            [constraint],
            known_sat_prefix_len=0,
            inconclusive_path_prefix_len=1,
        )
        is False
    )
