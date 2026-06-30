from __future__ import annotations

from typing import cast

import z3

from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.models.builtins.types.containers.dicts.mutations.pop import DictPopitemModel
from pysymex._internal.models.contracts.results import ModelResult


def _state() -> VMState:
    return VMState(pc=0)


def test_dict_popitem_does_not_mutate_receiver_in_place() -> None:
    """dict.popitem() success mutation is represented by a copied receiver."""
    source = SymbolicDict.from_const({"k": 1})
    old_len = source.z3_len

    result: ModelResult = DictPopitemModel().apply([source], {}, _state())

    assert source.z3_len is old_len
    assert z3.is_true(simplify_expr(source.z3_len == 1))

    mutation = cast("dict[str, object]", result.side_effects["dict_mutation"])
    assert mutation["original_dict"] is source
    updated = mutation["updated_dict"]
    assert isinstance(updated, SymbolicDict)
    assert updated is not source
    assert z3.is_true(simplify_expr(updated.z3_len == old_len - 1))


def test_dict_popitem_empty_exception_uses_pre_call_length() -> None:
    """dict.popitem() reports KeyError feasibility from the original length."""
    source = SymbolicDict.empty()

    result: ModelResult = DictPopitemModel().apply([source], {}, _state())

    assert z3.is_true(simplify_expr(source.z3_len == 0))
    effect = cast("dict[str, object]", result.side_effects["potential_exception"])
    condition = cast("z3.BoolRef", effect["condition"])
    assert z3.is_true(simplify_expr(condition))
