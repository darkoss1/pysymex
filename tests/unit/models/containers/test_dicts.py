from __future__ import annotations

from typing import cast

import pytest
import z3

from pysymex.typing import StackValue
from pysymex.core.constants import Z3_FALSE, Z3_TRUE
from pysymex.core.state.record import VMState
from pysymex.core.types.containers.dict_views import SymbolicDictView
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import FunctionModel, is_raised_exception_effect
from pysymex.models.containers.dicts.access import (
    DictContainsModel,
    DictGetitemModel,
    DictGetModel,
)
from pysymex.models.containers.dicts.mutations.bulk import (
    DictClearModel,
    DictSetdefaultModel,
    DictUpdateModel,
)
from pysymex.models.containers.dicts.mutations.items import DictDelitemModel, DictSetitemModel
from pysymex.models.containers.dicts.mutations.pop import DictPopitemModel, DictPopModel
from pysymex.models.containers.dicts.operators import DictIorModel, DictOrModel
from pysymex.models.containers.dicts.views import (
    DictCopyModel,
    DictItemsModel,
    DictKeysModel,
    DictValuesModel,
)


def _state() -> VMState:
    return VMState(pc=0)


def test_dict_get_faithfulness() -> None:
    """Faithfulness: dict.get with concrete dict matches Python semantics."""
    data = {"a": 1, "b": 2}
    key = "missing_key"
    real = data.get(key)
    stack_dict: dict[str, StackValue] = {k: v for k, v in data.items()}
    args: list[StackValue] = [stack_dict, key]
    DictGetModel().apply(args, {}, _state())
    assert real is None


def test_mutating_dict_models_concrete_none_result() -> None:
    """Concrete path: mutating dict methods return None-like symbolic value."""
    base: dict[str, StackValue] = {"a": 1}
    extra: dict[str, StackValue] = {"b": 2}
    cases: list[tuple[FunctionModel, list[StackValue]]] = [
        (DictSetitemModel(), [base, "k", 1]),
        (DictDelitemModel(), [base, "a"]),
        (DictUpdateModel(), [base, extra]),
        (DictClearModel(), [base]),
    ]
    for model, args in cases:
        result = model.apply(args, {}, _state())
        assert isinstance(result.value, SymbolicNone)


def test_symbolic_and_error_paths() -> None:
    """Symbolic and error-path coverage for dictionary methods."""
    DictGetitemModel().apply([], {}, _state())
    DictContainsModel().apply([], {}, _state())


def test_dict_edge_case_empty_input() -> None:
    """Edge case: empty dict and missing key for pop path."""
    args: list[StackValue] = [{}, "x"]
    DictPopModel().apply(args, {}, _state())


def test_dict_pop_existing_key_returns_retained_value_and_updates_dict() -> None:
    """dict.pop(existing_key) should return retained value metadata."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicDict.from_const({"k": value})

    result = DictPopModel().apply([source, "k"], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(value_constraint, result.value.z3_int != value.z3_int)
    assert solver.check() == z3.unsat

    mutation = cast("dict[str, object] | None", result.side_effects.get("dict_mutation"))
    assert mutation is not None
    updated = mutation["updated_dict"]
    assert isinstance(updated, SymbolicDict)
    found, _ = updated.concrete_value_for_key(SymbolicString.from_const("k"))
    assert not found


def test_dict_pop_missing_key_returns_retained_default_without_mutation() -> None:
    """dict.pop(missing, default) should return the retained default value."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicDict.from_const({"k": 1})

    result = DictPopModel().apply([source, "missing", value], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(value_constraint, result.value.z3_int != value.z3_int)
    assert solver.check() == z3.unsat
    assert "dict_mutation" not in result.side_effects


def test_dict_update_preserves_retained_mapping_values() -> None:
    """dict.update(mapping) should retain exact concrete-backed values."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicDict.from_const({"k": 1})
    other = SymbolicDict.from_const({"k": value})

    result = DictUpdateModel().apply([source, other], {}, _state())

    mutation = cast("dict[str, object] | None", result.side_effects.get("dict_mutation"))
    assert mutation is not None
    updated = mutation["updated_dict"]
    assert isinstance(updated, SymbolicDict)

    found, retained = updated.concrete_value_for_key(SymbolicString.from_const("k"))
    assert found
    assert isinstance(retained, SymbolicValue)

    solver = z3.Solver()
    solver.add(value_constraint, retained.z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_dict_update_preserves_retained_keyword_values() -> None:
    """dict.update(key=value) should apply keywords after positional updates."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicDict.from_const({"k": 1})

    result = DictUpdateModel().apply([source], {"k": value}, _state())

    mutation = cast("dict[str, object] | None", result.side_effects.get("dict_mutation"))
    assert mutation is not None
    updated = mutation["updated_dict"]
    assert isinstance(updated, SymbolicDict)

    found, retained = updated.concrete_value_for_key(SymbolicString.from_const("k"))
    assert found
    assert isinstance(retained, SymbolicValue)

    solver = z3.Solver()
    solver.add(value_constraint, retained.z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_dict_setdefault_existing_key_returns_retained_value_without_mutation() -> None:
    """dict.setdefault(existing, default) should not overwrite the existing value."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicDict.from_const({"k": value})

    result = DictSetdefaultModel().apply([source, "k", 1], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(value_constraint, result.value.z3_int != value.z3_int)
    assert solver.check() == z3.unsat
    assert "dict_mutation" not in result.side_effects


def test_dict_setdefault_missing_key_sets_and_returns_retained_default() -> None:
    """dict.setdefault(missing, default) should store and return the retained default."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicDict.from_const({"other": 1})

    result = DictSetdefaultModel().apply([source, "k", value], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(value_constraint, result.value.z3_int != value.z3_int)
    assert solver.check() == z3.unsat

    mutation = cast("dict[str, object] | None", result.side_effects.get("dict_mutation"))
    assert mutation is not None
    updated = mutation["updated_dict"]
    assert isinstance(updated, SymbolicDict)
    found, retained = updated.concrete_value_for_key(SymbolicString.from_const("k"))
    assert found
    assert isinstance(retained, SymbolicValue)

    solver = z3.Solver()
    solver.add(value_constraint, retained.z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_dict_clear_removes_retained_keys_and_known_key_metadata() -> None:
    """dict.clear() should remove retained values and known-key presence."""
    value, _value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicDict.from_const({"k": value})

    result = DictClearModel().apply([source], {}, _state())

    mutation = cast("dict[str, object] | None", result.side_effects.get("dict_mutation"))
    assert mutation is not None
    updated = mutation["updated_dict"]
    assert isinstance(updated, SymbolicDict)
    assert z3.is_true(z3.simplify(updated.z3_len == 0))

    key = SymbolicString.from_const("k")
    found, retained = updated.concrete_value_for_key(key)
    assert not found
    assert retained is None
    presence = updated.concrete_key_presence_condition(key)
    assert presence is not None
    assert z3.is_false(z3.simplify(presence))


def test_dict_copy_preserves_retained_key_values() -> None:
    """dict.copy() should retain known key/value metadata in the shallow copy."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicDict.from_const({"k": value})

    result = DictCopyModel().apply([source], {}, _state())

    copied = result.value
    assert isinstance(copied, SymbolicDict)
    found, retained = copied.concrete_value_for_key(SymbolicString.from_const("k"))
    assert found
    assert isinstance(retained, SymbolicValue)

    solver = z3.Solver()
    solver.add(value_constraint, retained.z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_dict_values_preserves_retained_values() -> None:
    """dict.values() should expose retained concrete-backed values."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicDict.from_const({"k": value})

    result = DictValuesModel().apply([source], {}, _state())

    values = result.value
    assert isinstance(values, SymbolicDictView)
    retained_values = values.concrete_items
    assert isinstance(retained_values, list)
    assert len(retained_values) == 1
    retained = retained_values[0]
    assert isinstance(retained, SymbolicValue)

    solver = z3.Solver()
    solver.add(value_constraint, retained.z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_dict_keys_preserves_retained_keys() -> None:
    """dict.keys() should expose retained concrete-backed keys."""
    source = SymbolicDict.from_const({"k": 1})

    result = DictKeysModel().apply([source], {}, _state())

    keys = result.value
    assert isinstance(keys, SymbolicDictView)
    retained_keys = keys.concrete_items
    assert retained_keys == ["k"]


def test_dict_or_preserves_retained_right_hand_values() -> None:
    """dict.__or__ should apply right-hand retained values exactly."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    left = SymbolicDict.from_const({"k": 1})
    right = SymbolicDict.from_const({"k": value})

    result = DictOrModel().apply([left, right], {}, _state())

    merged = result.value
    assert isinstance(merged, SymbolicDict)
    found, retained = merged.concrete_value_for_key(SymbolicString.from_const("k"))
    assert found
    assert isinstance(retained, SymbolicValue)

    solver = z3.Solver()
    solver.add(value_constraint, retained.z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_dict_ior_emits_exact_retained_mutation() -> None:
    """dict.__ior__ should expose an exact updated dictionary side effect."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    left = SymbolicDict.from_const({"k": 1})
    right = SymbolicDict.from_const({"k": value})

    result = DictIorModel().apply([left, right], {}, _state())

    mutation = cast("dict[str, object] | None", result.side_effects.get("dict_mutation"))
    assert mutation is not None
    updated = mutation["updated_dict"]
    assert isinstance(updated, SymbolicDict)
    found, retained = updated.concrete_value_for_key(SymbolicString.from_const("k"))
    assert found
    assert isinstance(retained, SymbolicValue)

    solver = z3.Solver()
    solver.add(value_constraint, retained.z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def _symbolic_dict() -> SymbolicDict:
    receiver, _constraint = SymbolicDict.symbolic("receiver")
    return receiver


INVALID_POSITIONAL_CASES: list[tuple[FunctionModel, list[StackValue]]] = [
    (DictGetModel(), []),
    (DictGetModel(), ["key", None, None]),
    (DictPopModel(), []),
    (DictPopModel(), ["key", None, None]),
    (DictPopitemModel(), ["unexpected"]),
    (DictSetdefaultModel(), []),
    (DictSetdefaultModel(), ["key", None, None]),
    (DictUpdateModel(), [dict[str, StackValue](), dict[str, StackValue]()]),
    (DictClearModel(), ["unexpected"]),
    (DictKeysModel(), ["unexpected"]),
    (DictItemsModel(), ["unexpected"]),
    (DictValuesModel(), ["unexpected"]),
    (DictCopyModel(), ["unexpected"]),
]


@pytest.mark.parametrize(
    ("model", "method_args"),
    INVALID_POSITIONAL_CASES,
)
def test_dict_public_methods_reject_invalid_positional_arity(
    model: FunctionModel, method_args: list[StackValue]
) -> None:
    """Public dict methods report TypeError for CPython-invalid positional forms."""
    result = model.apply([_symbolic_dict(), *method_args], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


@pytest.mark.parametrize(
    ("model", "method_args"),
    [
        (DictGetModel(), ["key"]),
        (DictPopModel(), ["key"]),
        (DictPopitemModel(), []),
        (DictSetdefaultModel(), ["key"]),
        (DictClearModel(), []),
        (DictKeysModel(), []),
        (DictItemsModel(), []),
        (DictValuesModel(), []),
        (DictCopyModel(), []),
    ],
)
def test_dict_public_methods_reject_unsupported_keywords(
    model: FunctionModel, method_args: list[StackValue]
) -> None:
    """Dictionary methods without keyword parameters reject keyword arguments."""
    result = model.apply([_symbolic_dict(), *method_args], {"unexpected": 1}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


def test_dict_update_accepts_keyword_items() -> None:
    """dict.update supports keyword items in CPython."""
    result = DictUpdateModel().apply([_symbolic_dict()], {"key": 1}, _state())

    assert "raised_exception" not in result.side_effects


def test_dict_get_existing_int_key_returns_retained_value() -> None:
    """dict.get should preserve concrete-backed values for integer keys."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicDict.from_const({1: value})

    result = DictGetModel().apply([source, 1, 0], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(value_constraint, result.value.z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_dict_get_missing_int_key_returns_retained_default() -> None:
    """dict.get should return the default for a known-missing integer key."""
    default, default_constraint = SymbolicValue.symbolic_int("default")
    source = SymbolicDict.from_const({1: 1})

    result = DictGetModel().apply([source, 2, default], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(default_constraint, result.value.z3_int != default.z3_int)
    assert solver.check() == z3.unsat


def test_dict_get_symbolic_int_key_over_exact_keys_selects_retained_values() -> None:
    """Symbolic integer keys should select among exact retained dictionary values."""
    y, y_constraint = SymbolicValue.symbolic_int("y")
    key = SymbolicValue(
        _name="key",
        z3_int=z3.If(y.z3_int == 0, z3.IntVal(0), z3.IntVal(1)),
        is_int=Z3_TRUE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_str=Z3_FALSE,
        is_none=Z3_FALSE,
        affinity_type="int",
    )
    source = SymbolicDict.from_const({0: 2, 1: 1})

    result = DictGetModel().apply([source, key, 0], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(y_constraint, result.value.z3_int == 0)
    assert solver.check() == z3.unsat
