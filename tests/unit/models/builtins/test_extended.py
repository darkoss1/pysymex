from __future__ import annotations

import pytest
import z3

from pysymex._typing import StackValue
from pysymex.core.objects.oop import EnhancedClass, EnhancedObject
from pysymex.core.objects.types import SymbolicClass, SymbolicObject as OOPSymbolicObject
from pysymex.core.state import VMState
from pysymex.core.types.containers import SymbolicList, SymbolicObject
from pysymex.core.types.scalars import SymbolicString, SymbolicValue
from pysymex.models.builtins.base import is_raised_exception_effect, is_sink_event_effect
from pysymex.models.builtins import extended


def _state() -> VMState:
    return VMState(pc=0)


def _to_python_bool(value: StackValue) -> bool:
    if isinstance(value, SymbolicValue) and isinstance(value.value, bool):
        return value.value
    return bool(value)


def _to_python_int(value: StackValue) -> int:
    if isinstance(value, SymbolicValue) and isinstance(value.value, int):
        return value.value
    if isinstance(value, int):
        return value
    raise TypeError("value is not concretely int")


def _symbolic_enhanced_instance() -> SymbolicValue:
    cls = SymbolicClass("Box")
    enhanced_class = EnhancedClass(cls)
    instance = EnhancedObject(OOPSymbolicObject(cls), enhanced_class)
    instance.set_attribute("value", 4)
    symbolic, _constraint = SymbolicValue.symbolic("box")
    symbolic.attach_enhanced_object(instance)
    return symbolic


def test_all_any_faithfulness() -> None:
    """Faithfulness: all/any model outputs match Python for concrete iterables."""
    cases: list[list[int | bool]] = [[], [1], [0, 1, 2], [False, True]]
    for items in cases:
        stack_items: list[StackValue] = [*items]
        args: list[StackValue] = [stack_items]
        all_res = extended.AllModel().apply(args, {}, _state())
        any_res = extended.AnyModel().apply(args, {}, _state())
        assert _to_python_bool(all_res.value) == all(items)
        assert _to_python_bool(any_res.value) == any(items)


def test_reversed_faithfulness() -> None:
    """Faithfulness: reversed model matches Python reversed for concrete input."""
    values: list[StackValue] = [1, 2, 3]
    args: list[StackValue] = [values]
    result = extended.ReversedModel().apply(args, {}, _state())
    assert result.value == list(reversed(values))


def test_ord_chr_faithfulness() -> None:
    """Faithfulness for ord/chr on concrete path."""
    ord_args: list[StackValue] = ["A"]
    chr_args: list[StackValue] = [65]
    ord_result = extended.OrdModel().apply(ord_args, {}, _state())
    chr_result = extended.ChrModel().apply(chr_args, {}, _state())
    assert _to_python_int(ord_result.value) == ord("A")
    assert hasattr(chr_result.value, "name")
    assert getattr(chr_result.value, "name") == "'A'"


def test_pow_round_divmod_faithfulness() -> None:
    """Faithfulness for numeric builtins on concrete path."""
    pow_result = extended.PowModel().apply([2, 5], {}, _state())
    round_result = extended.RoundModel().apply([3.14159, 2], {}, _state())
    divmod_result = extended.DivmodModel().apply([17, 5], {}, _state())
    assert _to_python_int(pow_result.value) == pow(2, 5)
    assert round_result.value == round(3.14159, 2)
    assert isinstance(divmod_result.value, tuple)


def test_bytearray_constructor_preserves_symbolic_list_length() -> None:
    """bytearray(symbolic-list) preserves the iterable length relation."""
    source, source_constraint = SymbolicList.symbolic("source_bytes")
    source_ref = SymbolicObject("source_bytes", 101, z3.IntVal(101), {101})
    state = VMState(memory={101: source})

    result = extended.BytearrayModel().apply([source_ref], {}, state)

    assert isinstance(result.value, SymbolicList)
    solver = z3.Solver()
    solver.add(source_constraint, *result.constraints)
    solver.add(result.value.z3_len != source.z3_len)
    assert solver.check() == z3.unsat


def test_hasattr_getattr_faithfulness() -> None:
    """Faithfulness for attribute builtins on concrete path."""
    target: object = "abc"
    has_result = extended.HasattrModel().apply([target, "upper"], {}, _state())
    get_result = extended.GetattrModel().apply([target, "upper"], {}, _state())
    assert bool(has_result.value) is hasattr(target, "upper")
    assert callable(get_result.value)


def test_extended_error_and_edge_paths() -> None:
    """Error and edge paths for representative models."""
    assert extended.AllModel().apply([], {}, _state()).value is not None
    assert extended.AnyModel().apply([], {}, _state()).value is not None

    with pytest.raises(Exception):
        invalid: list[StackValue] = [0x110000]
        result = extended.ChrModel().apply(invalid, {}, _state())
        assert str(result.value) == chr(0x110000)


def test_delattr_apply() -> None:
    """Test delattr model apply behavior."""
    from pysymex.core.types.scalars import SymbolicNone

    target: object = "test"
    args: list[StackValue] = [target, "attr"]
    result = extended.DelattrModel().apply(args, {}, _state())
    assert isinstance(result.value, SymbolicNone)
    assert result.side_effects is not None
    assert "mutates_arg" in result.side_effects


def test_aiter_apply() -> None:
    """Test aiter model apply behavior."""
    result = extended.AiterModel().apply([], {}, _state())
    assert isinstance(result.value, SymbolicValue)
    assert result.value.name.startswith("aiter_")


def test_anext_apply() -> None:
    """Test anext model apply behavior."""
    result = extended.AnextModel().apply([], {}, _state())
    assert isinstance(result.value, SymbolicValue)
    assert result.value.name.startswith("anext_")


def test_getattr_missing_attribute_emits_raised_exception_side_effect() -> None:
    """getattr without default emits raised_exception side effect on concrete missing attribute."""
    result = extended.GetattrModel().apply(["abc", "missing_attr"], {}, _state())
    raised_effect = result.side_effects.get("raised_exception")
    assert is_raised_exception_effect(raised_effect)


def test_getattr_symbolic_string_literal_emits_raised_exception_side_effect() -> None:
    """getattr accepts bytecode-loaded concrete symbolic strings as attribute names."""
    result = extended.GetattrModel().apply(
        ["abc", SymbolicString.from_const("missing_attr")], {}, _state()
    )
    raised_effect = result.side_effects.get("raised_exception")
    assert is_raised_exception_effect(raised_effect)


def test_getattr_with_default_omits_raised_exception_side_effect() -> None:
    """getattr with default returns default and does not emit raised_exception side effect."""
    result = extended.GetattrModel().apply(["abc", "missing_attr", 99], {}, _state())
    assert "raised_exception" not in result.side_effects


def test_iter_on_int_emits_type_error_side_effect() -> None:
    """iter(int) raises TypeError in CPython."""
    result = extended.IterModel().apply([SymbolicValue.from_const(1)], {}, _state())

    assert "raised_exception" in result.side_effects


def test_next_empty_concrete_iterator_emits_stop_iteration_side_effect() -> None:
    """next(iter([])) raises StopIteration in CPython."""
    result = extended.NextModel().apply([[]], {}, _state())

    raised_effect = result.side_effects.get("raised_exception")
    assert is_raised_exception_effect(raised_effect)
    assert raised_effect["issue_kind"] == "UNHANDLED_EXCEPTION"
    assert raised_effect["exception_type"] == "StopIteration"


def test_next_heap_list_handle_emits_stop_iteration_side_effect() -> None:
    """next() resolves scanner BUILD_LIST heap handles before checking exhaustion."""
    storage = SymbolicList.from_const([])
    handle = SymbolicObject("list_handle", 10, z3.IntVal(10), {10})
    state = VMState(memory={10: storage})

    result = extended.NextModel().apply([handle], {}, state)

    raised_effect = result.side_effects.get("raised_exception")
    assert is_raised_exception_effect(raised_effect)
    assert raised_effect["exception_type"] == "StopIteration"


def test_next_nonempty_concrete_iterator_returns_first_item() -> None:
    """next(iter([value])) returns the first item."""
    result = extended.NextModel().apply([[3]], {}, _state())

    assert result.value == 3


def test_getattr_symbolic_enhanced_existing_attribute_returns_value() -> None:
    """getattr on a known enhanced instance attribute is not a possible AttributeError."""
    result = extended.GetattrModel().apply([_symbolic_enhanced_instance(), "value"], {}, _state())

    assert result.value == 4
    assert "raised_exception" not in result.side_effects


def test_getattr_symbolic_enhanced_missing_attribute_emits_raised_exception() -> None:
    """getattr on a known missing enhanced instance attribute remains an AttributeError."""
    result = extended.GetattrModel().apply([_symbolic_enhanced_instance(), "missing"], {}, _state())

    raised_effect = result.side_effects.get("raised_exception")
    assert is_raised_exception_effect(raised_effect)


def test_setattr_none_emits_raised_exception_side_effect() -> None:
    """setattr(None, ...) emits raised_exception side effect."""
    result = extended.SetattrModel().apply([None, "x", 1], {}, _state())
    raised_effect = result.side_effects.get("raised_exception")
    assert is_raised_exception_effect(raised_effect)


def test_eval_symbolic_input_emits_critical_sink_event() -> None:
    """eval(symbolic) emits a critical sink_event side effect."""
    symbolic_code = SymbolicString.from_const("x + 1")
    result = extended.EvalModel().apply([symbolic_code], {}, _state())
    sink_event = result.side_effects.get("sink_event")
    assert is_sink_event_effect(sink_event) and sink_event["severity"] == "critical"


def test_exec_symbolic_input_emits_critical_sink_event() -> None:
    """exec(symbolic) emits a critical sink_event side effect."""
    symbolic_code = SymbolicString.from_const("x = 1")
    result = extended.ExecModel().apply([symbolic_code], {}, _state())
    sink_event = result.side_effects.get("sink_event")
    assert is_sink_event_effect(sink_event) and sink_event["severity"] == "critical"
