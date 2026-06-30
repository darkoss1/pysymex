from __future__ import annotations

from typing import cast

import z3

from pysymex._internal.core.classes.classes import SymbolicClass
from pysymex._internal.core.classes.registry import class_registry
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.attributes.descriptors import AsciiModel, DirModel, VarsModel
from pysymex._internal.models.builtins.attributes.getattr import GetattrModel
from pysymex._internal.models.builtins.attributes.mutation import (
    DelattrModel,
    HasattrModel,
    SetattrModel,
)
from pysymex._internal.models.builtins.bytes.constructors import BytearrayModel, BytesModel
from pysymex._internal.models.builtins.constructors.object import ObjectModel
from pysymex._internal.models.builtins.iteration.aggregates import SortedModel
from pysymex._internal.models.builtins.iteration.iter_model import IterModel
from pysymex._internal.models.builtins.iteration.next_model import NextModel
from pysymex._internal.models.builtins.iteration.reversed_model import ReversedModel
from pysymex._internal.models.builtins.iteration.sources import IterationSources
from pysymex._internal.models.builtins.iteration.truth import AllModel, AnyModel
from pysymex._internal.models.builtins.numeric.format import (
    BinModel,
    DivmodModel,
    HexModel,
    OctModel,
)
from pysymex._internal.models.builtins.numeric.max import MaxModel
from pysymex._internal.models.builtins.numeric.min import MinModel
from pysymex._internal.models.builtins.reflection.identity import FormatModel, HashModel
from pysymex._internal.models.builtins.reflection.namespace import (
    DictModel,
    GlobalsModel,
    IssubclassModel,
    LocalsModel,
)
from pysymex._internal.models.builtins.runtime.dynamic_io import EvalModel, ExecModel
from pysymex._internal.models.builtins.text.codepoints import (
    ChrModel,
    OrdModel,
    PowModel,
    RoundModel,
)
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue


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


def _symbolic_modeled_instance() -> SymbolicValue:
    cls = SymbolicClass("Box")
    instance = class_registry.create_instance(cls)
    instance.set_attribute("value", 4)
    symbolic, _constraint = SymbolicValue.symbolic("box")
    symbolic.attach_modeled_object(instance)
    return symbolic


def test_all_any_faithfulness() -> None:
    """Faithfulness: all/any model outputs match Python for concrete iterables."""
    cases: list[list[int | bool]] = [[], [1], [0, 1, 2], [False, True]]
    for items in cases:
        stack_items: list[StackValue] = [*items]
        args: list[StackValue] = [stack_items]
        all_res = AllModel().apply(args, {}, _state())
        any_res = AnyModel().apply(args, {}, _state())
        assert _to_python_bool(all_res.value) == all(items)
        assert _to_python_bool(any_res.value) == any(items)


def test_reversed_faithfulness() -> None:
    """Faithfulness: reversed model matches Python reversed for concrete input."""
    values: list[StackValue] = [1, 2, 3]
    args: list[StackValue] = [values]
    vm_state = _state()
    result = ReversedModel().apply(args, {}, vm_state)
    assert isinstance(result.value, SymbolicIterator)
    assert result.value.iterable is values
    assert result.value.reverse is True
    assert IterationSources.iterable_items(result.value, vm_state) == list(reversed(values))


def test_reversed_heap_backed_symbolic_items_are_preserved() -> None:
    """reversed(heap-backed-list) should keep concrete-backed symbolic items."""
    value, value_constraint = SymbolicValue.symbolic_int("value")
    source = SymbolicList.from_const([value])
    handle = SymbolicObject("items", 101, z3.IntVal(101), {101})
    state = _state().store_heap(101, source)

    result = ReversedModel().apply([handle], {}, state)

    assert isinstance(result.value, SymbolicIterator)
    assert result.value.iterable is source
    assert result.value.reverse is True
    assert IterationSources.iterable_items(result.value, state) == [value]

    solver = z3.Solver()
    reversed_items = IterationSources.iterable_items(result.value, state)
    assert reversed_items is not None
    reversed_item = cast("SymbolicValue", reversed_items[0])
    solver.add(value_constraint, reversed_item.z3_int != value.z3_int)
    assert solver.check() == z3.unsat


def test_ord_chr_faithfulness() -> None:
    """Faithfulness for ord/chr on concrete path."""
    ord_args: list[StackValue] = ["A"]
    chr_args: list[StackValue] = [65]
    ord_result = OrdModel().apply(ord_args, {}, _state())
    chr_result = ChrModel().apply(chr_args, {}, _state())
    assert _to_python_int(ord_result.value) == ord("A")
    assert hasattr(chr_result.value, "name")
    assert getattr(chr_result.value, "name") == "'A'"


def test_pow_round_divmod_faithfulness() -> None:
    """Faithfulness for numeric builtins on concrete path."""
    pow_result = PowModel().apply([2, 5], {}, _state())
    round_result = RoundModel().apply([3.14159, 2], {}, _state())
    divmod_result = DivmodModel().apply([17, 5], {}, _state())
    assert _to_python_int(pow_result.value) == pow(2, 5)
    assert round_result.value == round(3.14159, 2)
    assert isinstance(divmod_result.value, tuple)


def test_ordering_builtins_report_incompatible_concrete_items() -> None:
    """min(), max(), and sorted() preserve definite CPython comparison failures."""
    results = [
        MinModel().apply([1, "x"], {}, _state()),
        MaxModel().apply([1, "x"], {}, _state()),
        SortedModel().apply([[1, "x"]], {}, _state()),
    ]

    for result in results:
        effect = result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == "TypeError"


def test_divmod_concrete_failures_are_modeled_exceptions() -> None:
    zero_divisor = DivmodModel().apply([5, 0], {}, _state())
    invalid_operands = DivmodModel().apply(["5", 2], {}, _state())
    none_operand = DivmodModel().apply([None, 2], {}, _state())

    zero_effect = zero_divisor.side_effects.get("raised_exception")
    invalid_effect = invalid_operands.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(zero_effect)
    assert zero_effect["exception_type"] == "ZeroDivisionError"
    assert zero_effect["message"] == "integer division or modulo by zero"
    assert SideEffects.is_raised_exception(invalid_effect)
    assert invalid_effect["exception_type"] == "TypeError"
    none_effect = none_operand.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(none_effect)
    assert none_effect["exception_type"] == "TypeError"


def test_integer_representation_builtins_are_concrete_and_reject_float_inputs() -> None:
    cases = [
        (BinModel(), bin),
        (OctModel(), oct),
        (HexModel(), hex),
    ]
    for model, formatter in cases:
        valid = model.apply([10], {}, _state())
        invalid = model.apply([1.5], {}, _state())
        assert isinstance(valid.value, SymbolicString)
        assert valid.value.z3_str.as_string() == formatter(10)
        effect = invalid.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == "TypeError"
        none_effect = model.apply([None], {}, _state()).side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(none_effect)
        assert none_effect["exception_type"] == "TypeError"


def test_bytearray_constructor_preserves_symbolic_list_length() -> None:
    """bytearray(symbolic-list) preserves the iterable length relation."""
    source, source_constraint = SymbolicList.symbolic("source_bytes")
    source_ref = SymbolicObject("source_bytes", 101, z3.IntVal(101), {101})
    state = VMState(memory={101: source})

    result = BytearrayModel().apply([source_ref], {}, state)

    assert isinstance(result.value, SymbolicList)
    solver = z3.Solver()
    solver.add(source_constraint, *result.constraints)
    solver.add(result.value.z3_len != source.z3_len)
    assert solver.check() == z3.unsat


def test_dict_constructor_rejects_definite_non_iterable() -> None:
    result = DictModel().apply([1], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_dict_constructor_copies_symbolic_dict_without_aliasing() -> None:
    source = SymbolicDict.from_const({"k": 1})

    result = DictModel().apply([source], {}, _state())

    assert isinstance(result.value, SymbolicDict)
    has_value, value = result.value.concrete_value_for_key("k")
    assert has_value is True
    assert value == 1

    updated_copy = result.value.__delitem__("k")
    source_has_value, source_value = source.concrete_value_for_key("k")
    copy_has_value, _copy_value = updated_copy.concrete_value_for_key("k")
    assert source_has_value is True
    assert source_value == 1
    assert copy_has_value is False


def test_dict_constructor_reports_definite_malformed_pairs() -> None:
    """Exact dict iterables preserve CPython pair-length and hashability failures."""
    malformed = DictModel().apply([[("key",)]], {}, _state())
    unhashable = DictModel().apply([[([], 1)]], {}, _state())

    malformed_effect = malformed.side_effects.get("raised_exception")
    unhashable_effect = unhashable.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(malformed_effect)
    assert malformed_effect["exception_type"] == "ValueError"
    assert SideEffects.is_raised_exception(unhashable_effect)
    assert unhashable_effect["exception_type"] == "TypeError"


def test_binary_constructors_report_out_of_range_exact_items() -> None:
    """bytes() and bytearray() reject exact integer items outside one byte."""
    for model in (BytesModel(), BytearrayModel()):
        for invalid_items in ([-1], [256]):
            source: list[StackValue] = [*invalid_items]
            args: list[StackValue] = [source]
            result = model.apply(args, {}, _state())
            effect = result.side_effects.get("raised_exception")
            assert SideEffects.is_raised_exception(effect)
            assert effect["exception_type"] == "ValueError"


def test_issubclass_single_class_form_is_exact_and_invalid_subject_fails() -> None:
    valid = IssubclassModel().apply([bool, int], {}, _state())
    invalid = IssubclassModel().apply([1, int], {}, _state())

    assert isinstance(valid.value, SymbolicValue)
    assert valid.value.value is True
    effect = invalid.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_vars_primitive_failure_and_ascii_scalar_value_are_modeled() -> None:
    invalid = VarsModel().apply([1], {}, _state())
    ascii_result = AsciiModel().apply(["\N{LATIN SMALL LETTER E WITH ACUTE}"], {}, _state())

    effect = invalid.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert isinstance(ascii_result.value, SymbolicString)
    assert ascii_result.value.z3_str.as_string() == ascii("\N{LATIN SMALL LETTER E WITH ACUTE}")


def test_namespace_introspection_preserves_current_bound_values() -> None:
    """dir(), globals(), and locals() retain exact VM namespace information."""
    from pysymex._internal.core.state.types import UNBOUND

    state = VMState(local_vars={"local_value": 7}, global_vars={"global_value": 11})
    state = state.set_local("deleted", UNBOUND)

    directory = DirModel().apply([], {}, state)
    globals_result = GlobalsModel().apply([], {}, state)
    locals_result = LocalsModel().apply([], {}, state)

    assert isinstance(directory.value, SymbolicList)
    assert directory.value.concrete_items == ["local_value"]
    assert isinstance(globals_result.value, SymbolicDict)
    assert globals_result.value.concrete_value_for_key("global_value") == (True, 11)
    assert isinstance(locals_result.value, SymbolicDict)
    assert locals_result.value.concrete_value_for_key("local_value") == (True, 7)
    assert locals_result.value.concrete_value_for_key("deleted") == (False, None)


def test_object_constructor_returns_distinct_non_none_values() -> None:
    """Separate object() calls retain CPython's non-None identity distinction."""
    first = ObjectModel().apply([], {}, VMState(pc=1))
    second = ObjectModel().apply([], {}, VMState(pc=2))

    assert isinstance(first.value, SymbolicValue)
    assert isinstance(second.value, SymbolicValue)
    assert not z3.eq(first.value.z3_addr, second.value.z3_addr)
    assert z3.is_false(first.value.is_none)
    assert z3.is_false(second.value.is_none)


def test_hasattr_getattr_faithfulness() -> None:
    """Faithfulness for attribute builtins on concrete path."""
    target: object = "abc"
    has_result = HasattrModel().apply([target, "upper"], {}, _state())
    get_result = GetattrModel().apply([target, "upper"], {}, _state())
    assert bool(has_result.value) is hasattr(target, "upper")
    assert callable(get_result.value)


def test_extended_error_and_edge_paths() -> None:
    """Error and edge paths for representative models."""
    all_raised = AllModel().apply([], {}, _state()).side_effects.get("raised_exception")
    any_raised = AnyModel().apply([], {}, _state()).side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(all_raised)
    assert SideEffects.is_raised_exception(any_raised)

    two_args: list[StackValue] = [[True], [False]]
    assert SideEffects.is_raised_exception(
        AllModel().apply(two_args, {}, _state()).side_effects.get("raised_exception")
    )
    assert SideEffects.is_raised_exception(
        AnyModel().apply(two_args, {}, _state()).side_effects.get("raised_exception")
    )

    invalid_chr: list[StackValue] = [0x110000]
    chr_effect = ChrModel().apply(invalid_chr, {}, _state()).side_effects.get("raised_exception")
    ord_effect = OrdModel().apply(["AB"], {}, _state()).side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(chr_effect)
    assert chr_effect["exception_type"] == "ValueError"
    assert SideEffects.is_raised_exception(ord_effect)
    assert ord_effect["exception_type"] == "TypeError"
    ord_none_effect = OrdModel().apply([None], {}, _state()).side_effects.get("raised_exception")
    round_none_effect = (
        RoundModel().apply([None], {}, _state()).side_effects.get("raised_exception")
    )
    assert SideEffects.is_raised_exception(ord_none_effect)
    assert ord_none_effect["exception_type"] == "TypeError"
    assert SideEffects.is_raised_exception(round_none_effect)
    assert round_none_effect["exception_type"] == "TypeError"


def test_truth_and_iterator_builtins_reject_definite_non_iterables() -> None:
    results = [
        AllModel().apply([1], {}, _state()),
        AnyModel().apply([1], {}, _state()),
        ReversedModel().apply([1], {}, _state()),
        NextModel().apply([1], {}, _state()),
    ]

    for result in results:
        effect = result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == "TypeError"


def test_identity_format_and_attribute_builtins_report_definite_failures() -> None:
    cases = [
        (HashModel().apply([[]], {}, _state()), "TypeError"),
        (FormatModel().apply([1, "bad"], {}, _state()), "ValueError"),
        (FormatModel().apply([1, 1], {}, _state()), "TypeError"),
        (HasattrModel().apply([1, 2], {}, _state()), "TypeError"),
        (GetattrModel().apply([1, 2], {}, _state()), "TypeError"),
        (SetattrModel().apply([1, 2, 3], {}, _state()), "TypeError"),
        (DelattrModel().apply([1, 2], {}, _state()), "TypeError"),
    ]
    for result, exception_type in cases:
        effect = result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == exception_type


def test_delattr_apply() -> None:
    """Test delattr model apply behavior."""
    from pysymex._internal.core.types.base import SymbolicNoneType as SymbolicNone

    target: object = "test"
    args: list[StackValue] = [target, "attr"]
    result = DelattrModel().apply(args, {}, _state())
    assert isinstance(result.value, SymbolicNone)
    assert result.side_effects is not None
    assert "mutates_arg" in result.side_effects
    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "AttributeError"


def test_getattr_missing_attribute_emits_raised_exception_side_effect() -> None:
    """getattr without default emits raised_exception side effect on concrete missing attribute."""
    result = GetattrModel().apply(["abc", "missing_attr"], {}, _state())
    raised_effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(raised_effect)


def test_getattr_symbolic_string_literal_emits_raised_exception_side_effect() -> None:
    """getattr accepts bytecode-loaded concrete symbolic strings as attribute names."""
    result = GetattrModel().apply(["abc", SymbolicString.from_const("missing_attr")], {}, _state())
    raised_effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(raised_effect)


def test_getattr_with_default_omits_raised_exception_side_effect() -> None:
    """getattr with default returns default and does not emit raised_exception side effect."""
    result = GetattrModel().apply(["abc", "missing_attr", 99], {}, _state())
    assert "raised_exception" not in result.side_effects
    none_default = GetattrModel().apply(["abc", "missing_attr", None], {}, _state())
    assert none_default.value is None
    assert "raised_exception" not in none_default.side_effects


def test_iter_on_int_emits_type_error_side_effect() -> None:
    """iter(int) raises TypeError in CPython."""
    result = IterModel().apply([SymbolicValue.from_const(1)], {}, _state())

    assert "raised_exception" in result.side_effects


def test_next_empty_concrete_iterator_emits_stop_iteration_side_effect() -> None:
    """next(iter([])) raises StopIteration in CPython."""
    result = NextModel().apply([[]], {}, _state())

    raised_effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(raised_effect)
    assert raised_effect["issue_kind"] == "UNHANDLED_EXCEPTION"
    assert raised_effect["exception_type"] == "StopIteration"


def test_next_heap_list_handle_emits_stop_iteration_side_effect() -> None:
    """next() resolves scanner BUILD_LIST heap handles before checking exhaustion."""
    storage = SymbolicList.from_const([])
    handle = SymbolicObject("list_handle", 10, z3.IntVal(10), {10})
    state = VMState(memory={10: storage})

    result = NextModel().apply([handle], {}, state)

    raised_effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(raised_effect)
    assert raised_effect["exception_type"] == "StopIteration"


def test_next_nonempty_concrete_iterator_returns_first_item() -> None:
    """next(iter([value])) returns the first item."""
    result = NextModel().apply([[3]], {}, _state())

    assert result.value == 3


def test_iter_next_advances_symbolic_iterator_state() -> None:
    """next(iter([value])) should advance the explicit iterator object."""
    iterator_result = IterModel().apply([[3]], {}, _state())
    iterator = iterator_result.value
    assert isinstance(iterator, SymbolicIterator)

    first = NextModel().apply([iterator], {}, _state())

    assert first.value == 3
    mutation = cast("dict[str, object]", first.side_effects.get("iterator_mutation"))
    assert isinstance(mutation, dict)
    updated = mutation["updated_iterator"]
    assert isinstance(updated, SymbolicIterator)
    assert updated.index == 1


def test_next_exhausted_symbolic_iterator_uses_default_or_stop_iteration() -> None:
    """Exhausted explicit iterators should return defaults or raise StopIteration."""
    iterator = SymbolicIterator("items", [1], index=1)

    default_result = NextModel().apply([iterator, 7], {}, _state())
    raised_result = NextModel().apply([iterator], {}, _state())

    assert default_result.value == 7
    raised_effect = raised_result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(raised_effect)
    assert raised_effect["exception_type"] == "StopIteration"


def test_getattr_symbolic_modeled_existing_attribute_returns_value() -> None:
    """getattr on a known modeled instance attribute is not a possible AttributeError."""
    result = GetattrModel().apply([_symbolic_modeled_instance(), "value"], {}, _state())

    assert result.value == 4
    assert "raised_exception" not in result.side_effects


def test_getattr_symbolic_modeled_missing_attribute_emits_raised_exception() -> None:
    """getattr on a known missing modeled instance attribute remains an AttributeError."""
    result = GetattrModel().apply([_symbolic_modeled_instance(), "missing"], {}, _state())

    raised_effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(raised_effect)


def test_getattr_unknown_symbolic_receiver_does_not_emit_definite_attribute_error() -> None:
    """Unknown symbolic receivers produce unknown values, not definite AttributeError reports."""
    receiver, _constraint = SymbolicValue.symbolic("unknown_getattr_receiver")

    result = GetattrModel().apply([receiver, "missing"], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert "raised_exception" not in result.side_effects


def test_setattr_none_emits_raised_exception_side_effect() -> None:
    """setattr(None, ...) emits raised_exception side effect."""
    result = SetattrModel().apply([None, "x", 1], {}, _state())
    raised_effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(raised_effect)


def test_eval_symbolic_input_emits_critical_sink_event() -> None:
    """eval(symbolic) emits a critical sink_event side effect."""
    symbolic_code = SymbolicString.from_const("x + 1")
    result = EvalModel().apply([symbolic_code], {}, _state())
    sink_event = result.side_effects.get("sink_event")
    assert SideEffects.is_sink_event(sink_event) and sink_event["severity"] == "critical"


def test_exec_symbolic_input_emits_critical_sink_event() -> None:
    """exec(symbolic) emits a critical sink_event side effect."""
    symbolic_code = SymbolicString.from_const("x = 1")
    result = ExecModel().apply([symbolic_code], {}, _state())
    sink_event = result.side_effects.get("sink_event")
    assert SideEffects.is_sink_event(sink_event) and sink_event["severity"] == "critical"


def test_exec_simple_assignment_mutates_modeled_namespace() -> None:
    """exec of one simple assignment marks the namespace key as present."""
    symbolic_code = SymbolicString.from_const("result = seed + 2")
    namespace = SymbolicDict.from_const({"seed": 3})

    result = ExecModel().apply([symbolic_code, namespace], {}, _state())

    mutation = cast("dict[str, object]", result.side_effects.get("dict_mutation"))
    updated = cast("SymbolicDict", mutation["updated_dict"])
    found, value = updated.concrete_value_for_key("result")
    assert found is True
    assert value == 5
