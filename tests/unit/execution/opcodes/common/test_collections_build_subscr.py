from __future__ import annotations

from dataclasses import dataclass
from typing import cast

import pytest
import z3

from pysymex.analysis.detectors import IssueKind
from pysymex.typing import StackValue
from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.solver.engine.results import SolverResult
from pysymex.core.state.record import VMState
from pysymex.core.state.types import VMStateError
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.fallback import FallbackKind, RiskLevel, SoundnessTag
from pysymex.execution.opcodes.common.collections.build import (
    handle_common_build_const_key_map,
    handle_common_build_list,
    handle_common_build_map,
    handle_common_build_set,
    handle_common_build_tuple,
)
from pysymex.execution.opcodes.common.collections.fallbacks import (
    UNSUPPORTED_HASHED_COLLECTION_PROTOCOL,
)
from pysymex.execution.opcodes.common.collections.slice import handle_common_binary_slice
from pysymex.core.types.containers.slices import UNSUPPORTED_SLICE_ABSTRACTION
from pysymex.execution.opcodes.common.collections.subscript import (
    handle_common_binary_subscr,
    handle_common_store_subscr,
)
from pysymex.execution.opcodes.common.lowering.concrete_subscript import concrete_int_index
from pysymex.execution.opcodes.common.lowering.types import UNSUPPORTED_SUBSCRIPT_ABSTRACTION
from pysymex.models.objects import SymbolicClass, class_registry
from tests.unit.execution.opcodes.common.collections_helpers import instr


@dataclass(frozen=True)
class Entry:
    start: int
    end: int
    target: int
    depth: int
    lasti: bool


def test_handle_common_build_list_rejects_missing_elements() -> None:
    state = VMState(stack=[1], pc=10)
    with pytest.raises(VMStateError, match="BUILD_LIST"):
        handle_common_build_list(instr("BUILD_LIST", 2), state, OpcodeDispatcher())


def test_handle_common_build_const_key_map_rejects_missing_keys_tuple() -> None:
    state = VMState(stack=[1], pc=11)
    with pytest.raises(VMStateError, match="BUILD_CONST_KEY_MAP"):
        handle_common_build_const_key_map(
            instr("BUILD_CONST_KEY_MAP", 1), state, OpcodeDispatcher()
        )


def test_handle_common_build_const_key_map_preserves_unknown_key_count() -> None:
    keys, constraint = SymbolicValue.symbolic("keys")
    state = VMState(stack=[10, 20, keys], pc=21).add_constraint(constraint)

    result = handle_common_build_const_key_map(
        instr("BUILD_CONST_KEY_MAP", 2),
        state,
        OpcodeDispatcher(),
    )

    mapping = result.new_states[0].stack[-1]
    assert isinstance(mapping, SymbolicDict)
    assert z3.is_true(z3.simplify(mapping.z3_len == 2))


def test_handle_common_binary_subscr_rejects_missing_index() -> None:
    state = VMState(stack=[[1, 2, 3]], pc=12)
    with pytest.raises(VMStateError, match="BINARY_SUBSCR"):
        handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())


def test_handle_common_binary_subscr_preserves_concrete_list_lookup() -> None:
    state = VMState(stack=[[11, 22, 33], 1], pc=17)
    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())
    assert not result.terminal
    assert len(result.new_states) == 1
    assert result.new_states[0].stack[-1] == 22


def test_handle_common_binary_subscr_skips_sat_query_for_literal_false_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = VMState(stack=[[11, 22, 33], 1], pc=17)

    def fail_path_is_sat(_constraints: list[z3.BoolRef]) -> bool:
        raise AssertionError("literal false exception condition should not query SAT")

    monkeypatch.setattr(
        "pysymex.execution.opcodes.common.collections.read.path_is_sat",
        fail_path_is_sat,
    )

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    assert not result.terminal
    assert len(result.new_states) == 1
    assert result.new_states[0].stack[-1] == 22


def test_concrete_int_index_uses_symbolic_constant_payload_without_z3(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    index = SymbolicValue.from_const(2)

    def fail_simplify(_expr: z3.ExprRef) -> z3.ExprRef:
        raise AssertionError("concrete payload should avoid Z3 simplification")

    monkeypatch.setattr(z3, "simplify", fail_simplify)

    assert concrete_int_index(index) == 2


def test_handle_common_binary_subscr_terminates_uncaught_concrete_index_error() -> None:
    state = VMState(stack=[[11], 4], pc=18)
    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())
    assert result.terminal
    assert result.new_states == []


def test_handle_common_binary_subscr_reports_uncaught_concrete_key_error() -> None:
    state = VMState(stack=[{"present": 1}, "missing"], pc=18)

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.KEY_ERROR]


def test_handle_common_binary_subscr_does_not_report_key_error_on_solver_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = VMState(stack=[{"present": 1}, "missing"], pc=18)

    def unknown_check(
        _constraints: list[z3.BoolRef],
        *,
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        _ = known_sat_prefix_len
        return SolverResult.unknown()

    monkeypatch.setattr(
        "pysymex.execution.opcodes.common.collections.read.check_sat_result",
        unknown_check,
    )

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert result.issues == []


def test_handle_common_binary_subscr_passes_known_prefix_to_exception_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    x = z3.Int("subscript_prefix_x")
    y = z3.Int("subscript_prefix_y")
    seen_prefixes: list[int | None] = []
    seen_success_prefixes: list[int | None] = []
    state = VMState(
        stack=[{"present": 1}, "missing"],
        path_constraints=[x > 0, y > 0],
        pending_constraint_count=1,
        pc=18,
    )

    def unknown_check(
        _constraints: list[z3.BoolRef],
        *,
        known_sat_prefix_len: int | None = None,
    ) -> SolverResult:
        seen_prefixes.append(known_sat_prefix_len)
        return SolverResult.unknown()

    monkeypatch.setattr(
        "pysymex.execution.opcodes.common.collections.read.check_sat_result",
        unknown_check,
    )

    def fail_success_path(
        _constraints: list[z3.BoolRef],
        *,
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        seen_success_prefixes.append(known_sat_prefix_len)
        return False

    monkeypatch.setattr(
        "pysymex.execution.opcodes.common.collections.read.path_is_sat",
        fail_success_path,
    )

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    assert result.terminal
    assert seen_prefixes == [1]
    assert seen_success_prefixes == []
    assert result.issues == []


def test_handle_common_binary_subscr_reports_feasible_symbolic_index_error() -> None:
    index, index_constraint = SymbolicValue.symbolic("index")
    state = VMState(stack=[SymbolicList.from_const([11, 22, 33]), index], pc=19)
    state = state.add_constraint(index_constraint)

    result = handle_common_binary_subscr(
        instr("BINARY_SUBSCR"),
        state,
        OpcodeDispatcher(),
        report_mixed_list_error=True,
    )

    assert len(result.new_states) == 1
    assert any(issue.kind is IssueKind.INDEX_ERROR for issue in result.issues)


@pytest.mark.parametrize(("constraint_value", "expected"), [(1, 22), (-1, 33)])
def test_handle_common_binary_subscr_uses_unique_symbolic_index_for_concrete_list(
    constraint_value: int,
    expected: int,
) -> None:
    index, index_constraint = SymbolicValue.symbolic_int(f"index_{constraint_value}")
    state = VMState(stack=[SymbolicList.from_const([11, 22, 33]), index], pc=19)
    state = state.add_constraint(index_constraint)
    state = state.add_constraint(index.z3_int == constraint_value)

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    assert not result.terminal
    assert len(result.new_states) == 1
    assert result.new_states[0].stack[-1] == expected


def test_handle_common_binary_subscr_uses_exact_index_constraint_without_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    index, index_constraint = SymbolicValue.symbolic_int("exact_index_no_model")
    state = VMState(stack=[SymbolicList.from_const([11, 22, 33]), index], pc=19)
    state = state.add_constraint(index_constraint)
    state = state.add_constraint(index.z3_int == 1)

    def fail_get_model(_constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
        raise AssertionError("exact index equality should avoid model extraction")

    monkeypatch.setattr(
        "pysymex.execution.opcodes.common.collections.read.get_model",
        fail_get_model,
    )

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    assert not result.terminal
    assert len(result.new_states) == 1
    assert result.new_states[0].stack[-1] == 22


def test_handle_common_binary_subscr_does_not_lower_exact_index_on_infeasible_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    index, index_constraint = SymbolicValue.symbolic_int("exact_index_infeasible")
    guard = z3.Int("exact_index_guard")
    state = VMState(stack=[SymbolicList.from_const([11, 22, 33]), index], pc=19)
    state = state.add_constraint(index_constraint)
    state = state.add_constraint(index.z3_int == 1)
    state = state.add_constraint(guard > 0)
    state = state.add_constraint(guard < 0)

    def fail_get_model(_constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
        raise AssertionError("infeasible exact index should avoid model extraction")

    monkeypatch.setattr(
        "pysymex.execution.opcodes.common.collections.read.get_model",
        fail_get_model,
    )

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    assert not result.terminal
    assert len(result.new_states) == 1
    loaded = result.new_states[0].stack[-1]
    assert isinstance(loaded, SymbolicValue)
    assert loaded.value is None


def test_handle_common_binary_subscr_keeps_ambiguous_symbolic_index_symbolic() -> None:
    index, index_constraint = SymbolicValue.symbolic_int("ambiguous_index")
    state = VMState(stack=[SymbolicList.from_const([11, 22, 33]), index], pc=19)
    state = state.add_constraint(index_constraint)
    state = state.add_constraint(z3.Or(index.z3_int == 0, index.z3_int == 1))

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    assert not result.terminal
    assert len(result.new_states) == 1
    loaded = result.new_states[0].stack[-1]
    assert isinstance(loaded, SymbolicValue)
    assert loaded.value is None


def test_handle_common_binary_subscr_skips_model_for_ambiguous_integer_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    index, index_constraint = SymbolicValue.symbolic_int("ambiguous_integer_list_index")
    state = VMState(stack=[SymbolicList.from_const([11, 22, 33]), index], pc=19)
    state = state.add_constraint(index_constraint)
    state = state.add_constraint(z3.Or(index.z3_int == 0, index.z3_int == 1))

    def fail_get_model(_constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
        raise AssertionError("ambiguous integer-list lookup should use symbolic array fallback")

    monkeypatch.setattr(
        "pysymex.execution.opcodes.common.collections.read.get_model",
        fail_get_model,
    )

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    assert not result.terminal
    assert len(result.new_states) == 1
    loaded = result.new_states[0].stack[-1]
    assert isinstance(loaded, SymbolicValue)
    assert loaded.value is None


def test_handle_common_binary_subscr_integer_fallback_retains_exact_smt_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    index, index_constraint = SymbolicValue.symbolic_int("hidden_unique_integer_list_index")
    state = VMState(stack=[SymbolicList.from_const([11, 22, 33]), index], pc=19)
    state = state.add_constraint(index_constraint)
    state = state.add_constraint(index.z3_int >= 1)
    state = state.add_constraint(index.z3_int <= 1)

    def fail_get_model(_constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
        raise AssertionError("integer-list symbolic fallback should not require a model")

    monkeypatch.setattr(
        "pysymex.execution.opcodes.common.collections.read.get_model",
        fail_get_model,
    )

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    loaded = result.new_states[0].stack[-1]
    assert isinstance(loaded, SymbolicValue)
    solver = z3.Solver()
    solver.add(*result.new_states[0].path_constraints)
    solver.add(loaded.z3_int != 22)
    assert solver.check() == z3.unsat


def test_handle_common_binary_subscr_reports_unknown_container_abstraction() -> None:
    container, constraint = SymbolicValue.symbolic("unknown_container")
    state = VMState(stack=[container, 0], pc=20).add_constraint(constraint)

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), state, OpcodeDispatcher())

    assert result.degraded_passes == [UNSUPPORTED_SUBSCRIPT_ABSTRACTION]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.PRECISION_LOSS
    assert event.label == UNSUPPORTED_SUBSCRIPT_ABSTRACTION
    assert event.owner == "execution.opcodes.collections"
    assert event.reason == "subscript lowering required a collection abstraction"
    assert event.pc == 20
    assert event.soundness is SoundnessTag.PRECISION_LOSS
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_handle_common_binary_slice_reports_unsupported_slice_event() -> None:
    state = VMState(stack=[cast("StackValue", object()), 0, 1], pc=21)

    result = handle_common_binary_slice(instr("BINARY_SLICE"), state, OpcodeDispatcher())

    assert result.degraded_passes == [UNSUPPORTED_SLICE_ABSTRACTION]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.PRECISION_LOSS
    assert event.label == UNSUPPORTED_SLICE_ABSTRACTION
    assert event.owner == "execution.opcodes.collections"
    assert event.reason == "BINARY_SLICE precision was reduced to a symbolic slice result"
    assert event.pc == 21
    assert event.soundness is SoundnessTag.PRECISION_LOSS
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_handle_common_store_subscr_mutates_concrete_list() -> None:
    items = [1, 2]
    stack = [cast(StackValue, 9), cast(StackValue, items), cast(StackValue, 1)]
    local_vars = {"items": cast(StackValue, items)}
    state = VMState(stack=stack, local_vars=local_vars, pc=25)

    result = handle_common_store_subscr(instr("STORE_SUBSCR"), state, OpcodeDispatcher())

    assert not result.terminal
    assert items == [1, 9]
    assert result.new_states[0].stack == []
    assert result.new_states[0].local_vars["items"] == [1, 9]


def test_handle_common_store_subscr_mutates_concrete_dict() -> None:
    mapping: dict[object, object] = {"a": 1}
    stack = [cast(StackValue, 2), cast(StackValue, mapping), cast(StackValue, "b")]
    local_vars = {"mapping": cast(StackValue, mapping)}
    state = VMState(stack=stack, local_vars=local_vars, pc=26)

    result = handle_common_store_subscr(instr("STORE_SUBSCR"), state, OpcodeDispatcher())

    assert not result.terminal
    assert mapping == {"a": 1, "b": 2}
    assert result.new_states[0].local_vars["mapping"] == {"a": 1, "b": 2}


def test_handle_common_store_subscr_reports_definite_none_type_error() -> None:
    state = VMState(stack=[9, None, 0], pc=27)

    result = handle_common_store_subscr(instr("STORE_SUBSCR", offset=4), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "'NoneType' object does not support item assignment" in result.issues[0].message


def test_handle_common_store_subscr_routes_definite_type_error_to_handler() -> None:
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([instr("STORE_SUBSCR", offset=4), instr("NOP", offset=20)])
    dispatcher.set_exception_entries([Entry(start=4, end=6, target=20, depth=0, lasti=False)])
    state = VMState(stack=[9, None, 0], pc=0)

    result = handle_common_store_subscr(instr("STORE_SUBSCR", offset=4), state, dispatcher)

    assert not result.terminal
    assert result.issues == []
    next_state = result.new_states[0]
    assert next_state.pc == 1
    assert len(next_state.stack) == 1
    exception = next_state.stack[0]
    assert isinstance(exception, SymbolicException)
    assert exception.type_name == "TypeError"


def test_handle_common_store_subscr_reports_string_item_assignment_type_error() -> None:
    state = VMState(stack=["x", SymbolicString.from_const("abc"), 0], pc=28)

    result = handle_common_store_subscr(instr("STORE_SUBSCR"), state, OpcodeDispatcher())

    assert result.terminal
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert "'str' object does not support item assignment" in result.issues[0].message


def test_handle_common_store_subscr_refreshes_direct_symbolic_list_alias() -> None:
    items = SymbolicList.from_const([1, 2])
    state = VMState(stack=[9, items, 1], local_vars={"items": items}, pc=29)

    result = handle_common_store_subscr(instr("STORE_SUBSCR"), state, OpcodeDispatcher())

    updated = result.new_states[0].local_vars["items"]
    assert isinstance(updated, SymbolicList)
    assert updated is not items
    assert updated.concrete_items is not None
    assert getattr(updated.concrete_items[1], "value", None) == 9


def test_handle_common_build_set_preserves_concrete_set_semantics() -> None:
    state = VMState(stack=[1, 1, 2], pc=19)
    result = handle_common_build_set(instr("BUILD_SET", 3), state, OpcodeDispatcher())
    assert not result.terminal
    assert len(result.new_states) == 1
    assert getattr(result.new_states[0].stack[-1], "value") == {1, 2}


def test_handle_common_build_set_terminates_uncaught_unhashable_element() -> None:
    state = VMState(stack=[[1]], pc=20)
    result = handle_common_build_set(instr("BUILD_SET", 1), state, OpcodeDispatcher())
    assert result.terminal
    assert result.new_states == []


def _modeled_key_value() -> SymbolicValue:
    modeled_cls = class_registry.register_class(SymbolicClass("_HashedKey"))
    value = SymbolicValue.symbolic("hashed_key")[0]
    value.attach_modeled_object(class_registry.instantiate(modeled_cls))
    return value


def test_handle_common_build_set_degrades_modeled_object_hashing() -> None:
    result = handle_common_build_set(
        instr("BUILD_SET", 1), VMState(stack=[_modeled_key_value()], pc=20), OpcodeDispatcher()
    )

    assert result.terminal
    assert result.degraded_passes == [UNSUPPORTED_HASHED_COLLECTION_PROTOCOL]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == UNSUPPORTED_HASHED_COLLECTION_PROTOCOL
    assert event.owner == "execution.opcodes.collections"
    assert event.reason == "set construction requires modeled object hashing"
    assert event.pc == 20
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_handle_common_build_map_degrades_modeled_object_hashing() -> None:
    result = handle_common_build_map(
        instr("BUILD_MAP", 1),
        VMState(stack=[_modeled_key_value(), SymbolicValue.from_const(0)], pc=20),
        OpcodeDispatcher(),
    )

    assert result.terminal
    assert result.degraded_passes == [UNSUPPORTED_HASHED_COLLECTION_PROTOCOL]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == UNSUPPORTED_HASHED_COLLECTION_PROTOCOL
    assert event.owner == "execution.opcodes.collections"
    assert event.reason == "dict construction requires modeled object key hashing"
    assert event.pc == 20
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_handle_common_build_tuple_does_not_require_modeled_object_hashing() -> None:
    result = handle_common_build_tuple(
        instr("BUILD_TUPLE", 1), VMState(stack=[_modeled_key_value()], pc=20), OpcodeDispatcher()
    )

    assert not result.terminal
    assert result.degraded_passes == []


def test_handle_common_build_list_stores_nested_symbolic_container_address() -> None:
    nested = SymbolicList.empty("nested")
    state = VMState(stack=[nested], pc=22)
    result = handle_common_build_list(instr("BUILD_LIST", 1), state, OpcodeDispatcher())

    next_state = result.new_states[0]
    handle = next_state.stack[-1]
    assert isinstance(handle, SymbolicObject)
    outer = next_state.memory[handle.address]
    assert isinstance(outer, SymbolicList)
    nested_addresses = [address for address, value in next_state.memory.items() if value is nested]
    assert len(nested_addresses) == 1
    stored_address = z3.simplify(z3.Select(outer.z3_array, z3.IntVal(0)))
    assert z3.is_true(z3.simplify(stored_address == z3.IntVal(nested_addresses[0])))


def test_handle_common_binary_subscr_recovers_nested_symbolic_container() -> None:
    nested = SymbolicList.empty("nested")
    build_state = VMState(stack=[nested], pc=23)
    build_result = handle_common_build_list(instr("BUILD_LIST", 1), build_state, OpcodeDispatcher())
    built_state = build_result.new_states[0]
    handle = built_state.stack[-1]
    built_state = built_state.push(0)

    result = handle_common_binary_subscr(instr("BINARY_SUBSCR"), built_state, OpcodeDispatcher())

    assert not result.terminal
    assert result.new_states[0].stack[-1] is nested
    assert isinstance(handle, SymbolicObject)


def test_handle_common_build_list_preserves_repeated_nested_alias_address() -> None:
    nested = SymbolicList.empty("nested")
    state = VMState(stack=[nested, nested], pc=24)
    result = handle_common_build_list(instr("BUILD_LIST", 2), state, OpcodeDispatcher())

    next_state = result.new_states[0]
    handle = next_state.stack[-1]
    assert isinstance(handle, SymbolicObject)
    outer = next_state.memory[handle.address]
    assert isinstance(outer, SymbolicList)
    nested_addresses = [address for address, value in next_state.memory.items() if value is nested]
    assert len(nested_addresses) == 1
    first_address = z3.simplify(z3.Select(outer.z3_array, z3.IntVal(0)))
    second_address = z3.simplify(z3.Select(outer.z3_array, z3.IntVal(1)))
    assert z3.is_true(z3.simplify(first_address == z3.IntVal(nested_addresses[0])))
    assert z3.is_true(z3.simplify(second_address == z3.IntVal(nested_addresses[0])))
