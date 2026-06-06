from __future__ import annotations

import dis
from collections.abc import Callable, Iterator
from unittest.mock import patch
from typing import cast

import pytest
import z3

from pysymex.analysis.detectors import IssueKind
from pysymex.core.state.types import CallFrame
from pysymex.core.state.record import VMState
from pysymex.core.state.types import ProtocolCallCandidate
from pysymex.core.types.containers.sequences import SymbolicIterator
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.calls.construction_fallbacks import (
    CONSTRUCTOR_RETURN_UNCERTAIN_REASON,
    UNSUPPORTED_CONSTRUCTION_PROTOCOL,
)
from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher
from pysymex.execution.fallback import FallbackKind, RiskLevel, SoundnessTag
from pysymex.execution.opcodes.common.control.feasibility import (
    branch_feasible,
    handle_common_pop_jump_bool,
)
from pysymex.execution.opcodes.common.control import feasibility as control_feasibility
from pysymex.execution.opcodes.common.control.protocol.fallbacks import (
    COMPARISON_REFLECTION_UNCERTAIN_REASON,
    INIT_RETURN_UNCERTAIN_REASON,
    PROTOCOL_FALLBACK_UNAVAILABLE_REASON,
    TRUTH_CALL_UNAVAILABLE_REASON,
    UNSUPPORTED_COMPARISON_PROTOCOL,
    UNSUPPORTED_COMPARISON_REFLECTION,
    UNSUPPORTED_INIT_RETURN_PROTOCOL,
    UNSUPPORTED_TRUTH_PROTOCOL,
)
from pysymex.execution.opcodes.common.control.protocol.negotiation import (
    continue_deferred_protocol_call,
)
from pysymex.execution.opcodes.common.control.flow import (
    handle_common_list_to_tuple_intrinsic,
    handle_common_for_iter,
    handle_common_get_iter,
)
from pysymex.execution.opcodes.common.control_fallbacks import (
    LIST_TO_TUPLE_TYPE_UNCERTAIN,
    LIST_TO_TUPLE_TYPE_UNCERTAIN_REASON,
)
from pysymex.execution.opcodes.common.control.match import (
    handle_common_match_class,
)
from pysymex.execution.opcodes.common.control.returns import (
    apply_argument_alias_updates,
    handle_common_return_value,
)
from pysymex.execution.opcodes.common.functions.protocol.fallbacks import (
    ITERATION_PROTOCOL_UNAVAILABLE_REASON,
    UNSUPPORTED_ITERATION_PROTOCOL,
)
from pysymex.execution.opcodes.common.numeric.fallbacks import (
    NUMERIC_REFLECTION_UNCERTAIN_REASON,
)
from pysymex.execution.opcodes.common.numeric.labels import UNSUPPORTED_NUMERIC_REFLECTION
from pysymex.execution.opcodes.py312.control import handle_return_const
from pysymex.models.objects import SymbolicClass, class_registry
from pysymex.typing import StackValue


def _instr(opname: str, argval: object = None, offset: int = 0) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval, offset=offset)


class _Point:
    __match_args__ = ("x",)

    def __init__(self, x: int) -> None:
        self.x = x


def _class_body_code(name: str) -> object:
    module_code = compile(f"class {name}:\n    pass\n", "<match-class-test>", "exec")
    for const in module_code.co_consts:
        if getattr(const, "co_name", None) == name:
            return const
    raise AssertionError(f"missing class body code for {name}")


def _symbolic_class_value(name: str, modeled_cls: SymbolicClass, code_obj: object) -> SymbolicValue:
    class_registry.register_code_object(code_obj, modeled_cls)
    class_value = SymbolicValue(
        _name=name,
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_obj=z3.BoolVal(True),
        is_none=z3.BoolVal(False),
        is_path=z3.BoolVal(False),
        affinity_type="type",
    )
    class_value.attach_modeled_object(code_obj)
    return class_value


def _symbolic_instance_value(name: str, modeled_cls: SymbolicClass) -> SymbolicValue:
    instance = class_registry.instantiate(modeled_cls)
    instance.set_attribute("x", 7)
    instance_value = SymbolicValue(
        _name=f"{name}instance",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        is_obj=z3.BoolVal(True),
        is_none=z3.BoolVal(False),
        is_path=z3.BoolVal(False),
        affinity_type=name,
    )
    instance_value.attach_modeled_object(instance)
    return instance_value


def _modeled_false_bool(_self: object) -> bool:
    return False


def _modeled_length(_self: object) -> int:
    return 0


def test_branch_feasible_skips_solver_for_complex_bitvector_guard() -> None:
    value = z3.Int("value")
    masked = z3.BV2Int(z3.Int2BV(value, 8) & z3.BitVecVal(3, 8), is_signed=False)

    with patch("pysymex.core.solver.engine.policies.path_may_be_feasible") as solver_query:
        assert branch_feasible([], masked == 1) is True

    solver_query.assert_not_called()


def test_branch_feasible_uses_constraint_chain_bitvector_summary() -> None:
    """BitVec path-context checks should use ConstraintChain metadata, not rescan the chain."""
    value = z3.Int("bitvector_path_value")
    masked = z3.BV2Int(z3.Int2BV(value, 8) & z3.BitVecVal(3, 8), is_signed=False)
    state = VMState(path_constraints=[masked == 1])

    with (
        patch("pysymex.core.solver.engine.policies.path_may_be_feasible") as solver_query,
        patch.object(
            control_feasibility,
            "constraints_include_bitvector_smt_theory",
            side_effect=AssertionError("ConstraintChain summary should avoid path rescans"),
        ),
    ):
        assert branch_feasible(state.path_constraints, value > 0) is True

    solver_query.assert_not_called()


def test_branch_feasible_uses_negative_constraint_chain_bitvector_summary() -> None:
    """A ConstraintChain that has no BitVec summary should not be rescanned."""
    value = z3.Int("non_bitvector_path_value")
    state = VMState(path_constraints=[value >= 0])

    with (
        patch(
            "pysymex.core.solver.engine.policies.path_may_be_feasible",
            return_value=True,
        ) as solver_query,
        patch.object(
            control_feasibility,
            "constraints_include_bitvector_smt_theory",
            side_effect=AssertionError("ConstraintChain summary should avoid path rescans"),
        ),
    ):
        assert branch_feasible(state.path_constraints, value > 0) is True

    solver_query.assert_called_once()


def test_handle_common_pop_jump_bool_passes_known_sat_prefix_to_branch_solver() -> None:
    calls: list[tuple[int, int | None]] = []

    def capture_path_query(
        constraints: list[z3.BoolRef],
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        calls.append((len(constraints), known_sat_prefix_len))
        return True

    x = z3.Int("pop_jump_prefix_x")
    y = z3.Int("pop_jump_prefix_y")
    cond_int = z3.Int("pop_jump_prefix_cond")
    condition = SymbolicValue(
        _name="pop_jump_prefix_condition",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=cond_int > 0,
        is_bool=z3.BoolVal(True),
        is_obj=z3.BoolVal(False),
        is_none=z3.BoolVal(False),
        is_path=z3.BoolVal(False),
        affinity_type="bool",
    )
    dispatcher = OpcodeDispatcher()
    branch_instr = _instr("POP_JUMP_IF_TRUE", 8, offset=0)
    dispatcher.set_instructions(
        [
            branch_instr,
            _instr("LOAD_CONST", offset=2),
            _instr("LOAD_CONST", offset=8),
        ]
    )
    state = VMState(
        stack=[condition],
        path_constraints=[x > 0, x < 10, y > 0],
        pending_constraint_count=2,
        pc=0,
    )

    with patch(
        "pysymex.core.solver.engine.policies.path_may_be_feasible",
        side_effect=capture_path_query,
    ):
        result = handle_common_pop_jump_bool(
            branch_instr,
            state,
            dispatcher,
            jump_when_true=True,
        )

    assert len(result.new_states) == 2
    assert calls == [(4, 1), (4, 1)]


def test_handle_common_pop_jump_bool_prefers_pop_jump_true_fallthrough_first() -> None:
    condition = SymbolicValue(
        _name="pop_jump_true_fallthrough_condition",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=z3.Bool("pop_jump_true_fallthrough_bool"),
        is_bool=z3.BoolVal(True),
        is_obj=z3.BoolVal(False),
        is_none=z3.BoolVal(False),
        is_path=z3.BoolVal(False),
        affinity_type="bool",
    )
    dispatcher = OpcodeDispatcher()
    branch_instr = _instr("POP_JUMP_IF_TRUE", 8, offset=0)
    dispatcher.set_instructions(
        [
            branch_instr,
            _instr("LOAD_CONST", offset=2),
            _instr("LOAD_CONST", offset=8),
        ]
    )

    result = handle_common_pop_jump_bool(
        branch_instr,
        VMState(stack=[condition], pc=0),
        dispatcher,
        jump_when_true=True,
    )

    assert [branch.pc for branch in result.new_states] == [1, 2]


def test_handle_common_pop_jump_bool_prefers_string_witness_branch_order() -> None:
    """Branch ordering should favor a verified concrete string witness without pruning."""
    key = z3.String("key_str_65536_str")
    length = z3.Int("len_key_str_int")
    first_ord = z3.Int("ord_20_65541_int")
    cond_expr = first_ord % 2 == 1
    condition = SymbolicValue(
        _name="license_parity",
        z3_int=z3.IntVal(0),
        is_int=z3.BoolVal(False),
        z3_bool=cond_expr,
        is_bool=z3.BoolVal(True),
        is_obj=z3.BoolVal(False),
        is_none=z3.BoolVal(False),
        is_path=z3.BoolVal(False),
        affinity_type="bool",
    )
    dispatcher = OpcodeDispatcher()
    branch_instr = _instr("POP_JUMP_IF_FALSE", 8, offset=0)
    dispatcher.set_instructions(
        [
            branch_instr,
            _instr("LOAD_CONST", offset=2),
            _instr("LOAD_CONST", offset=8),
        ]
    )
    state = VMState(
        stack=[condition],
        path_constraints=[
            length == z3.Length(key),
            length == 16,
            first_ord == z3.StrToCode(z3.SubString(key, 0, 1)),
        ],
        pc=0,
    )

    result = handle_common_pop_jump_bool(branch_instr, state, dispatcher, jump_when_true=False)

    assert [branch.pc for branch in result.new_states] == [2, 1]


def test_string_witness_term_cache_reuses_subtree_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expr = z3.Int("string_witness_cache_x") + 1 < 3
    expr_cache = getattr(control_feasibility, "_STRING_WITNESS_EXPR_CACHE")
    getattr(expr_cache, "clear")()
    uncached_has_terms = cast(
        "Callable[[tuple[z3.ExprRef, ...]], bool]",
        getattr(control_feasibility, "_uncached_has_string_witness_terms"),
    )

    assert uncached_has_terms((expr,)) is False

    def fail_is_string_witness_term(_expr: z3.ExprRef) -> bool:
        raise AssertionError("cached subtree result should skip witness-term scan")

    monkeypatch.setattr(
        control_feasibility,
        "_is_string_witness_term",
        fail_is_string_witness_term,
    )

    assert uncached_has_terms((expr,)) is False


def test_preferred_truth_order_scans_condition_once_for_string_witness_terms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    condition = z3.Bool("preferred_truth_order_condition")
    constraints = [z3.BoolVal(True)]
    observed: list[tuple[z3.ExprRef, ...]] = []
    preferred_truth_order = cast(
        "Callable[[list[z3.BoolRef], z3.BoolRef, z3.BoolRef], tuple[bool, bool]]",
        getattr(control_feasibility, "_preferred_truth_order"),
    )

    def no_string_witness_terms(expressions: tuple[z3.ExprRef, ...]) -> bool:
        observed.append(expressions)
        return False

    monkeypatch.setattr(
        control_feasibility,
        "_has_string_witness_terms",
        no_string_witness_terms,
    )

    assert preferred_truth_order(constraints, condition, z3.Not(condition)) == (True, False)
    assert observed == [(condition,)]


def test_preferred_truth_order_uses_default_order_without_string_witness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    condition = z3.Bool("preferred_truth_order_default_condition")
    preferred_truth_order = cast(
        "Callable[..., tuple[bool, bool]]",
        getattr(control_feasibility, "_preferred_truth_order"),
    )

    def no_string_witness_terms(_expressions: tuple[z3.ExprRef, ...]) -> bool:
        return False

    monkeypatch.setattr(
        control_feasibility,
        "_has_string_witness_terms",
        no_string_witness_terms,
    )

    assert preferred_truth_order(
        [z3.BoolVal(True)],
        condition,
        z3.Not(condition),
        default_order=(False, True),
    ) == (False, True)


def test_preferred_truth_order_skips_constraint_materialization_without_string_witness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    condition = z3.Bool("preferred_truth_order_no_materialize_condition")
    preferred_truth_order = cast(
        "Callable[[object, z3.BoolRef, z3.BoolRef], tuple[bool, bool]]",
        getattr(control_feasibility, "_preferred_truth_order"),
    )

    class ConstraintsThatShouldNotBeRead:
        def __iter__(self) -> Iterator[z3.BoolRef]:
            raise AssertionError("constraints should not be read without witness terms")

    def no_string_witness_terms(_expressions: tuple[z3.ExprRef, ...]) -> bool:
        return False

    monkeypatch.setattr(
        control_feasibility,
        "_has_string_witness_terms",
        no_string_witness_terms,
    )

    assert preferred_truth_order(
        ConstraintsThatShouldNotBeRead(),
        condition,
        z3.Not(condition),
    ) == (True, False)


def test_handle_common_pop_jump_bool_resumes_after_modeled_bool_return() -> None:
    modeled_cls = class_registry.register_class(SymbolicClass("_BranchBool"))
    modeled_cls.add_method("__bool__", _modeled_false_bool)
    instance_value = _symbolic_instance_value("_BranchBool", modeled_cls)
    dispatcher = OpcodeDispatcher()
    branch_instr = _instr("POP_JUMP_IF_FALSE", 8, offset=0)
    dispatcher.set_instructions([branch_instr, _instr("NOP", offset=8)])

    dispatched = handle_common_pop_jump_bool(
        branch_instr,
        VMState(stack=[instance_value], pc=0),
        dispatcher,
        jump_when_true=False,
    )
    callee_state = dispatched.new_states[0]
    assert callee_state.call_stack[-1].return_pc == 0

    resumed = handle_return_const(_instr("RETURN_CONST", False), callee_state, dispatcher)
    branch_state = resumed.new_states[0]
    assert branch_state.pc == 0

    completed = handle_common_pop_jump_bool(
        branch_instr,
        branch_state,
        dispatcher,
        jump_when_true=False,
    )
    assert len(completed.new_states) == 1
    assert completed.new_states[0].pc == 1


def test_handle_common_pop_jump_bool_degrades_unexecutable_modeled_bool() -> None:
    modeled_cls = class_registry.register_class(SymbolicClass("_UnsupportedBool"))
    modeled_cls.add_method("__bool__")
    instance_value = _symbolic_instance_value("_UnsupportedBool", modeled_cls)
    dispatcher = OpcodeDispatcher()
    branch_instr = _instr("POP_JUMP_IF_FALSE", 8, offset=0)
    dispatcher.set_instructions([branch_instr, _instr("NOP", offset=8)])

    result = handle_common_pop_jump_bool(
        branch_instr,
        VMState(stack=[instance_value], pc=0),
        dispatcher,
        jump_when_true=False,
    )

    assert result.terminal is True
    assert result.new_states == []
    assert result.degraded_passes == [UNSUPPORTED_TRUTH_PROTOCOL]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == UNSUPPORTED_TRUTH_PROTOCOL
    assert event.owner == "execution.opcodes.control.truth"
    assert event.reason == TRUTH_CALL_UNAVAILABLE_REASON
    assert event.pc == 0
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_handle_common_pop_jump_bool_forks_negative_symbolic_modeled_length_result() -> None:
    modeled_cls = class_registry.register_class(SymbolicClass("_SymbolicLength"))
    modeled_cls.add_method("__len__", _modeled_length)
    instance_value = _symbolic_instance_value("_SymbolicLength", modeled_cls)
    dispatcher = OpcodeDispatcher()
    branch_instr = _instr("POP_JUMP_IF_FALSE", 8, offset=0)
    dispatcher.set_instructions([branch_instr, _instr("NOP", offset=8)])

    dispatched = handle_common_pop_jump_bool(
        branch_instr,
        VMState(stack=[instance_value], pc=0),
        dispatcher,
        jump_when_true=False,
    )
    symbolic_length, _ = SymbolicValue.symbolic_int("protocol_length")
    callee_state = dispatched.new_states[0].push(symbolic_length)
    result = handle_common_return_value(_instr("RETURN_VALUE"), callee_state, dispatcher)

    assert result.terminal is False
    assert len(result.new_states) == 1
    assert [issue.kind for issue in result.issues] == [IssueKind.VALUE_ERROR]
    assert result.degraded_passes == []


def test_handle_common_return_value_records_construction_return_event() -> None:
    class_name = "_AmbiguousNewReturn"
    code_obj = _class_body_code(class_name)
    modeled_cls = class_registry.register_class(SymbolicClass(class_name))
    class_value = _symbolic_class_value(class_name, modeled_cls, code_obj)
    return_value, constraint = SymbolicValue.symbolic("maybe_constructed")
    frame = CallFrame(
        function_name="__new__",
        return_pc=2,
        local_vars=VMState().local_vars,
        stack_depth=0,
        protocol_method="__new__",
        protocol_retained_operand=(class_value, (), {}),
    )
    state = VMState(stack=[return_value], path_constraints=[constraint], pc=18, call_stack=[frame])

    result = handle_common_return_value(_instr("RETURN_VALUE"), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert result.degraded_passes == [UNSUPPORTED_CONSTRUCTION_PROTOCOL]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == UNSUPPORTED_CONSTRUCTION_PROTOCOL
    assert event.owner == "execution.calls.construction"
    assert event.reason == CONSTRUCTOR_RETURN_UNCERTAIN_REASON
    assert event.pc == 18
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_handle_common_return_value_records_comparison_reflection_event() -> None:
    left, left_constraint = SymbolicValue.symbolic("ambiguous_left")
    right, right_constraint = SymbolicValue.symbolic("ambiguous_right")
    frame = CallFrame(
        function_name="__eq__",
        return_pc=2,
        local_vars=VMState().local_vars,
        stack_depth=0,
        protocol_method="__richcmp_eq__",
        protocol_retained_operand=(left, right),
    )
    state = VMState(
        stack=[NotImplemented],
        path_constraints=[left_constraint, right_constraint],
        pc=19,
        call_stack=[frame],
    )

    result = handle_common_return_value(_instr("RETURN_VALUE"), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert result.degraded_passes == [UNSUPPORTED_COMPARISON_REFLECTION]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == UNSUPPORTED_COMPARISON_REFLECTION
    assert event.owner == "execution.opcodes.compare.reflection"
    assert event.reason == COMPARISON_REFLECTION_UNCERTAIN_REASON
    assert event.pc == 19
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_handle_common_return_value_records_numeric_reflection_event() -> None:
    left, left_constraint = SymbolicValue.symbolic("ambiguous_numeric_left")
    right, right_constraint = SymbolicValue.symbolic("ambiguous_numeric_right")
    frame = CallFrame(
        function_name="__add__",
        return_pc=2,
        local_vars=VMState().local_vars,
        stack_depth=0,
        protocol_method="__numeric__",
        protocol_retained_operand=("+", left, right),
    )
    state = VMState(
        stack=[NotImplemented],
        path_constraints=[left_constraint, right_constraint],
        pc=22,
        call_stack=[frame],
    )

    result = handle_common_return_value(_instr("RETURN_VALUE"), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert result.degraded_passes == [UNSUPPORTED_NUMERIC_REFLECTION]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == UNSUPPORTED_NUMERIC_REFLECTION
    assert event.owner == "execution.opcodes.numeric.reflection"
    assert event.reason == NUMERIC_REFLECTION_UNCERTAIN_REASON
    assert event.pc == 22
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_handle_common_return_value_records_init_return_event() -> None:
    return_value, constraint = SymbolicValue.symbolic("maybe_init_return")
    frame = CallFrame(
        function_name="__init__",
        return_pc=2,
        local_vars=VMState().local_vars,
        stack_depth=0,
        is_init_call=True,
    )
    state = VMState(stack=[return_value], path_constraints=[constraint], pc=20, call_stack=[frame])

    result = handle_common_return_value(_instr("RETURN_VALUE"), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert result.degraded_passes == [UNSUPPORTED_INIT_RETURN_PROTOCOL]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == UNSUPPORTED_INIT_RETURN_PROTOCOL
    assert event.owner == "execution.opcodes.control.init_return"
    assert event.reason == INIT_RETURN_UNCERTAIN_REASON
    assert event.pc == 20
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_continue_deferred_protocol_call_records_comparison_event() -> None:
    modeled_cls = class_registry.register_class(SymbolicClass("_MissingFallbackCompare"))
    owner = _symbolic_instance_value("_MissingFallbackCompare", modeled_cls)
    frame = CallFrame(
        function_name="__lt__",
        return_pc=2,
        local_vars=VMState().local_vars,
        stack_depth=0,
        protocol_method="__richcmp__",
        protocol_fallbacks=(
            ProtocolCallCandidate(
                owner=owner,
                method_name="__gt__",
                argument=SymbolicValue.from_const(1),
            ),
        ),
    )
    state = VMState(pc=21)

    result = continue_deferred_protocol_call(
        frame,
        NotImplemented,
        state,
        OpcodeDispatcher(),
    )

    assert result is not None
    assert result.terminal
    assert result.new_states == []
    assert result.degraded_passes == [UNSUPPORTED_COMPARISON_PROTOCOL]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == UNSUPPORTED_COMPARISON_PROTOCOL
    assert event.owner == "execution.opcodes.compare"
    assert event.reason == PROTOCOL_FALLBACK_UNAVAILABLE_REASON
    assert event.pc == 21
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_apply_argument_alias_updates_restores_path_local_caller_mapping() -> None:
    caller = VMState()
    caller = caller.set_local("item", SymbolicValue.from_const(1))
    frame = CallFrame(
        function_name="callee",
        return_pc=1,
        local_vars=caller.local_vars,
        stack_depth=0,
    )

    first_return = apply_argument_alias_updates(VMState(), frame)
    second_return = apply_argument_alias_updates(VMState(), frame)
    first_return["item"] = SymbolicValue.from_const(7)

    second_item = second_return["item"]
    original_item = frame.local_vars["item"]
    assert isinstance(second_item, SymbolicValue)
    assert isinstance(original_item, SymbolicValue)
    assert second_item.value == 1
    assert original_item.value == 1


def test_handle_common_match_class_returns_attr_tuple_for_concrete_keyword_match() -> None:
    state = VMState(stack=cast("list[StackValue]", [_Point(5), _Point, ("x",)]), pc=4)

    result = handle_common_match_class(_instr("MATCH_CLASS", 0), state, OpcodeDispatcher())

    assert result.new_states[0].stack[-1] == (5,)


def test_handle_common_match_class_returns_match_self_tuple_for_builtin_positional_match() -> None:
    state = VMState(stack=["abc", str, ()], pc=5)

    result = handle_common_match_class(_instr("MATCH_CLASS", 1), state, OpcodeDispatcher())

    assert result.new_states[0].stack[-1] == ("abc",)


def test_handle_common_match_class_returns_none_for_concrete_mismatch() -> None:
    state = VMState(stack=[1, str, ()], pc=6)

    result = handle_common_match_class(_instr("MATCH_CLASS", 0), state, OpcodeDispatcher())

    assert isinstance(result.new_states[0].stack[-1], SymbolicNone)


def test_handle_common_match_class_constrains_symbolic_builtin_success() -> None:
    subject, type_constraint = SymbolicValue.symbolic("subject")
    state = VMState(stack=[subject, int, ()], pc=7).add_constraint(type_constraint)

    result = handle_common_match_class(_instr("MATCH_CLASS", 0), state, OpcodeDispatcher())

    match_result = result.new_states[0].stack[-1]
    assert isinstance(match_result, SymbolicValue)
    solver = z3.Solver()
    solver.add(
        *result.new_states[0].path_constraints,
        subject.is_str,
        z3.Not(match_result.is_none),
    )
    assert solver.check() == z3.unsat


def test_handle_common_match_class_uses_modeled_user_class_identity() -> None:
    class_name = "_MatchPoint"
    code_obj = _class_body_code(class_name)
    modeled_cls = class_registry.register_class(SymbolicClass(class_name))
    modeled_cls.class_vars["__match_args__"] = ("x",)
    class_value = _symbolic_class_value(class_name, modeled_cls, code_obj)
    instance_value = _symbolic_instance_value(class_name, modeled_cls)
    state = VMState(stack=[instance_value, class_value, ()], pc=8)

    result = handle_common_match_class(_instr("MATCH_CLASS", 1), state, OpcodeDispatcher())

    assert result.new_states[0].stack[-1] == (7,)


def test_handle_common_match_class_rejects_different_modeled_user_class() -> None:
    subject_cls = class_registry.register_class(SymbolicClass("_SubjectClass"))
    pattern_cls = class_registry.register_class(SymbolicClass("_PatternClass"))
    pattern_value = _symbolic_class_value(
        "_PatternClass", pattern_cls, _class_body_code("_PatternClass")
    )
    subject_value = _symbolic_instance_value("_SubjectClass", subject_cls)
    state = VMState(stack=[subject_value, pattern_value, ()], pc=9)

    result = handle_common_match_class(_instr("MATCH_CLASS", 0), state, OpcodeDispatcher())

    assert isinstance(result.new_states[0].stack[-1], SymbolicNone)


def test_handle_common_match_class_accepts_modeled_user_subclass() -> None:
    parent_cls = class_registry.register_class(SymbolicClass("_PatternParent"))
    child_cls = class_registry.register_class(SymbolicClass("_PatternChild", bases=[parent_cls]))
    parent_cls.class_vars["__match_args__"] = ("x",)
    pattern_value = _symbolic_class_value(
        "_PatternParent",
        parent_cls,
        _class_body_code("_PatternParent"),
    )
    subject_value = _symbolic_instance_value("_PatternChild", child_cls)
    state = VMState(stack=[subject_value, pattern_value, ()], pc=10)

    result = handle_common_match_class(_instr("MATCH_CLASS", 1), state, OpcodeDispatcher())

    assert result.new_states[0].stack[-1] == (7,)


def test_handle_common_get_iter_preserves_existing_symbolic_iterator() -> None:
    """GET_ITER should match CPython's iter(iterator) idempotence."""
    source = SymbolicList.from_const([10, 20])
    iterator = SymbolicIterator("it", source)
    state = VMState(stack=[iterator], pc=3)

    result = handle_common_get_iter(_instr("GET_ITER"), state, OpcodeDispatcher())

    next_iterator = result.new_states[0].peek()
    assert next_iterator is iterator

    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("FOR_ITER", 10, offset=0), _instr("NOP", offset=10)])
    iter_state = VMState(stack=[next_iterator], pc=0)
    iter_result = handle_common_for_iter(_instr("FOR_ITER", 10, offset=0), iter_state, dispatcher)

    continue_state = iter_result.new_states[0]
    advanced = continue_state.stack[-2]
    assert isinstance(advanced, SymbolicIterator)
    assert advanced.index == 1
    assert continue_state.stack[-1] == 10


def test_handle_common_for_iter_yields_concrete_tuple_items() -> None:
    """Concrete tuple iteration must not invent unconstrained symbolic values."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("FOR_ITER", 10, offset=0), _instr("NOP", offset=10)])
    iterator = SymbolicIterator("tuple_iter", (2, 4, 6))
    state = VMState(stack=[iterator], pc=0)

    result = handle_common_for_iter(_instr("FOR_ITER", 10, offset=0), state, dispatcher)

    continue_state = result.new_states[0]
    advanced = continue_state.stack[-2]
    assert isinstance(advanced, SymbolicIterator)
    assert advanced.index == 1
    assert continue_state.stack[-1] == 2


def test_handle_common_for_iter_continues_symbolic_string_before_exact_length() -> None:
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("FOR_ITER", 10, offset=0), _instr("NOP", offset=10)])
    symbolic_string, type_constraint = SymbolicString.symbolic("key")
    length_slot = z3.Int("len_key_int")
    state = VMState(
        stack=[SymbolicIterator("string_iter", symbolic_string, index=10)],
        path_constraints=[
            type_constraint,
            length_slot == symbolic_string.z3_len,
            z3.Not(16 != length_slot),
        ],
        pc=0,
    )

    result = handle_common_for_iter(_instr("FOR_ITER", 10, offset=0), state, dispatcher)

    assert len(result.new_states) == 1
    continue_state = result.new_states[0]
    advanced = continue_state.stack[-2]
    assert isinstance(advanced, SymbolicIterator)
    assert advanced.index == 11
    assert isinstance(continue_state.stack[-1], SymbolicString)


def test_handle_common_for_iter_exits_symbolic_string_at_exact_length() -> None:
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("FOR_ITER", 10, offset=0), _instr("NOP", offset=10)])
    symbolic_string, type_constraint = SymbolicString.symbolic("key")
    length_slot = z3.Int("len_key_int")
    state = VMState(
        stack=[SymbolicIterator("string_iter", symbolic_string, index=16)],
        path_constraints=[
            type_constraint,
            length_slot == symbolic_string.z3_len,
            z3.Not(16 != length_slot),
        ],
        pc=0,
    )

    result = handle_common_for_iter(_instr("FOR_ITER", 10, offset=0), state, dispatcher)

    assert len(result.new_states) == 1
    exit_state = result.new_states[0]
    assert exit_state.pc == 1
    assert isinstance(exit_state.stack[-1], SymbolicNone)


def test_handle_common_for_iter_preserves_tuple_element_for_unpacking() -> None:
    """``enumerate``-style tuple items should stay concrete for UNPACK_SEQUENCE."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("FOR_ITER", 10, offset=0), _instr("NOP", offset=10)])
    iterator = SymbolicIterator("pairs", ((0, "a"), (1, "b")))
    state = VMState(stack=[iterator], pc=0)

    result = handle_common_for_iter(_instr("FOR_ITER", 10, offset=0), state, dispatcher)

    assert result.new_states[0].stack[-1] == (0, "a")


def test_handle_common_for_iter_unwraps_concrete_tuple_symbolic_value() -> None:
    """LOAD_CONST tuple values may be wrapped before GET_ITER reaches FOR_ITER."""
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions([_instr("FOR_ITER", 10, offset=0), _instr("NOP", offset=10)])
    wrapped_tuple = SymbolicValue.from_const((2, 4, 6))
    iterator = SymbolicIterator("wrapped_tuple", wrapped_tuple)
    state = VMState(stack=[iterator], pc=0)

    result = handle_common_for_iter(_instr("FOR_ITER", 10, offset=0), state, dispatcher)

    assert result.new_states[0].stack[-1] == 2


def test_handle_common_get_iter_records_iteration_protocol_event() -> None:
    modeled_cls = class_registry.register_class(SymbolicClass("_UnsupportedIter"))
    modeled_cls.add_method("__iter__")
    instance_value = _symbolic_instance_value("_UnsupportedIter", modeled_cls)
    state = VMState(stack=[instance_value], pc=22)

    result = handle_common_get_iter(_instr("GET_ITER"), state, OpcodeDispatcher())

    assert result.terminal
    assert result.new_states == []
    assert result.degraded_passes == [UNSUPPORTED_ITERATION_PROTOCOL]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == UNSUPPORTED_ITERATION_PROTOCOL
    assert event.owner == "execution.opcodes.iteration"
    assert event.reason == ITERATION_PROTOCOL_UNAVAILABLE_REASON
    assert event.pc == 22
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_handle_common_for_iter_records_iteration_protocol_event() -> None:
    modeled_cls = class_registry.register_class(SymbolicClass("_UnsupportedNext"))
    modeled_cls.add_method("__next__")
    iterator_value = _symbolic_instance_value("_UnsupportedNext", modeled_cls)
    dispatcher = OpcodeDispatcher()
    for_iter = _instr("FOR_ITER", 10, offset=0)
    dispatcher.set_instructions([for_iter, _instr("NOP", offset=10)])
    state = VMState(stack=[iterator_value], pc=23)

    result = handle_common_for_iter(for_iter, state, dispatcher)

    assert result.terminal
    assert result.new_states == []
    assert result.degraded_passes == [UNSUPPORTED_ITERATION_PROTOCOL]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.UNSUPPORTED
    assert event.label == UNSUPPORTED_ITERATION_PROTOCOL
    assert event.owner == "execution.opcodes.iteration"
    assert event.reason == ITERATION_PROTOCOL_UNAVAILABLE_REASON
    assert event.pc == 23
    assert event.soundness is SoundnessTag.UNSUPPORTED
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.HIGH


def test_handle_common_list_to_tuple_intrinsic_records_uncertain_type_event() -> None:
    source, source_constraint = SymbolicValue.symbolic("maybe_list_to_tuple")
    state = VMState(path_constraints=[source_constraint], pc=24)

    result = handle_common_list_to_tuple_intrinsic(
        _instr("CALL_INTRINSIC_1", 6),
        state,
        source,
    )

    assert result.terminal is False
    assert result.degraded_passes == [LIST_TO_TUPLE_TYPE_UNCERTAIN]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.kind is FallbackKind.PRECISION_LOSS
    assert event.label == LIST_TO_TUPLE_TYPE_UNCERTAIN
    assert event.owner == "execution.opcodes.control"
    assert event.reason == LIST_TO_TUPLE_TYPE_UNCERTAIN_REASON
    assert event.pc == 24
    assert event.soundness is SoundnessTag.PRECISION_LOSS
    assert event.false_positive_risk is RiskLevel.MEDIUM
    assert event.false_negative_risk is RiskLevel.MEDIUM
