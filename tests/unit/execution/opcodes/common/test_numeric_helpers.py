from __future__ import annotations

import dis
from dataclasses import dataclass
from unittest.mock import patch

import z3

from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.engine.results import SolverResult
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
from pysymex._internal.execution.opcodes.common.numeric.labels import (
    NUMERIC_TYPE_ERROR_FEASIBILITY_UNKNOWN,
    NUMERIC_ZERO_DIVISION_FEASIBILITY_UNKNOWN,
)
from pysymex._internal.execution.opcodes.common.numeric.ops.dispatch import handle_numeric_binary_op
from pysymex._internal.execution.opcodes.common.numeric.ops.special import (
    handle_bitwise_op,
    handle_power_op,
    handle_shift_op,
)
from pysymex._internal.execution.opcodes.common.satisfiability import PathSatisfiability


def _instr(opname: str, argrepr: str = "", *, offset: int = 0) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argrepr=argrepr, offset=offset)


@dataclass(frozen=True, slots=True)
class _Entry:
    start: int
    end: int
    target: int
    depth: int
    lasti: bool


def test_path_is_sat_uses_solver_for_long_nontrivial_contradictions() -> None:
    x = z3.Int("x")
    padding = [z3.Int(f"p{i}") == i for i in range(12)]

    assert PathSatisfiability.is_sat([*padding, x > 0, x < 0]) is False


def test_path_is_sat_keeps_satisfiable_long_paths_feasible() -> None:
    x = z3.Int("x")
    padding = [z3.Int(f"q{i}") == i for i in range(12)]

    assert PathSatisfiability.is_sat([*padding, x > 0, x < 5]) is True


def test_modulo_by_concrete_nonzero_divisor_skips_zero_feasibility_query() -> None:
    value, value_constraint = SymbolicValue.symbolic_int("value")
    state = VMState(stack=[value, 2], path_constraints=[value_constraint])

    result = handle_numeric_binary_op(_instr("BINARY_OP", "%"), state, OpcodeDispatcher())

    assert len(result.new_states) == 1


def test_symbolic_division_checks_issue_condition_after_inconclusive_path_prefix() -> None:
    left = SymbolicValue.from_const(10)
    right, right_constraint = SymbolicValue.symbolic_int("inconclusive_divisor")
    state = VMState(
        stack=[left, right],
        path_constraints=[right_constraint],
        pending_constraint_count=1,
        last_inconclusive_feasibility_len=1,
    )

    with patch(
        "pysymex._internal.execution.opcodes.common.numeric.ops.dispatch.PathSatisfiability.result",
        return_value=SolverResult.unsat(),
    ) as check_result:
        result = handle_numeric_binary_op(_instr("BINARY_OP", "/"), state, OpcodeDispatcher())

    check_result.assert_called_once()
    assert len(result.new_states) == 1


def test_symbolic_division_unknown_zero_branch_checks_complement_for_diagnostics() -> None:
    left = SymbolicValue.from_const(10)
    right, right_constraint = SymbolicValue.symbolic_int("unknown_zero_divisor")
    state = VMState(stack=[left, right], path_constraints=[right_constraint])

    with (
        patch(
            "pysymex._internal.execution.opcodes.common.numeric.ops.dispatch.PathSatisfiability.result",
            return_value=SolverResult.unknown(),
        ) as check_result,
    ):
        result = handle_numeric_binary_op(_instr("BINARY_OP", "/"), state, OpcodeDispatcher())

    assert check_result.call_count == 2
    assert len(result.new_states) == 1
    assert result.degraded_passes == [NUMERIC_ZERO_DIVISION_FEASIBILITY_UNKNOWN]
    assert len(result.fallback_events) == 1
    assert result.fallback_events[0].label == NUMERIC_ZERO_DIVISION_FEASIBILITY_UNKNOWN
    assert result.fallback_events[0].reason == (
        "solver could not establish zero/nonzero numeric zero-division feasibility"
    )


def test_uncaught_numeric_type_error_carries_model_evidence() -> None:
    value, value_constraint = SymbolicValue.symbolic_int("type_error_value")
    state = VMState(
        stack=[SymbolicString.from_const("bad"), value],
        path_constraints=[value_constraint, value.z3_int == 7],
        pc=9,
    )

    result = handle_numeric_binary_op(_instr("BINARY_OP", "+"), state, OpcodeDispatcher())

    assert result.terminal is True
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert result.issues[0].constraints == [value_constraint, value.z3_int == 7]
    assert result.issues[0].model is not None
    assert result.degraded_passes == []
    assert result.fallback_events == []


def test_handled_numeric_type_error_preserves_message_for_reraise() -> None:
    dispatcher = OpcodeDispatcher()
    dispatcher.set_instructions(
        [_instr("BINARY_OP", "+", offset=4), _instr("PUSH_EXC_INFO", offset=20)]
    )
    dispatcher.set_exception_entries([_Entry(4, 6, 20, 0, False)])
    state = VMState(stack=[SymbolicString.from_const("bad"), 1], pc=0)

    result = handle_numeric_binary_op(_instr("BINARY_OP", "+", offset=4), state, dispatcher)

    assert result.terminal is False
    next_state = result.new_states[0]
    assert next_state.pc == dispatcher.offset_to_index(20)
    raised = next_state.stack[-1]
    assert getattr(raised, "type_name", None) == "TypeError"
    assert getattr(raised, "message", None) == "Cannot concatenate 'str' with non-'str' operand"


def test_uncaught_numeric_type_error_does_not_report_infeasible_path() -> None:
    value, value_constraint = SymbolicValue.symbolic_int("infeasible_type_error")
    state = VMState(
        stack=[SymbolicString.from_const("bad"), value],
        path_constraints=[value_constraint, value.z3_int == 1, value.z3_int == 2],
        pc=9,
    )

    result = handle_numeric_binary_op(_instr("BINARY_OP", "+"), state, OpcodeDispatcher())

    assert result.terminal is True
    assert result.issues == []
    assert result.degraded_passes == []
    assert result.fallback_events == []


def test_uncaught_numeric_type_error_unknown_is_inconclusive_not_issue() -> None:
    value, value_constraint = SymbolicValue.symbolic_int("unknown_type_error")
    state = VMState(
        stack=[SymbolicString.from_const("bad"), value],
        path_constraints=[value_constraint],
        pc=9,
    )

    with patch(
        "pysymex._internal.execution.opcodes.common.numeric.ops.errors.get_model_result",
        return_value=SolverResult.unknown(),
    ):
        result = handle_numeric_binary_op(_instr("BINARY_OP", "+"), state, OpcodeDispatcher())

    assert result.terminal is True
    assert result.issues == []
    assert result.degraded_passes == [NUMERIC_TYPE_ERROR_FEASIBILITY_UNKNOWN]
    assert len(result.fallback_events) == 1
    assert result.fallback_events[0].label == NUMERIC_TYPE_ERROR_FEASIBILITY_UNKNOWN


def test_uncaught_numeric_type_error_unknown_uses_verified_hard_theory_witness() -> None:
    value, _value_constraint = SymbolicValue.symbolic_int("hard_theory_type_error_value")
    text = z3.String("hard_theory_type_error_text_str")
    parsed = z3.Int("hard_theory_type_error_parsed_int")
    state = VMState(
        stack=[SymbolicString.from_const("bad"), value],
        path_constraints=[
            z3.InRe(text, z3.Plus(z3.Re("0"))),
            parsed == z3.StrToInt(text),
            parsed == 0,
            value.z3_int == 3,
        ],
        pc=9,
    )

    with patch(
        "pysymex._internal.execution.opcodes.common.numeric.ops.errors.get_model_result",
        return_value=SolverResult.unknown(),
    ):
        result = handle_numeric_binary_op(_instr("BINARY_OP", "+"), state, OpcodeDispatcher())

    assert result.terminal is True
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert isinstance(result.issues[0].model, z3.ModelRef)
    assert z3.is_true(simplify_expr(result.issues[0].model.eval(text) == z3.StringVal("0")))
    assert result.issues[0].model.eval(value.z3_int).as_long() == 3
    assert result.degraded_passes == []
    assert result.fallback_events == []


def test_uncaught_numeric_type_error_reports_inconclusive_prefix_issue() -> None:
    value, value_constraint = SymbolicValue.symbolic_int("inconclusive_prefix_type_error")
    state = VMState(
        stack=[SymbolicString.from_const("bad"), value],
        path_constraints=[value_constraint, value.z3_int > 1],
        last_inconclusive_feasibility_len=2,
        pc=9,
    )

    with (
        patch(
            "pysymex._internal.execution.opcodes.common.numeric.ops.errors.hard_theory_witness_model",
            return_value=None,
        ),
        patch(
            "pysymex._internal.execution.opcodes.common.numeric.ops.errors.get_model_result",
        ) as get_model,
    ):
        result = handle_numeric_binary_op(_instr("BINARY_OP", "+"), state, OpcodeDispatcher())

    get_model.assert_not_called()
    assert result.terminal is True
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert result.issues[0].model is None
    assert result.issues[0].confidence == 0.5
    assert "path feasibility inconclusive" in result.issues[0].message
    assert result.degraded_passes == [NUMERIC_TYPE_ERROR_FEASIBILITY_UNKNOWN]


def test_uncaught_numeric_type_error_reports_extended_inconclusive_prefix_issue() -> None:
    value, value_constraint = SymbolicValue.symbolic_int("extended_inconclusive_prefix_type_error")
    state = VMState(
        stack=[SymbolicString.from_const("bad"), value],
        path_constraints=[value_constraint, value.z3_int > 1],
        last_inconclusive_feasibility_len=1,
        pc=9,
    )

    with (
        patch(
            "pysymex._internal.execution.opcodes.common.numeric.ops.errors.hard_theory_witness_model",
            return_value=None,
        ),
        patch(
            "pysymex._internal.execution.opcodes.common.numeric.ops.errors.get_model_result",
        ) as get_model,
    ):
        result = handle_numeric_binary_op(_instr("BINARY_OP", "+"), state, OpcodeDispatcher())

    get_model.assert_not_called()
    assert result.terminal is True
    assert [issue.kind for issue in result.issues] == [IssueKind.TYPE_ERROR]
    assert result.issues[0].model is None
    assert result.issues[0].confidence == 0.5
    assert "path feasibility inconclusive" in result.issues[0].message
    assert result.degraded_passes == [NUMERIC_TYPE_ERROR_FEASIBILITY_UNKNOWN]


def test_concrete_right_shift_preserves_nonnegative_bounds() -> None:
    value = SymbolicValue(
        _name="masked",
        z3_int=z3.Int("masked"),
        is_int=z3.BoolVal(True),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
        affinity_type="int",
        min_val=0,
        max_val=0xFFFFFFFF,
    )

    result = handle_shift_op(VMState(), value, SymbolicValue.from_const(15), ">>")

    shifted = result.new_states[0].stack[-1]
    assert isinstance(shifted, SymbolicValue)
    assert shifted.min_val == 0
    assert shifted.max_val == 0x1FFFF


def test_finite_symbolic_power_interval_beyond_old_cap_stays_exact() -> None:
    exponent, _ = SymbolicValue.symbolic_int("exponent")
    state = VMState(path_constraints=[exponent.z3_int >= 0, exponent.z3_int <= 9])

    result = handle_power_op(state, SymbolicValue.from_const(2), exponent)

    powered = result.new_states[0].stack[-1]
    assert isinstance(powered, SymbolicValue)
    solver = z3.Solver()
    solver.add(exponent.z3_int == 9, powered.z3_int != 512)
    assert solver.check() == z3.unsat
    assert result.degraded_passes == []


def test_low_bits_mask_uses_exact_int_modulo_encoding() -> None:
    value, _ = SymbolicValue.symbolic_int("value")

    result = handle_bitwise_op(VMState(), value, SymbolicValue.from_const(255), "&")

    masked = result.new_states[0].stack[-1]
    assert isinstance(masked, SymbolicValue)
    solver = z3.Solver()
    solver.add(masked.z3_int != value.z3_int % 256)
    assert solver.check() == z3.unsat
    assert "BV2Int" not in str(masked.z3_int)
    assert masked.min_val == 0
    assert masked.max_val == 255
