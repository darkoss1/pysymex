from __future__ import annotations

import functools
import operator
import pickle
import random
import statistics

import pytest
import z3

import pysymex._internal.execution.calls.model.dispatch as models
from pysymex._internal.core.effects.events import WriteKind
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.engine.results import SolverResult
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.opcodes.common.satisfiability import PathSatisfiability
from pysymex._internal.models.stdlib.registry import extended_stdlib_registry


def test_function_model_path_is_sat_uses_solver_for_long_nontrivial_contradictions() -> None:
    x = z3.Int("x")
    padding = [z3.Int(f"p{i}") == i for i in range(12)]

    assert PathSatisfiability.is_sat([*padding, x > 0, x < 0]) is False


def test_function_model_path_is_sat_keeps_satisfiable_long_paths_feasible() -> None:
    x = z3.Int("x")
    padding = [z3.Int(f"q{i}") == i for i in range(12)]

    assert PathSatisfiability.is_sat([*padding, x > 0, x < 5]) is True


def test_model_side_effect_issue_feasibility_rejects_solver_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unknown_result(constraints: list[z3.BoolRef]) -> SolverResult:
        assert constraints
        return SolverResult.unknown()

    monkeypatch.setattr(models, "check_sat_result", unknown_result)

    assert models.reportable_issue_path_is_sat([z3.BoolVal(True)]) is False


def test_model_side_effect_issue_feasibility_accepts_verified_witness_before_solver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = z3.String("model_side_effect_witness_text_str")
    parsed = z3.Int("int_model_side_effect_witness_text_int")

    def fail_solver(_constraints: list[z3.BoolRef]) -> SolverResult:
        raise AssertionError("verified concrete witness should avoid the solver")

    monkeypatch.setattr(models, "check_sat_result", fail_solver)

    assert (
        models.reportable_issue_path_is_sat(
            [
                z3.InRe(text, z3.Plus(z3.Re("0"))),
                parsed == z3.StrToInt(text),
                parsed == 0,
            ]
        )
        is True
    )


def test_uncaught_model_raised_exception_is_terminal_without_successor() -> None:
    result = models.apply_model(VMState(pc=7), "int", ["not-an-int"], {})

    assert result is not None
    assert result.terminal is True
    assert not result.new_states
    assert [issue.kind for issue in result.issues] == [IssueKind.VALUE_ERROR]


def test_model_dispatch_resolves_random_module_bound_shuffle() -> None:
    xs, list_constraint = SymbolicList.symbolic("xs")
    state = VMState(local_vars={"xs": xs}, pc=11).add_constraint(list_constraint)

    result = models.apply_model(state, random.shuffle, [xs], {})

    assert result is not None
    assert result.terminal is False
    assert result.issues == []
    assert len(result.new_states) == 1

    next_state = result.new_states[0]
    assert isinstance(next_state.stack[-1], SymbolicNoneType)
    assert [
        (event.kind, event.location, event.precise, event.source)
        for event in next_state.write_events
    ] == [(WriteKind.ITEM, "xs[*]", True, "model.mutates_arg")]


def test_model_dispatch_resolves_random_builtin_instance_method() -> None:
    result = models.apply_model(VMState(pc=13), random.random, [], {})

    assert result is not None
    assert result.terminal is False
    assert result.issues == []
    assert len(result.new_states) == 1
    assert isinstance(result.new_states[0].stack[-1], SymbolicValue)


def test_model_dispatch_resolves_registered_module_without_dispatch_allowlist() -> None:
    result = models.apply_model(VMState(pc=15), statistics.mean, [[1, 2, 3]], {})

    assert result is not None
    assert result.terminal is False
    assert len(result.new_states) == 1
    assert isinstance(result.new_states[0].stack[-1], SymbolicValue)


@pytest.mark.parametrize(
    ("func", "expected_qualname"),
    [
        (functools.reduce, "functools.reduce"),
        (operator.add, "operator.add"),
        (pickle.loads, "pickle.loads"),
    ],
)
def test_model_dispatch_resolves_c_accelerator_callable(
    func: object, expected_qualname: str
) -> None:
    model = extended_stdlib_registry.resolve_callable(func)

    assert model is not None
    assert model.qualname == expected_qualname


def test_model_dispatch_rejects_user_function_with_stdlib_model_name() -> None:
    def mean(values: list[int]) -> int:
        return values[0]

    assert models.apply_model(VMState(pc=16), mean, [[1, 2, 3]], {}) is None


def test_model_dispatch_does_not_bare_name_match_public_stdlib_modules() -> None:
    def mean(values: list[int]) -> int:
        return values[0]

    mean.__module__ = "random"

    assert models.apply_model(VMState(pc=17), mean, [[1, 2, 3]], {}) is None


def test_model_dispatch_propagates_builtin_degradation_events() -> None:
    """Typed model limitations make the execution result explicitly degraded."""
    result = models.apply_model(VMState(pc=17), breakpoint, [], {})

    assert result is not None
    assert result.terminal is False
    assert result.degraded_passes == ["builtin_breakpoint_hook_unsupported"]
    assert len(result.fallback_events) == 1
    event = result.fallback_events[0]
    assert event.label == "builtin_breakpoint_hook_unsupported"
    assert event.owner == "pysymex._internal.models.builtins.runtime.dynamic_io.BreakpointModel"
    assert event.pc == 17
    assert event.soundness == "unsupported"
