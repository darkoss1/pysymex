"""Tests for invocation-scoped model capabilities."""

from __future__ import annotations

from collections.abc import Iterable

import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.solver.feasibility_context import (
    bind_path_feasibility_oracle,
    path_may_be_feasible,
)
from pysymex._internal.models.contracts.capabilities import (
    bind_model_invoker,
    invoke_registered_model,
)
from pysymex._internal.models.contracts.results import ModelResult
from pysymex._internal.typing.protocols import StackValue


def test_unbound_feasibility_is_conservative() -> None:
    assert path_may_be_feasible([z3.BoolVal(False)]) is True


def test_bound_feasibility_delegates_and_restores_default() -> None:
    observed: list[tuple[list[z3.BoolRef], int | None]] = []

    def oracle(
        constraints: Iterable[z3.BoolRef],
        *,
        known_sat_prefix_len: int | None = None,
    ) -> bool:
        observed.append((list(constraints), known_sat_prefix_len))
        return False

    constraint = z3.Bool("model_constraint")
    with bind_path_feasibility_oracle(oracle):
        assert path_may_be_feasible([constraint], known_sat_prefix_len=3) is False

    assert observed == [([constraint], 3)]
    assert path_may_be_feasible([z3.BoolVal(False)]) is True


def test_bound_model_invoker_delegates_and_restores_default() -> None:
    expected_state = VMState()

    def invoke(
        name: str,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult | None:
        assert name == "list.__iadd__"
        assert args == [1, 2]
        assert kwargs == {}
        assert state is expected_state
        return ModelResult(value=3)

    with bind_model_invoker(invoke):
        result = invoke_registered_model("list.__iadd__", [1, 2], {}, expected_state)

    assert result is not None and result.value == 3
    assert invoke_registered_model("list.__iadd__", [1, 2], {}, expected_state) is None
