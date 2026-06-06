from __future__ import annotations

import dis
from pathlib import Path
from typing import cast

from pysymex.core.effects.events import WriteEvent, WriteKind
from pysymex.core.state.record import VMState
from pysymex.core.state.types import BlockInfo
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.frontier import (
    FrontierRuntimeMode,
    FrontierSpillPolicy,
    FrontierSpillStatus,
    FrontierWorkStore,
    state_shadow_digest,
)


def _filesystem_spill_policy(tmp_path: Path) -> FrontierSpillPolicy:
    """Return a filesystem spill policy rooted in the test temp directory."""
    return FrontierSpillPolicy(
        filesystem_spill_enabled=True,
        spill_directory=tmp_path / "frontier-spill",
    )


def _assert_tuple_index_alias(value: object, index: int, expected: object) -> None:
    """Assert that a tuple member is the expected object identity."""
    assert isinstance(value, tuple)
    items = cast("tuple[object, ...]", value)
    assert items[index] is expected


def test_frontier_spill_policy_preserves_spill_safe_exception_roots(
    tmp_path: Path,
) -> None:
    """Spill-safe active exception roots replay through the value table."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    active_exception = b"active-exception"
    pending_exception = ("pending", active_exception)
    state = VMState(
        stack=[active_exception],
        active_exception=active_exception,
        pending_reraise_exception=pending_exception,
        pc=5,
        path_id=22,
    )
    store.add_state(0, state)

    decision = store.request_spill(0, _filesystem_spill_policy(tmp_path))
    selected = store.pop_materialized(0)

    assert decision.can_spill is True
    assert decision.status is FrontierSpillStatus.SPILLED
    assert selected is not None
    assert state_shadow_digest(selected) == state_shadow_digest(state)
    assert selected.active_exception is selected.stack[0]
    _assert_tuple_index_alias(selected.pending_reraise_exception, 1, selected.stack[0])


def test_frontier_spill_policy_preserves_block_stack_and_write_events(
    tmp_path: Path,
) -> None:
    """Primitive execution metadata survives filesystem spill materialization."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    block = BlockInfo("try", 1, 5, 3)
    write_event = WriteEvent(WriteKind.GLOBAL, "value", 7, True, "STORE_GLOBAL")
    state = VMState(
        block_stack=[block],
        write_events=[write_event],
        pc=5,
        path_id=24,
    )
    store.add_state(0, state)

    decision = store.request_spill(0, _filesystem_spill_policy(tmp_path))
    selected = store.pop_materialized(0)

    assert decision.can_spill is True
    assert decision.status is FrontierSpillStatus.SPILLED
    assert selected is not None
    assert state_shadow_digest(selected) == state_shadow_digest(state)
    assert selected.block_stack == [block]
    assert selected.write_events == [write_event]


def test_frontier_spill_policy_preserves_loop_metadata(tmp_path: Path) -> None:
    """Primitive loop counters and iteration keys survive filesystem spill."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    state = VMState(
        loop_iterations={1: 2, (1, 2): 3},
        loop_counters={4: 5},
        pc=5,
        path_id=25,
    )
    store.add_state(0, state)

    decision = store.request_spill(0, _filesystem_spill_policy(tmp_path))
    selected = store.pop_materialized(0)

    assert decision.can_spill is True
    assert decision.status is FrontierSpillStatus.SPILLED
    assert selected is not None
    assert state_shadow_digest(selected) == state_shadow_digest(state)
    assert dict(selected.loop_iterations.items()) == {1: 2, (1, 2): 3}
    assert dict(selected.loop_counters.items()) == {4: 5}


def test_frontier_spill_policy_preserves_current_instructions(tmp_path: Path) -> None:
    """JSON-safe CPython current-instruction lists survive filesystem spill."""
    instructions = list(dis.get_instructions(compile("x = 1\n", "<spill-current>", "exec")))
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    state = VMState(
        current_instructions=cast("list[object]", instructions),
        pc=1,
        path_id=26,
    )
    store.add_state(0, state)

    decision = store.request_spill(0, _filesystem_spill_policy(tmp_path))
    selected = store.pop_materialized(0)

    assert decision.can_spill is True
    assert decision.status is FrontierSpillStatus.SPILLED
    assert selected is not None
    assert state_shadow_digest(selected) == state_shadow_digest(state)
    assert selected.current_instructions == instructions


def test_frontier_spill_policy_rejects_object_heavy_current_instructions(
    tmp_path: Path,
) -> None:
    """Current-instruction lists stay live when they are not exact CPython instructions."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    state = VMState(
        current_instructions=[object()],
        pc=1,
        path_id=27,
    )
    store.add_state(0, state)

    decision = store.request_spill(0, _filesystem_spill_policy(tmp_path))
    selected = store.pop_materialized(0)

    assert decision.can_spill is False
    assert decision.status is FrontierSpillStatus.UNSUPPORTED_PAYLOAD
    assert selected is state


def test_frontier_spill_policy_rejects_symbolic_exception_roots(tmp_path: Path) -> None:
    """Exception roots remain live when replay would require symbolic values."""
    store = FrontierWorkStore(FrontierRuntimeMode.POLAR_CEGIS_RUNTIME)
    symbolic_value, symbolic_constraint = SymbolicValue.symbolic(
        "frontier_spill_symbolic_exception"
    )
    state = VMState(
        active_exception=symbolic_value,
        path_constraints=[symbolic_constraint],
        pending_constraint_count=1,
        pc=5,
        path_id=23,
    )
    store.add_state(0, state)

    decision = store.request_spill(0, _filesystem_spill_policy(tmp_path))
    selected = store.pop_materialized(0)

    assert decision.can_spill is False
    assert decision.status is FrontierSpillStatus.UNSUPPORTED_PAYLOAD
    assert selected is state
    assert selected is not None
    assert selected.active_exception is symbolic_value
