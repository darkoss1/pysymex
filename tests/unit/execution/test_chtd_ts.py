# pyright: reportPrivateUsage=false

import pytest
import z3
from unittest.mock import patch
from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.types import ExecutionConfig
from pysymex.core.state import create_initial_state
from pysymex.execution.strategies.manager import (
    ExplorationStrategy,
    TopologicalThompsonPathManager,
    create_path_manager,
)


@pytest.fixture
def executor() -> SymbolicExecutor:
    config = ExecutionConfig(enable_chtd=True, chtd_max_branch_infos=256)
    ex = SymbolicExecutor(config)
    # Manually initialize the components needed for testing
    ex._worklist = create_path_manager(ExplorationStrategy.ADAPTIVE, cig=ex._interaction_graph)
    return ex


def _manager(executor: SymbolicExecutor) -> TopologicalThompsonPathManager:
    manager = executor._worklist
    assert isinstance(manager, TopologicalThompsonPathManager)
    return manager


def test_ts_cannot_prune(executor: SymbolicExecutor) -> None:
    """Verify that Thompson Sampling scores alone never prune a path."""
    state = create_initial_state()
    manager = _manager(executor)
    # Mock a very low score for all arms
    with patch.object(manager.scheduler.path, "sample", return_value="DFS"):
        # Add state to worklist
        manager.add_state(state)
        assert manager.size() == 1

        # Even with 'bad' heuristics, the state must remain
        next_state = manager.get_next_state()
        assert next_state is state


def test_local_sat_is_not_global_sat(executor: SymbolicExecutor) -> None:
    """Verify that a local SAT result does not mark the full path as feasible."""
    x = z3.Int("x")
    # Full path is UNSAT: x > 0 AND x < 0
    # Bag 1: x > 0 (SAT)
    state = create_initial_state()
    state.add_constraint(x > 0)
    state.add_constraint(x < 0)
    state.pending_constraint_count = 2

    # Mock CHTD to return SAT for the bag
    with patch.object(executor, "_check_chtd_unsat", return_value=None):
        # Full solver should still find it UNSAT
        assert executor._check_path_feasibility(state) is False
        assert executor._paths_pruned == 1


def test_local_unsat_prunes(executor: SymbolicExecutor) -> None:
    """Verify that a certified local UNSAT core correctly prunes the path."""
    x = z3.Int("x")
    state = create_initial_state()
    c1 = x > 0
    c2 = x < 0
    state.add_constraint(c1)
    state.add_constraint(c2)
    state.pending_constraint_count = 2

    # Mock CHTD to find the core {c1, c2}
    # Indices 0 and 1
    with patch.object(executor, "_check_chtd_unsat", return_value=([0, 1], {})):
        assert executor._check_path_feasibility(state) is False
        assert executor._chtd_unsat_hits == 1
        # Registry should now have the core
        assert executor.core_registry.is_feasible({c1.hash(), c2.hash()}) is False


def test_unknown_does_not_prune(executor: SymbolicExecutor) -> None:
    """Verify that solver unknowns or timeouts do not prune paths."""
    state = create_initial_state()
    state.add_constraint(z3.Bool("b"))
    state.pending_constraint_count = 1

    with patch.object(executor.solver, "is_sat", side_effect=Exception("Timeout")):
        # If solver fails/times out, we should NOT prune (unless we have strict timeout pruning,
        # but the rule says "never prune because of timeout" for CHTD).
        # Actually, SymbolicExecutor handles solver exceptions by letting them bubble or marking as unknown.
        # But _check_path_feasibility should be safe.
        try:
            executor._check_path_feasibility(state)
        except Exception:
            pass

        # In our implementation, we only prune if is_sat returns False.
        # Exceptions are not False.
        # Note: if it returns True, it means it didn't prune.
        assert executor._paths_pruned == 0


def test_antichain_behavior(executor: SymbolicExecutor) -> None:
    """Verify that larger redundant cores are discarded from the registry."""
    c1, c2, c3 = 101, 102, 103
    registry = executor.core_registry

    # Add small core
    registry.add_core(frozenset([c1, c2]))
    assert len(registry.cores) == 1

    # Add larger redundant core (superset)
    registry.add_core(frozenset([c1, c2, c3]))
    assert len(registry.cores) == 1
    assert frozenset([c1, c2]) in registry.cores

    # Add smaller core that makes existing core redundant
    registry.add_core(frozenset([c1]))
    assert len(registry.cores) == 1
    assert frozenset([c1]) in registry.cores


def test_frontier_wide_pruning(executor: SymbolicExecutor) -> None:
    """Verify that learning a core prunes all states in the frontier containing it."""
    x = z3.Int("x")
    c1 = x > 0
    c2 = x < 0
    core = frozenset([c1.hash(), c2.hash()])
    manager = _manager(executor)

    # Create 3 states: 2 contain the core, 1 does not
    s1 = create_initial_state()
    s1.add_constraint(c1)
    s1.add_constraint(c2)

    s2 = create_initial_state()
    s2.add_constraint(c1)
    s2.add_constraint(c2)
    s2.add_constraint(z3.Int("y") > 0)

    s3 = create_initial_state()
    s3.add_constraint(c1)
    s3.add_constraint(z3.Int("y") > 0)

    manager.add_state(s1)
    manager.add_state(s2)
    manager.add_state(s3)
    assert manager.size() == 3

    # Learn the core
    executor.core_registry.add_core(core)
    manager.prune_states_containing_core(core)

    assert manager.size() == 1
    # Check that s3 is the only one left
    assert s3 in manager._states.values()
