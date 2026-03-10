"""Tests for parallel exploration module."""

import threading
import time

from pysymex.core.parallel import (
    ConstraintPartitioner,
    ExplorationConfig,
    ExplorationResult,
    ExplorationStrategy,
    ParallelExplorer,
    ParallelSolver,
    PathResult,
    StateMerger,
    StateSignature,
    WorkItem,
    WorkQueue,
)

# =============================================================================
# Mock State for Testing
# =============================================================================


class MockState:
    """Simple mock state for testing."""

    def __init__(self, pc: int = 0, value: int = 0):
        self.pc = pc
        self.value = value
        self.stack = []
        self.locals = {}
        self.constraints = []

    def fork(self, new_pc: int, new_value: int) -> "MockState":
        state = MockState(new_pc, new_value)
        state.stack = list(self.stack)
        state.locals = dict(self.locals)
        return state


# =============================================================================
# ExplorationConfig Tests
# =============================================================================


class TestExplorationConfig:
    """Tests for ExplorationConfig."""

    def test_default_config(self):
        config = ExplorationConfig()
        assert config.max_workers == 4
        assert config.strategy == ExplorationStrategy.DFS
        assert config.max_paths_per_worker == 250

    def test_custom_config(self):
        config = ExplorationConfig(
            max_workers=8,
            strategy=ExplorationStrategy.BFS,
            timeout_seconds=120.0,
        )
        assert config.max_workers == 8
        assert config.strategy == ExplorationStrategy.BFS
        assert config.timeout_seconds == 120.0


# =============================================================================
# WorkItem Tests
# =============================================================================


class TestWorkItem:
    """Tests for WorkItem."""

    def test_create_item(self):
        state = MockState(pc=10)
        item = WorkItem(state=state, priority=5.0, depth=3)

        assert item.state.pc == 10
        assert item.priority == 5.0
        assert item.depth == 3

    def test_priority_ordering(self):
        item1 = WorkItem(state=MockState(), priority=10.0)
        item2 = WorkItem(state=MockState(), priority=5.0)

        # Higher priority should come first (less than)
        assert item1 < item2


# =============================================================================
# PathResult Tests
# =============================================================================


class TestPathResult:
    """Tests for PathResult."""

    def test_create_result(self):
        result = PathResult(path_id=1, status="completed")

        assert result.path_id == 1
        assert result.status == "completed"
        assert result.issues == []
        assert result.coverage == set()

    def test_result_with_issues(self):
        result = PathResult(
            path_id=1,
            status="completed",
            issues=[{"type": "error", "message": "test"}],
        )

        assert len(result.issues) == 1


# =============================================================================
# ExplorationResult Tests
# =============================================================================


class TestExplorationResult:
    """Tests for ExplorationResult."""

    def test_add_path_result(self):
        result = ExplorationResult()

        path_result = PathResult(path_id=1, status="completed")
        result.add_path_result(path_result, worker_id=0)

        assert result.total_paths == 1
        assert result.completed_paths == 1
        assert result.paths_per_worker[0] == 1

    def test_count_timeouts(self):
        result = ExplorationResult()

        path_result = PathResult(path_id=1, status="timeout")
        result.add_path_result(path_result, worker_id=0)

        assert result.timeouts == 1
        assert result.completed_paths == 0


# =============================================================================
# WorkQueue Tests
# =============================================================================


class TestWorkQueue:
    """Tests for WorkQueue."""

    def test_put_get(self):
        queue: WorkQueue[MockState] = WorkQueue()
        state = MockState(pc=5)

        queue.put(state, priority=1.0)
        item = queue.get()

        assert item is not None
        assert item.state.pc == 5

    def test_priority_order(self):
        queue: WorkQueue[MockState] = WorkQueue()

        queue.put(MockState(pc=1), priority=1.0)
        queue.put(MockState(pc=2), priority=10.0)  # Higher priority
        queue.put(MockState(pc=3), priority=5.0)

        # Should get highest priority first
        item1 = queue.get()
        assert item1 is not None
        assert item1.state.pc == 2

    def test_empty(self):
        queue: WorkQueue[MockState] = WorkQueue()
        assert queue.empty()

        queue.put(MockState())
        assert not queue.empty()

        queue.get()
        assert queue.empty()

    def test_size(self):
        queue: WorkQueue[MockState] = WorkQueue()

        assert queue.size() == 0
        queue.put(MockState())
        queue.put(MockState())
        assert queue.size() == 2

    def test_get_timeout(self):
        queue: WorkQueue[MockState] = WorkQueue()

        item = queue.get(timeout=0.01)
        assert item is None


# =============================================================================
# StateSignature Tests
# =============================================================================


class TestStateSignature:
    """Tests for StateSignature."""

    def test_create_signature(self):
        sig = StateSignature(
            pc=10,
            stack_depth=3,
            local_keys=frozenset(["x", "y"]),
            constraint_hash=12345,
        )

        assert sig.pc == 10
        assert sig.stack_depth == 3
        assert "x" in sig.local_keys

    def test_equality(self):
        sig1 = StateSignature(
            pc=10,
            stack_depth=3,
            local_keys=frozenset(["x"]),
            constraint_hash=100,
        )
        sig2 = StateSignature(
            pc=10,
            stack_depth=3,
            local_keys=frozenset(["x"]),
            constraint_hash=200,  # Different hash
        )

        # Different constraint_hash means different states
        assert sig1 != sig2

        # Same constraint_hash means equal
        sig3 = StateSignature(
            pc=10,
            stack_depth=3,
            local_keys=frozenset(["x"]),
            constraint_hash=100,
        )
        assert sig1 == sig3

    def test_hashable(self):
        sig = StateSignature(
            pc=10,
            stack_depth=3,
            local_keys=frozenset(["x"]),
            constraint_hash=100,
        )

        # Should be hashable
        d = {sig: "value"}
        assert d[sig] == "value"


# =============================================================================
# StateMerger Tests
# =============================================================================


class TestStateMerger:
    """Tests for StateMerger."""

    def test_create_merger(self):
        merger = StateMerger[MockState](merge_threshold=5)
        assert merger._merge_threshold == 5

    def test_get_signature(self):
        merger = StateMerger[MockState]()
        state = MockState(pc=10)
        state.stack = [1, 2, 3]
        state.locals = {"x": 1}

        sig = merger.get_signature(state)

        assert sig.pc == 10
        assert sig.stack_depth == 3
        assert "x" in sig.local_keys

    def test_should_merge_not_ready(self):
        merger = StateMerger[MockState](merge_threshold=3)

        result = merger.should_merge(MockState(pc=0))
        assert result is None  # Not enough states yet

    def test_should_merge_ready(self):
        merger = StateMerger[MockState](merge_threshold=2)

        merger.should_merge(MockState(pc=0))
        result = merger.should_merge(MockState(pc=0))

        assert result is not None
        assert len(result) == 2

    def test_merge_states_default(self):
        merger = StateMerger[MockState]()

        states = [MockState(pc=0), MockState(pc=0)]
        merged = merger.merge_states(states)

        assert merged is states[0]

    def test_flush_pending(self):
        merger = StateMerger[MockState](merge_threshold=10)

        merger.should_merge(MockState(pc=0))
        merger.should_merge(MockState(pc=1))

        remaining = merger.flush_pending()
        assert len(remaining) == 2


# =============================================================================
# ParallelExplorer Tests
# =============================================================================


class TestParallelExplorer:
    """Tests for ParallelExplorer."""

    def test_create_explorer(self):
        config = ExplorationConfig(max_workers=2)
        explorer = ParallelExplorer[MockState](config=config)

        assert explorer.config.max_workers == 2

    def test_add_initial_state(self):
        explorer = ParallelExplorer[MockState]()
        explorer.add_initial_state(MockState(pc=0))

        assert not explorer._work_queue.empty()

    def test_simple_exploration(self):
        config = ExplorationConfig(
            max_workers=1,
            max_paths_per_worker=5,
            timeout_seconds=1.0,
        )
        explorer = ParallelExplorer[MockState](config=config)

        # Simple step function that terminates
        step_count = [0]

        def step(state: MockState) -> list[MockState]:
            step_count[0] += 1
            if state.pc >= 3:
                return []  # Terminal state
            return [state.fork(state.pc + 1, 0)]

        explorer.set_step_function(step)
        explorer.add_initial_state(MockState(pc=0))

        result = explorer.explore()

        assert result.total_paths > 0

    def test_stop_exploration(self):
        config = ExplorationConfig(max_workers=1, timeout_seconds=10.0)
        explorer = ParallelExplorer[MockState](config=config)

        def infinite_step(state: MockState) -> list[MockState]:
            return [state.fork(state.pc + 1, 0)]

        explorer.set_step_function(infinite_step)
        explorer.add_initial_state(MockState(pc=0))

        # Stop after a short delay
        def stop_after_delay():
            time.sleep(0.1)
            explorer.stop()

        threading.Thread(target=stop_after_delay).start()

        result = explorer.explore()
        assert result.total_paths > 0


# =============================================================================
# ConstraintPartitioner Tests
# =============================================================================


class TestConstraintPartitioner:
    """Tests for ConstraintPartitioner."""

    def test_create_partitioner(self):
        partitioner = ConstraintPartitioner()
        assert partitioner is not None

    def test_partition_empty(self):
        partitioner = ConstraintPartitioner()
        result = partitioner.partition([])
        assert result == []

    def test_partition_single(self):
        import z3

        partitioner = ConstraintPartitioner()

        x = z3.Int("x")
        constraints = [x > 0]

        result = partitioner.partition(constraints)
        assert len(result) == 1
        assert constraints[0] in result[0]

    def test_partition_independent(self):
        import z3

        partitioner = ConstraintPartitioner()

        x = z3.Int("x")
        y = z3.Int("y")

        # Two independent constraints
        constraints = [x > 0, y < 10]

        result = partitioner.partition(constraints)

        # Should be in separate partitions
        assert len(result) == 2

    def test_partition_dependent(self):
        import z3

        partitioner = ConstraintPartitioner()

        x = z3.Int("x")

        # Two dependent constraints (share x)
        constraints = [x > 0, x < 10]

        result = partitioner.partition(constraints)

        # Should be in same partition
        assert len(result) == 1
        assert len(result[0]) == 2


# =============================================================================
# ParallelSolver Tests
# =============================================================================


class TestParallelSolver:
    """Tests for ParallelSolver."""

    def test_create_solver(self):
        solver = ParallelSolver(max_workers=2)
        assert solver.max_workers == 2

    def test_check_empty(self):
        solver = ParallelSolver()
        is_sat, model = solver.check([])
        assert is_sat is True

    def test_check_satisfiable(self):
        import z3

        solver = ParallelSolver()

        x = z3.Int("x")
        constraints = [x > 0, x < 10]

        is_sat, model = solver.check(constraints)

        assert is_sat is True
        assert model is not None

    def test_check_unsatisfiable(self):
        import z3

        solver = ParallelSolver()

        x = z3.Int("x")
        constraints = [x > 10, x < 5]  # Impossible

        is_sat, model = solver.check(constraints)

        assert is_sat is False
        assert model is None
