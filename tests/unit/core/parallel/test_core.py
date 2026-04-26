import pysymex.core.parallel.core
import pysymex.core.parallel.types
import z3


class _DummyState:
    def __init__(self, pc: int = 0) -> None:
        self.pc = pc
        self.stack: list[int] = []
        self.locals: dict[str, object] = {}
        self.constraints: list[z3.BoolRef] = []


def _no_step(state: _DummyState) -> list[_DummyState]:
    return []


def _no_issues(state: _DummyState) -> list[dict[str, object]]:
    return []


class TestWorkQueue:
    """Test suite for pysymex.core.parallel.core.WorkQueue."""

    def test_put(self) -> None:
        """Scenario: put one item; expected returned path id starts at zero."""
        q: pysymex.core.parallel.core.WorkQueue[int] = pysymex.core.parallel.core.WorkQueue()
        assert q.put(1) == 0

    def test_get(self) -> None:
        """Scenario: put then get; expected retrieved work item state matches inserted value."""
        q: pysymex.core.parallel.core.WorkQueue[int] = pysymex.core.parallel.core.WorkQueue()
        _ = q.put(7)
        item = q.get(timeout=0.01)
        assert item is not None and item.state == 7

    def test_empty(self) -> None:
        """Scenario: fresh queue; expected empty true."""
        q: pysymex.core.parallel.core.WorkQueue[int] = pysymex.core.parallel.core.WorkQueue()
        assert q.empty() is True

    def test_size(self) -> None:
        """Scenario: two insertions; expected queue size two."""
        q: pysymex.core.parallel.core.WorkQueue[int] = pysymex.core.parallel.core.WorkQueue()
        _ = q.put(1)
        _ = q.put(2)
        assert q.size() == 2

    def test_clear(self) -> None:
        """Scenario: queue has items then clear; expected empty queue."""
        q: pysymex.core.parallel.core.WorkQueue[int] = pysymex.core.parallel.core.WorkQueue()
        _ = q.put(1)
        q.clear()
        assert q.empty() is True


class TestStateMerger:
    """Test suite for pysymex.core.parallel.core.StateMerger."""

    def test_get_signature(self) -> None:
        """Scenario: compute signature from dummy state; expected matching program counter."""
        merger: pysymex.core.parallel.core.StateMerger[_DummyState] = (
            pysymex.core.parallel.core.StateMerger()
        )
        sig = merger.get_signature(_DummyState(pc=3))
        assert sig.pc == 3

    def test_should_merge(self) -> None:
        """Scenario: threshold one; expected immediate merge candidate list."""
        merger: pysymex.core.parallel.core.StateMerger[_DummyState] = (
            pysymex.core.parallel.core.StateMerger(merge_threshold=1)
        )
        candidates = merger.should_merge(_DummyState())
        assert candidates is not None

    def test_merge_states(self) -> None:
        """Scenario: default merge implementation; expected first state returned."""
        merger: pysymex.core.parallel.core.StateMerger[_DummyState] = (
            pysymex.core.parallel.core.StateMerger()
        )
        a = _DummyState(pc=1)
        b = _DummyState(pc=2)
        assert merger.merge_states([a, b]) is a

    def test_get_merge_count(self) -> None:
        """Scenario: merge invoked once; expected merge count one."""
        merger: pysymex.core.parallel.core.StateMerger[_DummyState] = (
            pysymex.core.parallel.core.StateMerger()
        )
        _ = merger.merge_states([_DummyState(), _DummyState()])
        assert merger.get_merge_count() == 1

    def test_flush_pending(self) -> None:
        """Scenario: pending state exists; expected flush returns and clears pending list."""
        merger: pysymex.core.parallel.core.StateMerger[_DummyState] = (
            pysymex.core.parallel.core.StateMerger(merge_threshold=2)
        )
        _ = merger.should_merge(_DummyState())
        assert len(merger.flush_pending()) == 1


class TestParallelExplorer:
    """Test suite for pysymex.core.parallel.core.ParallelExplorer."""

    def test_set_step_function(self) -> None:
        """Scenario: set step function callback; expected internal callback assignment."""
        ex: pysymex.core.parallel.core.ParallelExplorer[_DummyState] = (
            pysymex.core.parallel.core.ParallelExplorer()
        )

        def step_fn(state: _DummyState) -> list[_DummyState]:
            return []

        ex.set_step_function(step_fn)
        ex.add_initial_state(_DummyState())
        result = ex.explore()
        assert isinstance(result, pysymex.core.parallel.types.ExplorationResult)

    def test_set_check_function(self) -> None:
        """Scenario: set check function callback; expected internal callback assignment."""
        ex: pysymex.core.parallel.core.ParallelExplorer[_DummyState] = (
            pysymex.core.parallel.core.ParallelExplorer(step_function=_no_step)
        )

        def check_fn(state: _DummyState) -> list[dict[str, object]]:
            return []

        ex.set_check_function(check_fn)
        ex.add_initial_state(_DummyState())
        result = ex.explore()
        assert result.total_paths >= 1

    def test_add_initial_state(self) -> None:
        """Scenario: add one initial state; expected queue size increments."""
        ex: pysymex.core.parallel.core.ParallelExplorer[_DummyState] = (
            pysymex.core.parallel.core.ParallelExplorer(step_function=_no_step)
        )
        ex.add_initial_state(_DummyState())
        result = ex.explore()
        assert result.total_paths >= 1

    def test_explore(self) -> None:
        """Scenario: trivial explorer with no successors; expected at least one completed path."""
        ex: pysymex.core.parallel.core.ParallelExplorer[_DummyState] = (
            pysymex.core.parallel.core.ParallelExplorer(
                step_function=_no_step,
                check_function=_no_issues,
            )
        )
        ex.add_initial_state(_DummyState(pc=5))
        result = ex.explore()
        assert result.completed_paths >= 1

    def test_stop(self) -> None:
        """Scenario: stop called; expected stop event set."""
        ex: pysymex.core.parallel.core.ParallelExplorer[_DummyState] = (
            pysymex.core.parallel.core.ParallelExplorer()
        )
        ex.stop()
        assert ex.get_coverage() == set()

    def test_get_coverage(self) -> None:
        """Scenario: coverage set has one PC; expected same PC returned by getter."""
        ex: pysymex.core.parallel.core.ParallelExplorer[_DummyState] = (
            pysymex.core.parallel.core.ParallelExplorer(
                step_function=lambda state: [],
                check_function=lambda state: [],
            )
        )
        ex.add_initial_state(_DummyState(pc=9))
        _ = ex.explore()
        assert 9 in ex.get_coverage()


class TestConstraintPartitioner:
    """Test suite for pysymex.core.parallel.core.ConstraintPartitioner."""

    def test_partition(self) -> None:
        """Scenario: independent x/y constraints; expected two partitions."""
        part = pysymex.core.parallel.core.ConstraintPartitioner()
        x = z3.Int("x")
        y = z3.Int("y")
        partitions = part.partition([x > 0, y > 0])
        assert len(partitions) == 2


class TestParallelSolver:
    """Test suite for pysymex.core.parallel.core.ParallelSolver."""

    def test_check(self) -> None:
        """Scenario: satisfiable constraint set; expected SAT status true."""
        solver = pysymex.core.parallel.core.ParallelSolver(max_workers=2)
        x = z3.Int("x")
        is_sat, _model = solver.check([x > 0, x < 2])
        assert is_sat is True


class TestProcessParallelVerifier:
    """Test suite for pysymex.core.parallel.core.ProcessParallelVerifier."""

    def test_verify_files(self) -> None:
        """Scenario: empty file list verification; expected empty result mapping."""
        verifier = pysymex.core.parallel.core.ProcessParallelVerifier(max_workers=1)
        assert verifier.verify_files([]) == {}
