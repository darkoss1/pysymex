import pysymex.core.parallel.types

class TestExplorationStrategy:
    """Test suite for pysymex.core.parallel.types.ExplorationStrategy."""
    def test_initialization(self) -> None:
        """Scenario: enum values expose strategy members; expected ADAPTIVE name."""
        assert pysymex.core.parallel.types.ExplorationStrategy.ADAPTIVE.name == "ADAPTIVE"


class TestExplorationConfig:
    """Test suite for pysymex.core.parallel.types.ExplorationConfig."""
    def test_initialization(self) -> None:
        """Scenario: default config construction; expected default worker count."""
        cfg = pysymex.core.parallel.types.ExplorationConfig()
        assert cfg.max_workers == 4


class TestWorkItem:
    """Test suite for pysymex.core.parallel.types.WorkItem."""
    def test_initialization(self) -> None:
        """Scenario: work item stores state and priority."""
        item = pysymex.core.parallel.types.WorkItem(state="s", priority=1.5)
        assert (item.state, item.priority) == ("s", 1.5)


class TestPathResult:
    """Test suite for pysymex.core.parallel.types.PathResult."""
    def test_initialization(self) -> None:
        """Scenario: path result construction; expected path id and status retained."""
        result = pysymex.core.parallel.types.PathResult(path_id=1, status="completed")
        assert (result.path_id, result.status) == (1, "completed")


class TestExplorationResult:
    """Test suite for pysymex.core.parallel.types.ExplorationResult."""
    def test_add_path_result(self) -> None:
        """Scenario: add completed path result; expected totals and worker count increment."""
        agg = pysymex.core.parallel.types.ExplorationResult()
        path = pysymex.core.parallel.types.PathResult(path_id=2, status="completed")
        agg.add_path_result(path, worker_id=7)
        assert (agg.total_paths, agg.completed_paths, agg.paths_per_worker[7]) == (1, 1, 1)


class TestStateSignature:
    """Test suite for pysymex.core.parallel.types.StateSignature."""
    def test_initialization(self) -> None:
        """Scenario: state signature object stores structural identifiers."""
        sig = pysymex.core.parallel.types.StateSignature(1, 2, frozenset({"x"}), 99)
        assert sig.constraint_hash == 99
