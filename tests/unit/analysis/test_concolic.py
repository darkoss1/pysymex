import z3
from unittest.mock import patch
from pysymex.analysis.concolic import (
    ConcreteInput,
    BranchRecord,
    ExecutionTrace,
    ConcolicExecutor,
    ConcolicResult,
    GenerationalSearch,
)


class TestConcreteInput:
    """Test suite for pysymex.analysis.concolic.ConcreteInput."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        inp1 = ConcreteInput(values={"x": 5})
        inp2 = ConcreteInput(values={"x": 5})
        assert inp1 == inp2
        assert hash(inp1) == hash(inp2)


class TestBranchRecord:
    """Test suite for pysymex.analysis.concolic.BranchRecord."""

    def test_negate(self) -> None:
        """Test negate behavior."""
        cond = z3.BoolVal(True)
        rec_taken = BranchRecord(pc=0, condition=cond, taken=True)
        assert z3.is_expr(rec_taken.negate())

        rec_not_taken = BranchRecord(pc=0, condition=cond, taken=False)
        assert rec_not_taken.negate() is cond


class TestExecutionTrace:
    """Test suite for pysymex.analysis.concolic.ExecutionTrace."""

    def test_path_condition(self) -> None:
        """Test path_condition behavior."""
        cond = z3.BoolVal(True)
        rec = BranchRecord(pc=0, condition=cond, taken=True)
        inp = ConcreteInput(values={})
        trace = ExecutionTrace(input=inp, branches=[rec])
        assert len(trace.path_condition()) == 1

    def test_path_hash(self) -> None:
        """Test path_hash behavior."""
        inp = ConcreteInput(values={})
        trace = ExecutionTrace(
            input=inp, branches=[BranchRecord(pc=0, condition=z3.BoolVal(True), taken=True)]
        )
        assert isinstance(trace.path_hash(), int)


class TestConcolicExecutor:
    """Test suite for pysymex.analysis.concolic.ConcolicExecutor."""

    def test_execute(self) -> None:
        """Test execute behavior."""

        def dummy_func(x: int) -> None:
            if x > 0:
                pass

        exec = ConcolicExecutor(max_iterations=1, max_time_seconds=5.0)

        with (
            patch.object(exec, "_execute_concrete") as mock_exec,
            patch.object(exec, "_expand_worklist"),
        ):
            mock_trace = ExecutionTrace(input=ConcreteInput(values={"x": 0}))
            mock_exec.return_value = mock_trace

            res = exec.execute(dummy_func, initial_inputs={"x": 0}, symbolic_types={"x": "int"})
            assert isinstance(res, ConcolicResult)
            assert res.num_paths > 0


class TestConcolicResult:
    """Test suite for pysymex.analysis.concolic.ConcolicResult."""

    def test_num_paths(self) -> None:
        """Test num_paths behavior."""
        res = ConcolicResult(traces=[], coverage=set(), iterations=0, time_seconds=0.0)
        assert res.num_paths == 0

    def test_coverage_percentage(self) -> None:
        """Test coverage_percentage behavior."""
        res = ConcolicResult(traces=[], coverage={1, 2}, iterations=0, time_seconds=0.0)
        assert res.coverage_percentage == 2

    def test_get_failing_inputs(self) -> None:
        """Test get_failing_inputs behavior."""
        inp = ConcreteInput(values={"x": 5})
        trace = ExecutionTrace(input=inp, exception=RuntimeError("fail"))
        res = ConcolicResult(traces=[trace], coverage=set(), iterations=0, time_seconds=0.0)
        assert len(res.get_failing_inputs()) == 1

    def test_format_summary(self) -> None:
        """Test format_summary behavior."""
        res = ConcolicResult(traces=[], coverage=set(), iterations=0, time_seconds=0.0)
        assert "Concolic Execution Summary" in res.format_summary()


class TestGenerationalSearch:
    """Test suite for pysymex.analysis.concolic.GenerationalSearch."""

    def test_search(self) -> None:
        """Test search behavior."""
        searcher = GenerationalSearch(max_generations=1)

        def dummy_func(x: int) -> None:
            pass

        with patch("pysymex.analysis.concolic.ConcolicExecutor") as mock_exec_class:
            mock_res = ConcolicResult(traces=[], coverage=set(), iterations=0, time_seconds=0.0)
            mock_exec_class.return_value.execute.return_value = mock_res
            traces = searcher.search(dummy_func, {"x": 5}, {"x": "int"})
            assert isinstance(traces, list)
