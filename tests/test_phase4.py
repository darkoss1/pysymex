"""Tests for Phase 4 advanced analysis features."""

import pytest
import z3

from pysymex.analysis import (
    BranchRecord,
    CallGraph,
    CallSite,
    # Inter-procedural
    CallType,
    ConcolicExecutor,
    # Concolic
    ConcreteInput,
    DetectorRegistry,
    ExecutionTrace,
    FunctionSummary,
    GenerationalSearch,
    InfiniteLoopDetector,
    IntegerOverflowDetector,
    InterproceduralAnalyzer,
    # Advanced detectors
    NullDereferenceDetector,
    TaintAnalyzer,
    TaintedValue,
    TaintFlow,
    TaintLabel,
    TaintPolicy,
    TaintSink,
    # Taint analysis
    TaintSource,
    TaintTracker,
    UnreachableCodeDetector,
    register_advanced_detectors,
)

# =============================================================================
# Advanced Detectors Tests
# =============================================================================


class TestAdvancedDetectors:
    """Tests for advanced bug detectors."""

    def test_register_advanced_detectors(self):
        """Test registering advanced detectors."""
        registry = DetectorRegistry()
        register_advanced_detectors(registry)

        # Should have registered multiple detectors
        assert len(registry._detectors) >= 4

    def test_null_dereference_detector(self):
        """Test NullDereferenceDetector instantiation."""
        detector = NullDereferenceDetector()
        assert detector.name == "null-dereference"
        assert "None" in detector.description

    def test_infinite_loop_detector(self):
        """Test InfiniteLoopDetector instantiation."""
        detector = InfiniteLoopDetector()
        assert detector.name == "infinite-loop"
        assert detector._max_iterations == 1000

    def test_integer_overflow_detector(self):
        """Test IntegerOverflowDetector with custom bit width."""
        detector = IntegerOverflowDetector(bits=32)
        assert detector.bits == 32
        assert detector.max_val == 2**31 - 1
        assert detector.min_val == -(2**31)

    def test_unreachable_code_detector(self):
        """Test UnreachableCodeDetector instantiation."""
        detector = UnreachableCodeDetector()
        assert detector.name == "unreachable-code"


# =============================================================================
# Inter-Procedural Analysis Tests
# =============================================================================


class TestInterproceduralAnalysis:
    """Tests for inter-procedural analysis."""

    def test_call_type_enum(self):
        """Test CallType enum values."""
        # auto() generates integers, not strings
        assert CallType.DIRECT is not None
        assert CallType.INDIRECT is not None
        assert CallType.BUILTIN is not None

    def test_call_site_creation(self):
        """Test CallSite dataclass."""
        site = CallSite(
            caller="main",
            callee="helper",
            call_type=CallType.DIRECT,
            pc=100,
            line_number=10,
        )
        assert site.caller == "main"
        assert site.callee == "helper"
        assert site.call_type == CallType.DIRECT
        assert site.line_number == 10
        assert site.pc == 100

    def test_function_summary_creation(self):
        """Test FunctionSummary dataclass."""
        x = z3.Int("x")
        summary = FunctionSummary(
            name="safe_divide",
            parameters=["x", "y"],
            return_expr=x + 1,
            preconditions=[x > 0],
            is_pure=True,
        )
        assert summary.name == "safe_divide"
        assert summary.is_pure
        assert len(summary.preconditions) == 1

    def test_call_graph_basic(self):
        """Test CallGraph construction."""
        graph = CallGraph()

        graph.add_function("main")
        graph.add_function("helper")

        # add_call expects (caller, callee, CallSite)
        site = CallSite(caller="main", callee="helper", call_type=CallType.DIRECT, pc=10)
        graph.add_call("main", "helper", site)

        assert "main" in graph._nodes
        assert "helper" in graph._nodes

    def test_call_graph_callees(self):
        """Test getting callees of a function."""
        graph = CallGraph()
        graph.add_function("main")
        graph.add_function("foo")
        graph.add_function("bar")

        site1 = CallSite(caller="main", callee="foo", call_type=CallType.DIRECT, pc=10)
        site2 = CallSite(caller="main", callee="bar", call_type=CallType.DIRECT, pc=20)
        graph.add_call("main", "foo", site1)
        graph.add_call("main", "bar", site2)

        callees = graph.get_callees("main")
        assert "foo" in callees
        assert "bar" in callees

    def test_call_graph_dot_export(self):
        """Test DOT format export."""
        graph = CallGraph()
        graph.add_function("main")
        graph.add_function("helper")

        site = CallSite(caller="main", callee="helper", call_type=CallType.DIRECT, pc=10)
        graph.add_call("main", "helper", site)

        dot = graph.to_dot()
        assert "digraph" in dot
        assert "main" in dot
        assert "helper" in dot

    def test_interprocedural_analyzer_creation(self):
        """Test InterproceduralAnalyzer instantiation."""
        analyzer = InterproceduralAnalyzer(max_inline_depth=3)
        assert analyzer.max_inline_depth == 3
        assert analyzer.call_graph is not None


# =============================================================================
# Taint Analysis Tests
# =============================================================================


class TestTaintAnalysis:
    """Tests for taint analysis."""

    def test_taint_source_enum(self):
        """Test TaintSource enum values."""
        # auto() generates integers, check enum members exist
        assert TaintSource.USER_INPUT is not None
        assert TaintSource.NETWORK is not None
        assert TaintSource.FILE_READ is not None
        assert TaintSource.DATABASE is not None

    def test_taint_sink_enum(self):
        """Test TaintSink enum values."""
        # auto() generates integers
        assert TaintSink.SQL_QUERY is not None
        assert TaintSink.COMMAND_EXEC is not None
        assert TaintSink.FILE_PATH is not None
        assert TaintSink.EVAL is not None

    def test_taint_label_creation(self):
        """Test TaintLabel dataclass."""
        label = TaintLabel(
            source=TaintSource.USER_INPUT,
            origin="user_data",
            line_number=5,
        )
        assert label.source == TaintSource.USER_INPUT
        assert label.origin == "user_data"

    def test_tainted_value_creation(self):
        """Test TaintedValue creation."""
        label = TaintLabel(
            source=TaintSource.USER_INPUT,
            origin="input",
        )
        tainted = TaintedValue(
            value="test",
            labels=frozenset({label}),
        )
        assert tainted.value == "test"
        assert len(tainted.labels) == 1
        assert tainted.is_tainted()

    def test_tainted_value_clean(self):
        """Test TaintedValue.clean()."""
        clean = TaintedValue.clean("safe")
        assert clean.value == "safe"
        assert not clean.is_tainted()

    def test_tainted_value_factory(self):
        """Test TaintedValue.tainted() factory."""
        tainted = TaintedValue.tainted(
            "danger",
            TaintSource.USER_INPUT,
            "input",
            10,
        )
        assert tainted.is_tainted()
        assert tainted.value == "danger"

    def test_taint_policy_default_rules(self):
        """Test TaintPolicy default dangerous flows."""
        policy = TaintPolicy()

        # User input to SQL should be dangerous
        assert policy.is_dangerous(TaintSource.USER_INPUT, TaintSink.SQL_QUERY)

        # User input to command should be dangerous
        assert policy.is_dangerous(TaintSource.USER_INPUT, TaintSink.COMMAND_EXEC)

    def test_taint_tracker_basic(self):
        """Test TaintTracker operations."""
        tracker = TaintTracker()

        # mark_tainted takes (value, source, origin, line)
        value = "test_value"
        tainted = tracker.mark_tainted(value, TaintSource.USER_INPUT, "x", 5)

        assert tracker.is_tainted(value)
        assert tainted.is_tainted()

    def test_taint_tracker_propagation(self):
        """Test taint propagation."""
        tracker = TaintTracker()

        original = "original"
        tracker.mark_tainted(original, TaintSource.USER_INPUT, "x")

        # Propagate to a new value
        new_value = "new_value"
        propagated = tracker.propagate_taint(new_value, original)

        assert tracker.is_tainted(new_value)
        assert propagated.is_tainted()

    def test_taint_flow_creation(self):
        """Test TaintFlow dataclass."""
        label = TaintLabel(TaintSource.USER_INPUT, "input", 10)
        flow = TaintFlow(
            source_labels=frozenset({label}),
            sink=TaintSink.SQL_QUERY,
            sink_location="execute_query",
            sink_line=20,
            path=["input", "data", "query"],
        )
        assert flow.sink == TaintSink.SQL_QUERY
        assert len(flow.path) == 3

    def test_taint_analyzer_creation(self):
        """Test TaintAnalyzer instantiation."""
        analyzer = TaintAnalyzer()
        # Just check it instantiates without error
        assert analyzer is not None


# =============================================================================
# Concolic Execution Tests
# =============================================================================


class TestConcolicExecution:
    """Tests for concolic execution."""

    def test_concrete_input_creation(self):
        """Test ConcreteInput dataclass."""
        inputs = ConcreteInput(
            values={"x": 42, "y": 10},
            generation=0,
        )
        assert inputs.values["x"] == 42
        assert inputs.generation == 0

    def test_concrete_input_hash(self):
        """Test ConcreteInput hashing."""
        input1 = ConcreteInput(values={"x": 1, "y": 2})
        input2 = ConcreteInput(values={"x": 1, "y": 2})
        input3 = ConcreteInput(values={"x": 3, "y": 4})

        assert hash(input1) == hash(input2)
        assert input1 == input2
        assert input1 != input3

    def test_branch_record_creation(self):
        """Test BranchRecord dataclass."""
        condition = z3.Int("x") > 0
        record = BranchRecord(
            pc=10,
            condition=condition,
            taken=True,
        )
        assert record.pc == 10
        assert record.taken

    def test_branch_record_negate(self):
        """Test negating a branch condition."""
        x = z3.Int("x")
        record = BranchRecord(
            pc=10,
            condition=x > 0,
            taken=True,
        )

        negated = record.negate()
        # When taken=True, negate() returns Not(condition)
        solver = z3.Solver()
        solver.add(negated)
        solver.add(x == 0)
        assert solver.check() == z3.sat

    def test_execution_trace_basic(self):
        """Test ExecutionTrace operations."""
        input_data = ConcreteInput(values={"x": 5})
        trace = ExecutionTrace(input=input_data)

        condition = z3.Int("x") > 0
        trace.branches.append(BranchRecord(pc=10, condition=condition, taken=True))

        assert len(trace.branches) == 1
        assert trace.branches[0].pc == 10
        assert trace.branches[0].taken

    def test_execution_trace_path_condition(self):
        """Test getting path constraint from trace."""
        input_data = ConcreteInput(values={"x": 50})
        trace = ExecutionTrace(input=input_data)

        x = z3.Int("x")
        trace.branches.append(BranchRecord(pc=10, condition=x > 0, taken=True))
        trace.branches.append(BranchRecord(pc=20, condition=x < 100, taken=True))

        conditions = trace.path_condition()
        # Should be list of both conditions
        assert len(conditions) == 2

        solver = z3.Solver()
        solver.add(conditions)
        assert solver.check() == z3.sat

    def test_execution_trace_path_hash(self):
        """Test path hash for deduplication."""
        input_data = ConcreteInput(values={"x": 5})
        trace1 = ExecutionTrace(input=input_data)
        trace2 = ExecutionTrace(input=input_data)

        x = z3.Int("x")
        trace1.branches.append(BranchRecord(pc=10, condition=x > 0, taken=True))
        trace2.branches.append(BranchRecord(pc=10, condition=x > 0, taken=True))

        assert trace1.path_hash() == trace2.path_hash()

    def test_concolic_executor_creation(self):
        """Test ConcolicExecutor instantiation."""
        executor = ConcolicExecutor(
            max_iterations=50,
            strategy="dfs",
        )
        assert executor.max_iterations == 50
        assert executor.strategy == "dfs"

    def test_concolic_executor_strategies(self):
        """Test different concolic strategies."""
        strategies = ["dfs", "bfs", "random", "coverage"]

        for strategy in strategies:
            executor = ConcolicExecutor(strategy=strategy)
            assert executor.strategy == strategy

    def test_generational_search_creation(self):
        """Test GenerationalSearch (SAGE-style) instantiation."""
        search = GenerationalSearch(max_generations=5)
        assert search.max_generations == 5


# =============================================================================
# Integration Tests
# =============================================================================


class TestPhase4Integration:
    """Integration tests for Phase 4 components."""

    def test_taint_with_detector_registry(self):
        """Test combining taint analysis with detector registry."""
        registry = DetectorRegistry()
        register_advanced_detectors(registry)

        tracker = TaintTracker()
        value = "user_data"
        tracker.mark_tainted(value, TaintSource.USER_INPUT, "input")

        # Verify both components work
        assert len(registry._detectors) > 0
        assert tracker.is_tainted(value)

    def test_call_graph_with_summaries(self):
        """Test call graph with function summaries."""
        graph = CallGraph()

        graph.add_function("main")
        graph.add_function("validate")
        graph.add_function("process")

        site1 = CallSite(caller="main", callee="validate", call_type=CallType.DIRECT, pc=10)
        site2 = CallSite(caller="main", callee="process", call_type=CallType.DIRECT, pc=20)
        graph.add_call("main", "validate", site1)
        graph.add_call("main", "process", site2)

        summary = FunctionSummary(
            name="validate",
            parameters=["x"],
            return_expr=z3.Int("result"),
            is_pure=True,
        )

        # Both should work together
        assert "validate" in graph.get_callees("main")
        assert summary.is_pure

    def test_concolic_with_traces(self):
        """Test concolic executor with execution traces."""
        executor = ConcolicExecutor(max_iterations=10)
        input_data = ConcreteInput(values={"x": 25})
        trace = ExecutionTrace(input=input_data)

        x = z3.Int("x")
        trace.branches.append(BranchRecord(pc=10, condition=x > 0, taken=True))
        trace.branches.append(BranchRecord(pc=20, condition=x < 50, taken=True))

        # Trace should have branches that can be negated
        assert len(trace.branches) == 2

        # Path condition should be satisfiable
        solver = z3.Solver()
        solver.add(trace.path_condition())
        assert solver.check() == z3.sat


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
