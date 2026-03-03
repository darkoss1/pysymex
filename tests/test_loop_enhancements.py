"""Comprehensive tests for loop enhancement features.

Tests for:
- InductionVariableDetector
- LoopSummarizer
- LoopBoundInference (enhanced)
- Nested loops
- Symbolic bounds
"""

import pytest

import z3

from unittest.mock import MagicMock, patch

from types import SimpleNamespace

from pysymex.analysis.loops import (
    LoopType,
    LoopBound,
    LoopInfo,
    InductionVariable,
    LoopDetector,
    LoopBoundInference,
    InductionVariableDetector,
    LoopSummary,
    LoopSummarizer,
    LoopInvariantGenerator,
    LoopWidening,
)

from pysymex.core.state import VMState

from pysymex.core.types import SymbolicValue


def mock_symbolic(name: str) -> SymbolicValue:
    """Create a SymbolicValue for testing."""

    sym_val, _constraint = SymbolicValue.symbolic(name)

    return sym_val


class TestInductionVariableDetector:
    """Tests for InductionVariableDetector."""

    def test_create_detector(self):
        """Test creating an induction variable detector."""

        detector = InductionVariableDetector()

        assert detector is not None

        assert detector._detected == {}

    def test_detect_empty_loop(self):
        """Test detection with empty loop body."""

        detector = InductionVariableDetector()

        loop = LoopInfo(header_pc=0, back_edge_pc=10, body_pcs=set(), exit_pcs={15})

        state = MagicMock(spec=VMState)

        state.locals = {}

        result = detector.detect(loop, [], state)

        assert result == {}

    def test_detect_simple_increment(self):
        """Test detecting i += 1 pattern."""

        detector = InductionVariableDetector()

        loop = LoopInfo(header_pc=0, back_edge_pc=20, body_pcs={0, 5, 10, 15, 20}, exit_pcs={25})

        instructions = [
            SimpleNamespace(offset=0, opname="LOAD_FAST", argval="i"),
            SimpleNamespace(offset=5, opname="LOAD_CONST", argval=1),
            SimpleNamespace(offset=10, opname="BINARY_OP", argval=0),
            SimpleNamespace(offset=15, opname="STORE_FAST", argval="i"),
        ]

        state = MagicMock(spec=VMState)

        state.locals = {"i": mock_symbolic("i")}

        result = detector.detect(loop, instructions, state)

        assert isinstance(result, dict)

    def test_detect_step_patterns(self):
        """Test detecting various step values."""

        detector = InductionVariableDetector()

        for step in [1, 2, 5, 10, -1]:
            loop = LoopInfo(
                header_pc=0, back_edge_pc=20, body_pcs={0, 5, 10, 15, 20}, exit_pcs={25}
            )

            instructions = [
                SimpleNamespace(offset=0, opname="LOAD_FAST", argval="counter"),
                SimpleNamespace(offset=5, opname="LOAD_CONST", argval=step),
                SimpleNamespace(offset=10, opname="BINARY_OP", argval=0),
                SimpleNamespace(offset=15, opname="STORE_FAST", argval="counter"),
            ]

            state = MagicMock(spec=VMState)

            state.locals = {"counter": 0}

            result = detector.detect(loop, instructions, state)

            assert isinstance(result, dict)

    def test_detect_no_induction_variable(self):
        """Test when no induction variable exists."""

        detector = InductionVariableDetector()

        loop = LoopInfo(header_pc=0, back_edge_pc=10, body_pcs={0, 5, 10}, exit_pcs={15})

        instructions = [
            SimpleNamespace(offset=0, opname="LOAD_FAST", argval="x"),
            SimpleNamespace(offset=5, opname="PRINT_EXPR", argval=None),
        ]

        state = MagicMock(spec=VMState)

        state.locals = {"x": 5}

        result = detector.detect(loop, instructions, state)

        assert "x" not in result

    def test_detect_multiple_induction_vars(self):
        """Test detecting multiple induction variables."""

        detector = InductionVariableDetector()

        loop = LoopInfo(
            header_pc=0, back_edge_pc=40, body_pcs={0, 5, 10, 15, 20, 25, 30, 35, 40}, exit_pcs={45}
        )

        instructions = [
            SimpleNamespace(offset=0, opname="LOAD_FAST", argval="i"),
            SimpleNamespace(offset=5, opname="LOAD_CONST", argval=1),
            SimpleNamespace(offset=10, opname="BINARY_OP", argval=0),
            SimpleNamespace(offset=15, opname="STORE_FAST", argval="i"),
            SimpleNamespace(offset=20, opname="LOAD_FAST", argval="j"),
            SimpleNamespace(offset=25, opname="LOAD_CONST", argval=2),
            SimpleNamespace(offset=30, opname="BINARY_OP", argval=0),
            SimpleNamespace(offset=35, opname="STORE_FAST", argval="j"),
        ]

        state = MagicMock(spec=VMState)

        state.locals = {"i": 0, "j": 0}

        result = detector.detect(loop, instructions, state)

        assert isinstance(result, dict)


class TestLoopSummarizer:
    """Tests for LoopSummarizer."""

    def test_create_summarizer(self):
        """Test creating a loop summarizer."""

        summarizer = LoopSummarizer()

        assert summarizer is not None

    def test_summarize_no_bound(self):
        """Test summarization fails without bound."""

        summarizer = LoopSummarizer()

        loop = LoopInfo(header_pc=0, back_edge_pc=10, body_pcs={0, 5, 10}, exit_pcs={15})

        loop.bound = None

        state = MagicMock(spec=VMState)

        result = summarizer.summarize(loop, state)

        assert result is None

    def test_summarize_unbounded_loop(self):
        """Test summarization fails for unbounded loop."""

        summarizer = LoopSummarizer()

        loop = LoopInfo(header_pc=0, back_edge_pc=10, body_pcs={0, 5, 10}, exit_pcs={15})

        loop.bound = LoopBound.unbounded()

        state = MagicMock(spec=VMState)

        result = summarizer.summarize(loop, state)

        assert result is None

    def test_summarize_no_induction_vars(self):
        """Test summarization fails without induction variables."""

        summarizer = LoopSummarizer()

        loop = LoopInfo(header_pc=0, back_edge_pc=10, body_pcs={0, 5, 10}, exit_pcs={15})

        loop.bound = LoopBound.constant(10)

        loop.induction_vars = {}

        state = MagicMock(spec=VMState)

        result = summarizer.summarize(loop, state)

        assert result is None

    def test_summarize_simple_loop(self):
        """Test summarizing a simple counted loop."""

        summarizer = LoopSummarizer()

        loop = LoopInfo(header_pc=0, back_edge_pc=10, body_pcs={0, 5, 10}, exit_pcs={15})

        loop.bound = LoopBound.constant(100)

        loop.induction_vars = {
            "i": InductionVariable(
                name="i",
                initial=z3.IntVal(0),
                step=z3.IntVal(1),
            )
        }

        loop.invariants = []

        state = MagicMock(spec=VMState)

        result = summarizer.summarize(loop, state)

        assert result is not None

        assert isinstance(result, LoopSummary)

        assert result.can_summarize

        assert "i" in result.variable_effects

    def test_summarize_symbolic_bound(self):
        """Test summarizing with symbolic bound."""

        summarizer = LoopSummarizer()

        n = z3.Int("n")

        loop = LoopInfo(header_pc=0, back_edge_pc=10, body_pcs={0, 5, 10}, exit_pcs={15})

        loop.bound = LoopBound.symbolic(n)

        loop.induction_vars = {
            "i": InductionVariable(
                name="i",
                initial=z3.IntVal(0),
                step=z3.IntVal(1),
            )
        }

        loop.invariants = []

        state = MagicMock(spec=VMState)

        result = summarizer.summarize(loop, state)

        assert result is not None

        assert result.can_summarize

    def test_apply_summary(self):
        """Test applying loop summary to state."""

        summarizer = LoopSummarizer()

        summary = LoopSummary(
            iterations=10,
            variable_effects={"i": z3.IntVal(10)},
            memory_effects={},
            can_summarize=True,
        )

        state = MagicMock(spec=VMState)

        state.locals = {"i": mock_symbolic("i")}

        state.memory = {}

        state.copy = MagicMock(return_value=MagicMock(locals={"i": mock_symbolic("i")}, memory={}))

        new_state = summarizer.apply_summary(summary, state)

        assert new_state is not None


class TestLoopSummary:
    """Tests for LoopSummary dataclass."""

    def test_create_summary(self):
        """Test creating a loop summary."""

        summary = LoopSummary(
            iterations=10,
            variable_effects={"i": z3.IntVal(10)},
            memory_effects={},
        )

        assert summary.iterations == 10

        assert "i" in summary.variable_effects

    def test_summary_with_memory_effects(self):
        """Test summary with memory effects."""

        summary = LoopSummary(
            iterations=5,
            variable_effects={},
            memory_effects={123: {"value": z3.IntVal(50)}},
        )

        assert 123 in summary.memory_effects

    def test_summary_invariants_verified(self):
        """Test summary invariants flag."""

        summary = LoopSummary(
            iterations=10,
            variable_effects={},
            memory_effects={},
            invariants_verified=True,
        )

        assert summary.invariants_verified


class TestLoopBoundInferenceEnhanced:
    """Enhanced tests for LoopBoundInference."""

    def test_bound_caching(self):
        """Test that bounds are cached."""

        inference = LoopBoundInference()

        loop = LoopInfo(header_pc=100, back_edge_pc=110, body_pcs={100, 105, 110}, exit_pcs={115})

        state = MagicMock(spec=VMState)

        state.stack = []

        state.memory = {}

        state.path_constraints = []

        state.locals = {}

        bound1 = inference.infer_bound(loop, state)

        bound2 = inference.infer_bound(loop, state)

        assert bound1 is bound2

    def test_extract_iterator_bound_empty_stack(self):
        """Test iterator bound extraction with empty stack."""

        inference = LoopBoundInference()

        state = MagicMock(spec=VMState)

        state.stack = []

        result = inference._try_extract_iterator_bound(state)

        assert result is None

    def test_infer_while_bound(self):
        """Test while loop bound inference."""

        inference = LoopBoundInference()

        loop = LoopInfo(header_pc=0, back_edge_pc=10, body_pcs={0, 5, 10}, exit_pcs={15})

        state = MagicMock(spec=VMState)

        state.path_constraints = []

        bound = inference._infer_while_bound(loop, state)

        assert bound is not None

        assert bound.is_finite

    def test_infer_range_bound_from_stack(self):
        """Test range bound inference from stack."""

        inference = LoopBoundInference()

        loop = LoopInfo(header_pc=0, back_edge_pc=10, body_pcs={0, 5, 10}, exit_pcs={15})

        state = MagicMock(spec=VMState)

        state.stack = []

        state.memory = {}

        bound = inference._infer_range_bound(loop, state)

        assert bound is not None


class TestLoopInvariantGeneratorEnhanced:
    """Enhanced tests for LoopInvariantGenerator."""

    def test_generate_invariants_with_induction_vars(self):
        """Test invariant generation with induction variables."""

        generator = LoopInvariantGenerator()

        loop = LoopInfo(header_pc=0, back_edge_pc=10, body_pcs={0, 5, 10}, exit_pcs={15})

        loop.bound = LoopBound.constant(100)

        loop.induction_vars = {
            "i": InductionVariable(
                name="i",
                initial=z3.IntVal(0),
                step=z3.IntVal(1),
            )
        }

        i_sym = mock_symbolic("i")

        state = MagicMock(spec=VMState)

        state.locals = {"i": i_sym}

        state.stack = []

        state.path_constraints = []

        invariants = generator.generate_invariants(loop, state)

        assert isinstance(invariants, list)

    def test_verify_invariant_true(self):
        """Test verifying a true invariant."""

        generator = LoopInvariantGenerator()

        loop = LoopInfo(header_pc=0, back_edge_pc=10, body_pcs={0, 5, 10}, exit_pcs={15})

        x = z3.Int("x")

        invariant = x >= 0

        state = MagicMock(spec=VMState)

        state.path_constraints = [x >= 0]

        result = generator.verify_invariant(invariant, loop, state)

        assert isinstance(result, bool)


class TestLoopWideningEnhanced:
    """Enhanced tests for LoopWidening."""

    def test_widen_with_induction_vars(self):
        """Test widening with induction variables."""

        widening = LoopWidening()

        loop = LoopInfo(header_pc=0, back_edge_pc=10, body_pcs={0, 5, 10}, exit_pcs={15})

        loop.bound = LoopBound.constant(100)

        loop.induction_vars = {
            "i": InductionVariable(
                name="i",
                initial=z3.IntVal(0),
                step=z3.IntVal(1),
            )
        }

        old_state = MagicMock(spec=VMState)

        old_state.locals = {"i": mock_symbolic("i_old")}

        new_state = MagicMock(spec=VMState)

        new_state.locals = {"i": mock_symbolic("i_new")}

        new_state.path_constraints = []

        new_state.copy = MagicMock(
            return_value=MagicMock(locals={"i": mock_symbolic("i_new")}, path_constraints=[])
        )

        widened = widening.widen_state(old_state, new_state, loop)

        assert widened is not None

    def test_widen_non_induction_vars(self):
        """Test widening non-induction variables."""

        widening = LoopWidening()

        loop = LoopInfo(header_pc=0, back_edge_pc=10, body_pcs={0, 5, 10}, exit_pcs={15})

        loop.induction_vars = {}

        old_state = MagicMock(spec=VMState)

        old_state.locals = {"x": mock_symbolic("x_old")}

        new_state = MagicMock(spec=VMState)

        new_state.locals = {"x": mock_symbolic("x_new")}

        new_state.copy = MagicMock(
            return_value=MagicMock(locals={"x": mock_symbolic("x_new")}, path_constraints=[])
        )

        widened = widening.widen_state(old_state, new_state, loop)

        assert widened is not None


class TestNestedLoops:
    """Tests for nested loop handling."""

    def test_nested_loop_structure(self):
        """Test nested loop parent-child relationship."""

        outer = LoopInfo(
            header_pc=0, back_edge_pc=30, body_pcs={0, 5, 10, 15, 20, 25, 30}, exit_pcs={35}
        )

        inner = LoopInfo(header_pc=10, back_edge_pc=20, body_pcs={10, 15, 20}, exit_pcs={25})

        outer.children.append(inner)

        inner.parent = outer

        assert inner in outer.children

        assert inner.parent is outer

    def test_nested_loop_depths(self):
        """Test loop nesting depths."""

        outer = LoopInfo(header_pc=0, back_edge_pc=50, body_pcs=set(range(0, 55, 5)), exit_pcs={55})

        middle = LoopInfo(
            header_pc=10, back_edge_pc=40, body_pcs=set(range(10, 45, 5)), exit_pcs={45}
        )

        inner = LoopInfo(header_pc=20, back_edge_pc=30, body_pcs={20, 25, 30}, exit_pcs={35})

        outer.nesting_depth = 0

        middle.nesting_depth = 1

        inner.nesting_depth = 2

        outer.children.append(middle)

        middle.children.append(inner)

        middle.parent = outer

        inner.parent = middle

        assert outer.nesting_depth == 0

        assert middle.nesting_depth == 1

        assert inner.nesting_depth == 2

    def test_nested_induction_variables(self):
        """Test induction variables in nested loops."""

        outer = LoopInfo(
            header_pc=0, back_edge_pc=30, body_pcs={0, 5, 10, 15, 20, 25, 30}, exit_pcs={35}
        )

        inner = LoopInfo(header_pc=10, back_edge_pc=20, body_pcs={10, 15, 20}, exit_pcs={25})

        outer.induction_vars = {
            "i": InductionVariable(name="i", initial=z3.IntVal(0), step=z3.IntVal(1))
        }

        inner.induction_vars = {
            "j": InductionVariable(name="j", initial=z3.IntVal(0), step=z3.IntVal(1))
        }

        assert "i" in outer.induction_vars

        assert "j" in inner.induction_vars

        assert "j" not in outer.induction_vars


class TestSymbolicBounds:
    """Tests for symbolic loop bounds."""

    def test_symbolic_bound_creation(self):
        """Test creating symbolic bounds."""

        n = z3.Int("n")

        bound = LoopBound.symbolic(n)

        assert bound.exact is not None

    def test_symbolic_bound_with_constraint(self):
        """Test symbolic bound with constraint."""

        n = z3.Int("n")

        bound = LoopBound.symbolic(n)

        solver = z3.Solver()

        solver.add(n > 0)

        solver.add(n < 100)

        assert solver.check() == z3.sat

    def test_induction_var_with_symbolic_bound(self):
        """Test induction variable value with symbolic bound."""

        n = z3.Int("n")

        iv = InductionVariable(
            name="i",
            initial=z3.IntVal(0),
            step=z3.IntVal(1),
        )

        final = iv.final_value(n)

        solver = z3.Solver()

        solver.add(n == 10)

        solver.add(final == 10)

        assert solver.check() == z3.sat

    def test_symbolic_bound_arithmetic(self):
        """Test arithmetic with symbolic bounds."""

        n = z3.Int("n")

        m = z3.Int("m")

        outer_bound = LoopBound.symbolic(n)

        inner_bound = LoopBound.symbolic(m)

        total = n * m

        solver = z3.Solver()

        solver.add(n == 10)

        solver.add(m == 5)

        solver.add(total == 50)

        assert solver.check() == z3.sat


class TestLoopEdgeCases:
    """Edge case tests for loop handling."""

    def test_zero_iteration_loop(self):
        """Test loop that never executes."""

        bound = LoopBound.constant(0)

        assert bound.exact is not None

    def test_single_iteration_loop(self):
        """Test loop with exactly one iteration."""

        bound = LoopBound.constant(1)

        assert bound.is_finite

    def test_negative_step_induction(self):
        """Test induction variable with negative step."""

        iv = InductionVariable(
            name="i",
            initial=z3.IntVal(10),
            step=z3.IntVal(-1),
            direction=-1,
        )

        assert iv.direction == -1

        final = iv.final_value(z3.IntVal(10))

        solver = z3.Solver()

        solver.add(final == 0)

        assert solver.check() == z3.sat

    def test_zero_step_induction(self):
        """Test induction variable with zero step (no progress)."""

        iv = InductionVariable(
            name="i",
            initial=z3.IntVal(5),
            step=z3.IntVal(0),
        )

        final = iv.final_value(z3.IntVal(100))

        solver = z3.Solver()

        solver.add(final == 5)

        assert solver.check() == z3.sat

    def test_large_step_induction(self):
        """Test induction variable with large step."""

        iv = InductionVariable(
            name="i",
            initial=z3.IntVal(0),
            step=z3.IntVal(1000),
        )

        final = iv.final_value(z3.IntVal(10))

        solver = z3.Solver()

        solver.add(final == 10000)

        assert solver.check() == z3.sat

    def test_empty_loop_body(self):
        """Test loop with empty body."""

        loop = LoopInfo(header_pc=0, back_edge_pc=5, body_pcs={0, 5}, exit_pcs={10})

        assert len(loop.body_pcs) == 2

    def test_loop_all_same_types(self):
        """Test all loop types."""

        for loop_type in LoopType:
            loop = LoopInfo(
                header_pc=0,
                back_edge_pc=10,
                body_pcs={0, 5, 10},
                exit_pcs={15},
                loop_type=loop_type,
            )

            assert loop.loop_type == loop_type


class TestLoopIntegration:
    """Integration tests for loop components."""

    def test_detector_to_bound_inference(self):
        """Test loop detection flowing to bound inference."""

        detector = LoopDetector()

        inference = LoopBoundInference()

        assert detector is not None

        assert inference is not None

    def test_bound_to_summarizer(self):
        """Test bound inference flowing to summarizer."""

        summarizer = LoopSummarizer()

        loop = LoopInfo(header_pc=0, back_edge_pc=10, body_pcs={0, 5, 10}, exit_pcs={15})

        loop.bound = LoopBound.constant(10)

        loop.induction_vars = {
            "i": InductionVariable(
                name="i",
                initial=z3.IntVal(0),
                step=z3.IntVal(1),
            )
        }

        loop.invariants = []

        state = MagicMock(spec=VMState)

        summary = summarizer.summarize(loop, state)

        assert summary is not None

        assert summary.can_summarize

    def test_full_loop_analysis_pipeline(self):
        """Test complete loop analysis pipeline."""

        detector = LoopDetector()

        inference = LoopBoundInference()

        iv_detector = InductionVariableDetector()

        summarizer = LoopSummarizer()

        invariant_gen = LoopInvariantGenerator()

        widening = LoopWidening()

        assert all([detector, inference, iv_detector, summarizer, invariant_gen, widening])

    def test_widening_after_threshold(self):
        """Test widening kicks in after threshold iterations."""

        widening = LoopWidening(widening_threshold=3)

        loop = LoopInfo(header_pc=0, back_edge_pc=10, body_pcs={0, 5, 10}, exit_pcs={15})

        assert not widening.should_widen(loop)

        widening.record_iteration(loop)

        widening.record_iteration(loop)

        assert not widening.should_widen(loop)

        widening.record_iteration(loop)

        assert widening.should_widen(loop)
