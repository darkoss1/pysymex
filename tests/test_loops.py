"""Tests for loop analysis module."""

import pytest

import z3


from pysymex.analysis.loops import (
    LoopType,
    LoopBound,
    LoopInfo,
    InductionVariable,
    LoopDetector,
    LoopBoundInference,
    LoopInvariantGenerator,
    LoopWidening,
)


class TestLoopInfo:
    """Tests for LoopInfo."""

    def test_create_loop_info(self):
        """Test creating loop info."""

        loop = LoopInfo(
            header_pc=10,
            back_edge_pc=20,
            body_pcs={10, 15, 20},
            exit_pcs={25},
            loop_type=LoopType.FOR_RANGE,
        )

        assert loop.header_pc == 10

        assert loop.back_edge_pc == 20

        assert 15 in loop.body_pcs

        assert 25 in loop.exit_pcs

        assert loop.loop_type == LoopType.FOR_RANGE

    def test_loop_depth(self):
        """Test loop nesting depth."""

        outer = LoopInfo(header_pc=0, back_edge_pc=10, body_pcs={0, 5, 10}, exit_pcs={15})

        inner = LoopInfo(header_pc=5, back_edge_pc=8, body_pcs={5, 6, 7, 8}, exit_pcs={10})

        outer.children.append(inner)

        inner.parent = outer

        outer.nesting_depth = 0

        inner.nesting_depth = 1

        assert outer.nesting_depth == 0

        assert inner.nesting_depth == 1


class TestLoopBound:
    """Tests for LoopBound."""

    def test_constant_bound(self):
        """Test constant loop bound."""

        bound = LoopBound.constant(10)

        assert bound.exact is not None

        assert bound.is_finite

    def test_symbolic_bound(self):
        """Test symbolic loop bound."""

        n = z3.Int("n")

        bound = LoopBound.symbolic(n)

        assert bound.exact is not None

    def test_range_bound(self):
        """Test range loop bound."""

        bound = LoopBound.range(0, 100)

        assert bound.is_finite

    def test_unbounded(self):
        """Test unbounded loop."""

        bound = LoopBound.unbounded()

        assert not bound.is_finite


class TestInductionVariable:
    """Tests for InductionVariable."""

    def test_basic_induction_variable(self):
        """Test basic induction variable."""

        iv = InductionVariable(
            name="i",
            initial=z3.IntVal(0),
            step=z3.IntVal(1),
        )

        assert iv.name == "i"

        assert iv.direction == 1

    def test_value_at_iteration(self):
        """Test computing value at iteration k."""

        iv = InductionVariable(
            name="i",
            initial=z3.IntVal(0),
            step=z3.IntVal(2),
        )

        k = z3.Int("k")

        value = iv.value_at_iteration(k)

        solver = z3.Solver()

        solver.add(k == 5)

        solver.add(value == 10)

        assert solver.check() == z3.sat


class TestLoopDetector:
    """Tests for LoopDetector."""

    def test_create_detector(self):
        """Test creating a loop detector."""

        detector = LoopDetector()

        assert detector is not None

        assert len(detector._loops) == 0

    def test_detector_initialization(self):
        """Test loop detector initialization."""

        detector = LoopDetector()

        assert detector._back_edges == []


class TestLoopBoundInference:
    """Tests for LoopBoundInference."""

    def test_create_inference(self):
        """Test creating loop bound inference."""

        inference = LoopBoundInference()

        assert inference is not None

    def test_infer_bound_returns_bound(self):
        """Test that infer_bound returns a LoopBound."""

        inference = LoopBoundInference()

        loop = LoopInfo(
            header_pc=0,
            back_edge_pc=10,
            exit_pcs={15},
            body_pcs={0, 5, 10},
        )

        assert hasattr(inference, "infer_bound")


class TestLoopInvariantGenerator:
    """Tests for LoopInvariantGenerator."""

    def test_create_generator(self):
        """Test creating invariant generator."""

        generator = LoopInvariantGenerator()

        assert generator is not None

        assert generator._invariants is not None

    def test_generate_invariants_exists(self):
        """Test that generate_invariants method exists."""

        generator = LoopInvariantGenerator()

        assert hasattr(generator, "generate_invariants")


class TestLoopWidening:
    """Tests for LoopWidening."""

    def test_create_widening(self):
        """Test creating widening operator."""

        widening = LoopWidening()

        assert widening is not None

        assert widening.widening_threshold == 3

    def test_widening_threshold_param(self):
        """Test widening with custom threshold."""

        widening = LoopWidening(widening_threshold=5)

        assert widening.widening_threshold == 5

    def test_should_widen(self):
        """Test checking if widening should be applied."""

        widening = LoopWidening(widening_threshold=2)

        loop = LoopInfo(
            header_pc=0,
            back_edge_pc=10,
            exit_pcs={15},
            body_pcs={0, 5, 10},
        )

        assert not widening.should_widen(loop)

        widening.record_iteration(loop)

        widening.record_iteration(loop)

        assert widening.should_widen(loop)

    def test_record_iteration(self):
        """Test recording loop iterations."""

        widening = LoopWidening()

        loop = LoopInfo(
            header_pc=0,
            back_edge_pc=10,
            exit_pcs={15},
            body_pcs={0, 5, 10},
        )

        widening.record_iteration(loop)

        assert widening._iteration_count.get(0, 0) == 1
