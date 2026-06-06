from unittest.mock import Mock, patch

import z3

from pysymex.analysis.static.loops.invariant_generation import LoopInvariantGenerator
from pysymex.analysis.static.loops.widening import LoopWidening
from pysymex.analysis.static.loops.types import (
    InductionVariable,
    LoopInfo,
    LoopInvariantProofStatus,
)
from pysymex.core.solver.constraints.chain import ConstraintChain
from pysymex.core.solver.engine.context import active_incremental_solver
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.solver.engine.results import SolverResult


class TestLoopInvariantGenerator:
    """Test suite for pysymex.analysis.static.loops.invariant_generation.LoopInvariantGenerator."""

    def test_generate_invariants(self) -> None:
        """Test generate_invariants behavior."""
        generator = LoopInvariantGenerator()
        loop = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 20})
        iv = InductionVariable("i", z3.IntVal(0), z3.IntVal(1))
        loop.induction_vars = {"i": iv}

        state = Mock()
        state.stack = []
        state.path_constraints = []

        mock_val = Mock()
        mock_val.z3_int = z3.Int("i")
        state.locals = {"i": mock_val}

        invariants = generator.generate_invariants(loop, state)
        assert len(invariants) > 0

    @patch("pysymex.core.solver.engine.queries.check_sat_result", return_value=SolverResult.unsat())
    def test_verify_invariant(self, mock_check_sat: Mock) -> None:
        """Test verify_invariant behavior."""
        _ = mock_check_sat
        generator = LoopInvariantGenerator()
        invariant = z3.BoolVal(True)
        state = Mock()
        state.path_constraints = []
        state.locals = {}
        loop = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 20})
        loop.induction_vars = {}
        assert generator.verify_invariant(invariant, loop, state) is True

    def test_verify_invariant_result_marks_solver_unknown_explicitly(self) -> None:
        generator = LoopInvariantGenerator()
        x = z3.Int("loop_invariant_unknown_x")
        state = Mock()
        state.path_constraints = []
        loop = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 20})
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(0.0)
        token = active_incremental_solver.set(solver)
        try:
            result = generator.verify_invariant_result(x > 0, loop, state)
        finally:
            active_incremental_solver.reset(token)

        assert result.status == LoopInvariantProofStatus.UNKNOWN
        assert result.is_proven is False
        assert result.counterexample is None
        assert result.reason == "Loop invariant proof inconclusive: solver returned unknown"

    def test_verify_invariant_result_marks_definite_counterexample(self) -> None:
        generator = LoopInvariantGenerator()
        x = z3.Int("loop_invariant_counterexample_x")
        state = Mock()
        state.path_constraints = [x == 0]
        loop = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 20})

        result = generator.verify_invariant_result(x > 0, loop, state)

        assert result.status == LoopInvariantProofStatus.DISPROVEN
        assert result.is_proven is False
        assert result.counterexample is not None
        assert result.reason is None

    def test_verify_invariant_result_marks_missing_model_as_unknown(self) -> None:
        generator = LoopInvariantGenerator()
        x = z3.Int("loop_invariant_missing_model_x")
        state = Mock()
        state.path_constraints = [x == 0]
        loop = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 20})

        with (
            patch(
                "pysymex.core.solver.engine.queries.check_sat_result",
                return_value=SolverResult.sat(None),
            ),
            patch("pysymex.core.solver.engine.queries.get_model", return_value=None),
        ):
            result = generator.verify_invariant_result(x > 0, loop, state)

        assert result.status == LoopInvariantProofStatus.UNKNOWN
        assert result.is_proven is False
        assert result.counterexample is None
        assert result.reason == (
            "Loop invariant violation is satisfiable but no counterexample model was available"
        )


class TestLoopWidening:
    """Test suite for pysymex.analysis.static.loops.widening.LoopWidening."""

    def test_should_widen(self) -> None:
        """Test should_widen behavior."""
        widening = LoopWidening(widening_threshold=2)
        loop = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 20})
        assert widening.should_widen(loop, 1) is False
        assert widening.should_widen(loop, 2) is True

    @patch("pysymex.core.types.scalars.values.SymbolicValue.symbolic_int")
    def test_widen_state(self, mock_sym_int: Mock) -> None:
        """Test widen_state behavior."""
        mock_sym_int.return_value = (Mock(z3_int=z3.Int("x_widened")), z3.BoolVal(True))
        widening = LoopWidening()
        loop = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 20})
        iv = InductionVariable("x", z3.IntVal(0), z3.IntVal(1))
        loop.induction_vars = {"x": iv}

        old_val = Mock()
        new_val = Mock(affinity_type="int")
        old_state = Mock()
        old_state.locals = {"x": old_val}

        new_state = Mock()
        new_state.copy.return_value = new_state
        new_state.locals = {"x": new_val}
        new_state.path_constraints = ConstraintChain.empty()

        widened = widening.widen_state(old_state, new_state, loop)
        assert "x" in widened.locals
