import pytest
import dis
from unittest.mock import Mock, patch
import z3
from pysymex.analysis.loops.core import (
    LoopDetector, LoopBoundInference, InductionVariableDetector,
    LoopSummarizer, LoopInvariantGenerator, LoopWidening
)
from pysymex.analysis.loops.types import LoopInfo, LoopBound, InductionVariable, LoopSummary

def make_dummy_code() -> object:
    def f() -> None:
        for i in range(10):
            pass
    return f.__code__

class TestLoopDetector:
    """Test suite for pysymex.analysis.loops.core.LoopDetector."""
    def test_analyze_cfg(self) -> None:
        """Test analyze_cfg behavior."""
        d = LoopDetector()
        code = make_dummy_code() # type: ignore[arg-type]
        instructions = list(dis.get_instructions(code))
        loops = d.analyze_cfg(instructions)
        assert isinstance(loops, list)
        # Should detect a loop
        assert len(loops) > 0
        assert isinstance(loops[0], LoopInfo)

    def test_loops(self) -> None:
        """Test loops behavior."""
        d = LoopDetector()
        assert d.loops == []
        code = make_dummy_code() # type: ignore[arg-type]
        instructions = list(dis.get_instructions(code))
        loops = d.analyze_cfg(instructions)
        assert d.loops == loops

    def test_get_loop_at(self) -> None:
        """Test get_loop_at behavior."""
        d = LoopDetector()
        code = make_dummy_code() # type: ignore[arg-type]
        instructions = list(dis.get_instructions(code))
        loops = d.analyze_cfg(instructions)
        assert len(loops) > 0
        pc = list(loops[0].body_pcs)[0]
        assert d.get_loop_at(pc) is loops[0]
        assert d.get_loop_at(-1) is None

class TestLoopBoundInference:
    """Test suite for pysymex.analysis.loops.core.LoopBoundInference."""
    def test_infer_bound(self) -> None:
        """Test infer_bound behavior."""
        lbi = LoopBoundInference()
        loop = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 20})
        state = Mock(stack=[], locals={}, memory={}, path_constraints=[])
        
        # Test default fallback
        bound = lbi.infer_bound(loop, state)
        assert isinstance(bound, LoopBound)
        
        # Test caching
        assert lbi.infer_bound(loop, state) is bound

class TestInductionVariableDetector:
    """Test suite for pysymex.analysis.loops.core.InductionVariableDetector."""
    def test_detect(self) -> None:
        """Test detect behavior."""
        ivd = InductionVariableDetector()
        loop = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 20})
        # Empty instructions
        res = ivd.detect(loop, [], Mock())
        assert isinstance(res, dict)
        assert len(res) == 0

class TestLoopSummarizer:
    """Test suite for pysymex.analysis.loops.core.LoopSummarizer."""
    def test_summarize(self) -> None:
        """Test summarize behavior."""
        ls = LoopSummarizer()
        loop = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 20})
        # No bound
        assert ls.summarize(loop, Mock()) is None
        
        # With finite bound but no IVs
        loop.bound = LoopBound.constant(10)
        assert ls.summarize(loop, Mock()) is None
        
        # With IVs
        iv = InductionVariable("i", z3.IntVal(0), z3.IntVal(1))
        loop.induction_vars = {"i": iv}
        summary = ls.summarize(loop, Mock())
        assert summary is not None
        assert "i" in summary.variable_effects

    def test_apply_summary(self) -> None:
        """Test apply_summary behavior."""
        ls = LoopSummarizer()
        summary = LoopSummary(10, {"x": z3.IntVal(42)}, {})
        state = Mock()
        state.copy.return_value = state
        state.locals = {"x": Mock()}
        
        new_state = ls.apply_summary(summary, state)
        # Should have updated local "x"
        assert new_state.locals["x"].z3_int.eq(z3.IntVal(42))

class TestLoopInvariantGenerator:
    """Test suite for pysymex.analysis.loops.core.LoopInvariantGenerator."""
    def test_generate_invariants(self) -> None:
        """Test generate_invariants behavior."""
        lig = LoopInvariantGenerator()
        loop = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 20})
        iv = InductionVariable("i", z3.IntVal(0), z3.IntVal(1))
        loop.induction_vars = {"i": iv}
        
        state = Mock(stack=[], path_constraints=[])
        mock_val = Mock()
        mock_val.z3_int = z3.Int("i")
        state.locals = {"i": mock_val}
        
        invs = lig.generate_invariants(loop, state)
        assert len(invs) > 0

    @patch("pysymex.analysis.loops.core.is_satisfiable", return_value=False)
    def test_verify_invariant(self, mock_is_sat) -> None:
        """Test verify_invariant behavior."""
        lig = LoopInvariantGenerator()
        inv = z3.BoolVal(True)
        state = Mock(path_constraints=[])
        assert lig.verify_invariant(inv, Mock(), state) is True

class TestLoopWidening:
    """Test suite for pysymex.analysis.loops.core.LoopWidening."""
    def test_record_iteration(self) -> None:
        """Test record_iteration behavior."""
        lw = LoopWidening()
        loop = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 20})
        lw.record_iteration(loop)
        assert lw._iteration_count[10] == 1

    def test_should_widen(self) -> None:
        """Test should_widen behavior."""
        lw = LoopWidening(widening_threshold=2)
        loop = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 20})
        assert lw.should_widen(loop, 1) is False
        assert lw.should_widen(loop, 2) is True
        
        # using global iteration count
        lw.record_iteration(loop)
        assert lw.should_widen(loop) is False
        lw.record_iteration(loop)
        assert lw.should_widen(loop) is True

    @patch("pysymex.core.types.scalars.SymbolicValue.symbolic_int")
    def test_widen_state(self, mock_sym_int) -> None:
        """Test widen_state behavior."""
        mock_sym_int.return_value = (Mock(z3_int=z3.Int("x_widened")), z3.BoolVal(True))
        lw = LoopWidening()
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
        
        class MockConstraints(list):
            def append(self, x):
                return MockConstraints(super().copy() + [x])
                
        new_state.path_constraints = MockConstraints()
        
        widened = lw.widen_state(old_state, new_state, loop)
        assert "x" in widened.locals
