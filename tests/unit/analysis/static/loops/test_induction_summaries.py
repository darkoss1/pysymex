from unittest.mock import Mock

import z3

from pysymex.analysis.static.loops.induction import InductionVariableDetector
from pysymex.analysis.static.loops.summaries import LoopSummarizer
from pysymex.analysis.static.loops.types import InductionVariable, LoopBound, LoopInfo, LoopSummary
from pysymex.core.types.scalars.values import SymbolicValue


class TestInductionVariableDetector:
    """Test suite for pysymex.analysis.static.loops.induction.InductionVariableDetector."""

    def test_detect(self) -> None:
        """Test detect behavior."""
        detector = InductionVariableDetector()
        loop = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 20})
        result = detector.detect(loop, [], Mock())
        assert isinstance(result, dict)
        assert len(result) == 0


class TestLoopSummarizer:
    """Test suite for pysymex.analysis.static.loops.summaries.LoopSummarizer."""

    def test_summarize(self) -> None:
        """Test summarize behavior."""
        summarizer = LoopSummarizer()
        loop = LoopInfo(header_pc=10, back_edge_pc=20, exit_pcs={30}, body_pcs={10, 20})

        mock_state = Mock()
        mock_state.locals = {}
        mock_state.stack = []
        mock_state.memory = {}
        mock_state.path_constraints = []
        mock_state.current_instructions = []

        assert summarizer.summarize(loop, mock_state) is None

        loop.bound = LoopBound.constant(10)
        assert summarizer.summarize(loop, mock_state) is None

        iv = InductionVariable("i", z3.IntVal(0), z3.IntVal(1))
        loop.induction_vars = {"i": iv}
        summary = summarizer.summarize(loop, mock_state)
        assert summary is not None
        assert "i" in summary.variable_effects

    def test_apply_summary(self) -> None:
        """Test apply_summary behavior."""
        summarizer = LoopSummarizer()
        summary = LoopSummary(10, {"x": z3.IntVal(42)}, {})
        state = Mock()
        state.copy.return_value = state
        state.locals = {"x": Mock()}

        new_state = summarizer.apply_summary(summary, state)
        new_value = new_state.locals["x"]
        assert isinstance(new_value, SymbolicValue)
        assert z3.eq(new_value.z3_int, z3.IntVal(42))
