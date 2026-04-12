from unittest.mock import MagicMock
from pysymex.analysis.taint.checker import (
    TaintAnalyzer, TaintFlowAnalysis, TaintChecker
)
from pysymex.analysis.taint.types import (
    TaintKind, SinkKind, TaintState, TaintedValue, TaintLabel
)

class TestTaintAnalyzer:
    def test_analyze_function(self) -> None:
        ta = TaintAnalyzer()
        def dummy() -> None:
            _ = input()
        code = dummy.__code__
        flows = ta.analyze_function(code)
        assert isinstance(flows, list)

    def test_process_instruction(self) -> None:
        ta = TaintAnalyzer()
        state = TaintState()
        instr = MagicMock()
        instr.opname = "LOAD_NAME"
        instr.argval = "x"
        ta.process_instruction(instr, state, 1, "f.py")
        assert len(state.stack) == 1

    def test_add_source(self) -> None:
        from pysymex.analysis.taint.types import TaintSource
        ta = TaintAnalyzer()
        ta.add_source(TaintSource("foo", TaintKind.USER_INPUT))
        assert "foo" in ta.sources

    def test_add_sink(self) -> None:
        from pysymex.analysis.taint.types import TaintSink
        ta = TaintAnalyzer()
        ta.add_sink(TaintSink("bar", SinkKind.EVAL, {0}))
        assert "bar" in ta.sinks

    def test_add_sanitizer(self) -> None:
        from pysymex.analysis.taint.types import Sanitizer
        ta = TaintAnalyzer()
        ta.add_sanitizer(Sanitizer("baz", TaintKind.USER_INPUT))
        assert "baz" in ta.sanitizers

class TestTaintFlowAnalysis:
    def test_initial_value(self) -> None:
        ta = TaintAnalyzer()
        tfa = TaintFlowAnalysis(MagicMock(), ta)
        assert isinstance(tfa.initial_value(), TaintState)

    def test_boundary_value(self) -> None:
        ta = TaintAnalyzer()
        tfa = TaintFlowAnalysis(MagicMock(), ta)
        assert isinstance(tfa.boundary_value(), TaintState)

    def test_transfer(self) -> None:
        ta = TaintAnalyzer()
        tfa = TaintFlowAnalysis(MagicMock(), ta)
        blk = MagicMock()
        blk.start_pc = 0
        blk.instructions = []
        state = TaintState()
        s2 = tfa.transfer(blk, state)
        assert isinstance(s2, TaintState)

    def test_meet(self) -> None:
        ta = TaintAnalyzer()
        tfa = TaintFlowAnalysis(MagicMock(), ta)
        s1 = TaintState()
        s1.variables["x"] = TaintedValue("x", {TaintLabel(TaintKind.USER_INPUT)})
        s2 = tfa.meet([s1])
        assert "x" in s2.variables

class TestTaintChecker:
    def test_check_function(self) -> None:
        tc = TaintChecker()
        def dummy() -> None: pass
        assert isinstance(tc.check_function(dummy.__code__), list)

    def test_check_flow_sensitive(self) -> None:
        tc = TaintChecker()
        def dummy() -> None: pass
        # Might crash if builder is mocked, but code is simple enough
        assert isinstance(tc.check_flow_sensitive(dummy.__code__), list)

    def test_add_source(self) -> None:
        tc = TaintChecker()
        tc.add_source("foo", TaintKind.USER_INPUT)
        assert "foo" in tc.analyzer.sources

    def test_add_sink(self) -> None:
        tc = TaintChecker()
        tc.add_sink("foo", SinkKind.EVAL, {0})
        assert "foo" in tc.analyzer.sinks

    def test_add_sanitizer(self) -> None:
        tc = TaintChecker()
        tc.add_sanitizer("foo", TaintKind.USER_INPUT)
        assert "foo" in tc.analyzer.sanitizers
