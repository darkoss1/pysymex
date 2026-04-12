from unittest.mock import MagicMock
from pysymex.analysis.taint.core import (
    TaintSource, TaintSink, TaintLabel, TaintedValue, TaintFlow,
    TaintPolicy, TaintTracker, TaintAnalyzer
)

class TestTaintSource:
    def test_initialization(self) -> None:
        assert TaintSource.USER_INPUT.name == "USER_INPUT"

class TestTaintSink:
    def test_initialization(self) -> None:
        assert TaintSink.SQL_QUERY.name == "SQL_QUERY"

class TestTaintLabel:
    def test_initialization(self) -> None:
        lbl = TaintLabel(TaintSource.USER_INPUT, "origin", 1)
        assert lbl.source == TaintSource.USER_INPUT
        assert str(lbl) == "USER_INPUT(origin@1)"
        lbl2 = TaintLabel(TaintSource.USER_INPUT)
        assert str(lbl2) == "USER_INPUT"

class TestTaintedValue:
    def test_is_tainted(self) -> None:
        tv = TaintedValue.clean(1)
        assert not tv.is_tainted()
        tv2 = TaintedValue.tainted(1, TaintSource.USER_INPUT)
        assert tv2.is_tainted()

    def test_with_taint(self) -> None:
        tv = TaintedValue.clean(1)
        tv2 = tv.with_taint(TaintLabel(TaintSource.USER_INPUT))
        assert tv2.is_tainted()

    def test_merge_taint(self) -> None:
        tv1 = TaintedValue.tainted(1, TaintSource.USER_INPUT)
        tv2 = TaintedValue.tainted(2, TaintSource.NETWORK)
        tv3 = tv1.merge_taint(tv2)
        assert len(tv3.labels) == 2

    def test_clean(self) -> None:
        tv = TaintedValue.clean(1)
        assert tv.value == 1
        assert not tv.labels

    def test_tainted(self) -> None:
        tv = TaintedValue.tainted(1, TaintSource.USER_INPUT, "orig", 10)
        assert tv.is_tainted()

class TestTaintFlow:
    def test_format(self) -> None:
        tf = TaintFlow(frozenset([TaintLabel(TaintSource.USER_INPUT)]), TaintSink.SQL_QUERY, "loc", 1, ("a", "b"))
        assert "Taint Flow Detected" in tf.format()

class TestTaintPolicy:
    def test_is_dangerous(self) -> None:
        p = TaintPolicy()
        assert p.is_dangerous(TaintSource.USER_INPUT, TaintSink.SQL_QUERY)
        assert not p.is_dangerous(TaintSource.ENVIRONMENT, TaintSink.LOG_OUTPUT)

    def test_add_sanitizer(self) -> None:
        p = TaintPolicy()
        p.add_sanitizer(TaintSource.USER_INPUT, TaintSink.SQL_QUERY, "escape")
        assert "escape" in p.get_sanitizers(TaintSource.USER_INPUT, TaintSink.SQL_QUERY)

    def test_get_sanitizers(self) -> None:
        p = TaintPolicy()
        assert p.get_sanitizers(TaintSource.USER_INPUT, TaintSink.LOG_OUTPUT) == set()

class TestTaintTracker:
    def test_fork(self) -> None:
        tt = TaintTracker()
        tt.mark_tainted("x", TaintSource.USER_INPUT)
        tt2 = tt.fork()
        assert len(tt2._taint_map) == 1  # type: ignore[reportPrivateUsage]
        tt2.mark_tainted("y", TaintSource.NETWORK)
        assert len(tt._taint_map) == 1  # type: ignore[reportPrivateUsage]
        assert len(tt2._taint_map) == 2  # type: ignore[reportPrivateUsage]

    def test_mark_tainted(self) -> None:
        tt = TaintTracker()
        tt.mark_tainted("x", TaintSource.USER_INPUT)
        assert tt.is_tainted("x")

    def test_get_taint(self) -> None:
        tt = TaintTracker()
        assert tt.get_taint("x") is None

    def test_is_tainted(self) -> None:
        tt = TaintTracker()
        assert not tt.is_tainted("x")
        tt.mark_tainted("x", TaintSource.USER_INPUT)
        assert tt.is_tainted("x")

    def test_propagate_taint(self) -> None:
        tt = TaintTracker()
        a = "a"
        b = "b"
        c = "c"
        tt.mark_tainted(a, TaintSource.USER_INPUT)
        tt.propagate_taint(c, a, b)
        assert tt.is_tainted(c)

    def test_check_sink(self) -> None:
        tt = TaintTracker()
        a = "a"
        tt.mark_tainted(a, TaintSource.USER_INPUT)
        flows = tt.check_sink(TaintSink.SQL_QUERY, a)
        assert len(flows) == 1

    def test_mark_sanitized(self) -> None:
        tt = TaintTracker()
        a = "a"
        tt.mark_tainted(a, TaintSource.USER_INPUT)
        tt.mark_sanitized(a)
        flows = tt.check_sink(TaintSink.SQL_QUERY, a)
        assert len(flows) == 0

    def test_get_all_flows(self) -> None:
        tt = TaintTracker()
        a = "a"
        tt.mark_tainted(a, TaintSource.USER_INPUT)
        tt.check_sink(TaintSink.SQL_QUERY, a)
        assert len(tt.get_all_flows()) == 1

    def test_clear(self) -> None:
        tt = TaintTracker()
        tt.mark_tainted("a", TaintSource.USER_INPUT)
        tt.clear()
        assert not tt.is_tainted("a")

class TestTaintAnalyzer:
    def test_analyze_function(self) -> None:
        analyzer = TaintAnalyzer()
        def dummy() -> None: pass
        import sys
        sys.modules['pysymex.execution.executors'] = MagicMock()
        flows = analyzer.analyze_function(dummy, {"x": TaintSource.USER_INPUT})
        assert isinstance(flows, list)
