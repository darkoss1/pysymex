from pysymex.analysis.taint.types import (
    TaintKind, SinkKind, TaintLabel, TaintedValue, TaintSource, TaintSink,
    Sanitizer, TaintDefinitions, TaintState, TaintViolation
)

class TestTaintKind:
    """Test suite for pysymex.analysis.taint.types.TaintKind."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert TaintKind.USER_INPUT.value != 0
        assert (TaintKind.UNTRUSTED & TaintKind.USER_INPUT) == TaintKind.USER_INPUT

class TestSinkKind:
    """Test suite for pysymex.analysis.taint.types.SinkKind."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert SinkKind.EVAL.name == "EVAL"

class TestTaintLabel:
    """Test suite for pysymex.analysis.taint.types.TaintLabel."""
    def test_propagate(self) -> None:
        """Test propagate behavior."""
        label = TaintLabel(TaintKind.USER_INPUT, "src")
        label2 = label.propagate("op1")
        assert label2.path == ("op1",)

    def test_merge_with(self) -> None:
        """Test merge_with behavior."""
        label1 = TaintLabel(TaintKind.USER_INPUT, "src1")
        label2 = TaintLabel(TaintKind.FILE, "src2", path=("op",))
        m = label1.merge_with(label2)
        assert (m.kind & TaintKind.USER_INPUT) == TaintKind.USER_INPUT
        assert (m.kind & TaintKind.FILE) == TaintKind.FILE
        assert m.path == ("op",)

    def test_is_tainted(self) -> None:
        """Test is_tainted behavior."""
        assert TaintLabel(TaintKind.USER_INPUT).is_tainted
        assert not TaintLabel(TaintKind.NONE).is_tainted

    def test_is_untrusted(self) -> None:
        """Test is_untrusted behavior."""
        assert TaintLabel(TaintKind.USER_INPUT).is_untrusted
        assert not TaintLabel(TaintKind.FILE).is_untrusted

class TestTaintedValue:
    """Test suite for pysymex.analysis.taint.types.TaintedValue."""
    def test_add_label(self) -> None:
        """Test add_label behavior."""
        tv = TaintedValue("x")
        tv.add_label(TaintLabel(TaintKind.USER_INPUT))
        assert len(tv.labels) == 1

    def test_merge_labels(self) -> None:
        """Test merge_labels behavior."""
        tv1 = TaintedValue("x")
        tv1.add_label(TaintLabel(TaintKind.USER_INPUT))
        tv2 = TaintedValue("y")
        tv2.add_label(TaintLabel(TaintKind.FILE))
        tv1.merge_labels(tv2)
        assert len(tv1.labels) == 2

    def test_is_tainted(self) -> None:
        """Test is_tainted behavior."""
        tv = TaintedValue("x")
        assert not tv.is_tainted
        tv.add_label(TaintLabel(TaintKind.USER_INPUT))
        assert tv.is_tainted

    def test_taint_kinds(self) -> None:
        """Test taint_kinds behavior."""
        tv = TaintedValue("x")
        tv.add_label(TaintLabel(TaintKind.USER_INPUT))
        tv.add_label(TaintLabel(TaintKind.FILE))
        k = tv.taint_kinds
        assert (k & TaintKind.USER_INPUT)
        assert (k & TaintKind.FILE)

class TestTaintSource:
    """Test suite for pysymex.analysis.taint.types.TaintSource."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        ts = TaintSource("s", TaintKind.USER_INPUT)
        assert ts.name == "s"

class TestTaintSink:
    """Test suite for pysymex.analysis.taint.types.TaintSink."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        ts = TaintSink("s", SinkKind.EVAL)
        assert ts.name == "s"

class TestSanitizer:
    """Test suite for pysymex.analysis.taint.types.Sanitizer."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        s = Sanitizer("s", TaintKind.USER_INPUT)
        assert s.name == "s"

class TestTaintDefinitions:
    """Test suite for pysymex.analysis.taint.types.TaintDefinitions."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert len(TaintDefinitions.SOURCES) > 0
        assert len(TaintDefinitions.SINKS) > 0
        assert len(TaintDefinitions.SANITIZERS) > 0

class TestTaintState:
    """Test suite for pysymex.analysis.taint.types.TaintState."""
    def test_copy(self) -> None:
        """Test copy behavior."""
        ts = TaintState()
        tv = TaintedValue("x")
        ts.variables["x"] = tv
        ts2 = ts.copy()
        assert "x" in ts2.variables
        assert ts2.variables["x"] is not tv

    def test_get_taint(self) -> None:
        """Test get_taint behavior."""
        ts = TaintState()
        assert ts.get_taint("x").value_name == "x"

    def test_set_taint(self) -> None:
        """Test set_taint behavior."""
        ts = TaintState()
        ts.set_taint("x", TaintedValue("y"))
        assert ts.variables["x"].value_name == "y"

    def test_is_tainted(self) -> None:
        """Test is_tainted behavior."""
        ts = TaintState()
        assert not ts.is_tainted("x")
        tv = TaintedValue("x")
        tv.add_label(TaintLabel(TaintKind.USER_INPUT))
        ts.set_taint("x", tv)
        assert ts.is_tainted("x")

    def test_push(self) -> None:
        """Test push behavior."""
        ts = TaintState()
        ts.push(TaintedValue("x"))
        assert len(ts.stack) == 1

    def test_pop(self) -> None:
        """Test pop behavior."""
        ts = TaintState()
        ts.push(TaintedValue("x"))
        assert ts.pop().value_name == "x"
        assert ts.pop().value_name == "_unknown"

    def test_peek(self) -> None:
        """Test peek behavior."""
        ts = TaintState()
        ts.push(TaintedValue("x"))
        assert ts.peek() is not None
        assert ts.peek() is not None
        assert ts.peek(100) is None

    def test_merge_with(self) -> None:
        """Test merge_with behavior."""
        ts1 = TaintState()
        ts1.variables["x"] = TaintedValue("x", {TaintLabel(TaintKind.USER_INPUT)})
        ts2 = TaintState()
        ts2.variables["x"] = TaintedValue("x", {TaintLabel(TaintKind.FILE)})
        ts3 = ts1.merge_with(ts2)
        assert len(ts3.variables["x"].labels) == 2

class TestTaintViolation:
    """Test suite for pysymex.analysis.taint.types.TaintViolation."""
    def test_format(self) -> None:
        """Test format behavior."""
        lbl = TaintLabel(TaintKind.USER_INPUT, "src", 10, ("op",))
        sink = TaintSink("eval", SinkKind.EVAL)
        tv = TaintViolation(lbl, sink, 20, 0, "file.py", "x", "desc")
        assert "TAINT" in tv.format()
        assert "eval" in str(tv)
