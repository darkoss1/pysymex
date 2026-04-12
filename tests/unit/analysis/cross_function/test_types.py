import pytest
from pysymex.analysis.cross_function.types import (
    Effect, EffectSummary, CallSiteInfo, CallGraphNode, CallContext, ContextSensitiveSummary
)
from pysymex.analysis.type_inference import PyType

class TestEffect:
    """Test suite for pysymex.analysis.cross_function.types.Effect."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert Effect.NONE.value == 0
        assert Effect.READ_LOCAL.value > 0

class TestEffectSummary:
    """Test suite for pysymex.analysis.cross_function.types.EffectSummary."""
    def test_is_pure(self) -> None:
        """Test is_pure behavior."""
        summary = EffectSummary(effects=Effect.NONE)
        assert summary.is_pure is True
        summary_impure = EffectSummary(effects=Effect.READ_LOCAL)
        assert summary_impure.is_pure is False

    def test_is_read_only(self) -> None:
        """Test is_read_only behavior."""
        summary = EffectSummary(effects=Effect.READ_LOCAL | Effect.READ_GLOBAL)
        assert summary.is_read_only is True
        summary_write = EffectSummary(effects=Effect.WRITE_LOCAL)
        assert summary_write.is_read_only is False

    def test_merge_with(self) -> None:
        """Test merge_with behavior."""
        s1 = EffectSummary(
            effects=Effect.READ_LOCAL,
            reads_globals=frozenset(["g1"])
        )
        s2 = EffectSummary(
            effects=Effect.WRITE_LOCAL,
            reads_globals=frozenset(["g2"])
        )
        merged = s1.merge_with(s2)
        assert merged.effects == (Effect.READ_LOCAL | Effect.WRITE_LOCAL)
        assert "g1" in merged.reads_globals and "g2" in merged.reads_globals

class TestCallSiteInfo:
    """Test suite for pysymex.analysis.cross_function.types.CallSiteInfo."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        cs = CallSiteInfo("caller", "callee", 10, 20)
        assert cs.caller == "caller"
        assert cs.callee == "callee"
        assert cs.line == 10
        assert cs.pc == 20

class TestCallGraphNode:
    """Test suite for pysymex.analysis.cross_function.types.CallGraphNode."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        node = CallGraphNode("my_func", "pkg.my_func")
        assert node.name == "my_func"
        assert node.qualified_name == "pkg.my_func"
        assert len(node.callees) == 0

class TestCallContext:
    """Test suite for pysymex.analysis.cross_function.types.CallContext."""
    def test_extend(self) -> None:
        """Test extend behavior."""
        ctx = CallContext()
        ctx2 = ctx.extend("f1", 10, k=2)
        assert len(ctx2.call_string) == 1
        assert ctx2.call_string[0] == ("f1", 10)
        
        ctx3 = ctx2.extend("f2", 20, k=2)
        assert len(ctx3.call_string) == 2
        
        ctx4 = ctx3.extend("f3", 30, k=2)
        assert len(ctx4.call_string) == 2
        assert ctx4.call_string[0] == ("f2", 20)
        assert ctx4.call_string[1] == ("f3", 30)

class TestContextSensitiveSummary:
    """Test suite for pysymex.analysis.cross_function.types.ContextSensitiveSummary."""
    def test_initialization(self) -> None:
        """Test basic initialization."""
        ctx = CallContext()
        summary = ContextSensitiveSummary(context=ctx, function="f")
        assert summary.function == "f"
        assert summary.context == ctx
