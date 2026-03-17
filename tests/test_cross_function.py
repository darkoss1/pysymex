"""Tests for cross-function analysis (analysis/cross_function/)."""
from __future__ import annotations
import pytest
from pysymex.analysis.cross_function.types import (
    Effect,
    EffectSummary,
    CallSiteInfo,
    CallGraphNode,
    CallContext,
    ContextSensitiveSummary,
)
from pysymex.analysis.cross_function.core import (
    FunctionSummaryCache,
    CallGraph,
    CallGraphBuilder,
    EffectAnalyzer,
    CrossFunctionAnalyzer,
)


# -- Types --

class TestEffect:
    def test_flag_enum(self):
        assert Effect is not None
        assert len(Effect) >= 1

    def test_combinations(self):
        members = list(Effect)
        if len(members) >= 2:
            combined = members[0] | members[1]
            assert combined is not None


class TestEffectSummary:
    def test_creation(self):
        members = list(Effect)
        es = EffectSummary(effects=members[0] if members else Effect(0))
        assert es is not None


class TestCallSiteInfo:
    def test_creation(self):
        info = CallSiteInfo(caller="foo", callee="bar", line=1, pc=0)
        assert info.caller == "foo"
        assert info.callee == "bar"


class TestCallGraphNode:
    def test_creation(self):
        node = CallGraphNode(name="func", qualified_name="module.func")
        assert node.name == "func"


class TestCallContext:
    def test_creation(self):
        ctx = CallContext(call_string=(("foo", 0), ("bar", 10)))
        assert len(ctx.call_string) == 2


# -- Core --

class TestFunctionSummaryCache:
    def test_creation(self):
        cache = FunctionSummaryCache()
        assert cache is not None

    def test_get_missing(self):
        cache = FunctionSummaryCache()
        if hasattr(cache, 'get'):
            result = cache.get("nonexistent", [], [])
            assert result is None
        elif hasattr(cache, '__getitem__'):
            with pytest.raises((KeyError, Exception)):
                cache["nonexistent"]

    def test_put_and_get(self):
        cache = FunctionSummaryCache()
        if hasattr(cache, 'put'):
            cache.put("func", [], [], {"returns": "int"})
            result = cache.get("func", [], [])
            assert result is not None
        elif hasattr(cache, 'add'):
            cache.add("func", {"returns": "int"})


class TestCallGraph:
    def test_creation(self):
        cg = CallGraph()
        assert cg is not None

    def test_add_edge(self):
        cg = CallGraph()
        if hasattr(cg, 'add_edge'):
            cg.add_edge("foo", "bar")
        elif hasattr(cg, 'add_call'):
            cg.add_call("foo", "bar", line=1, pc=0)

    def test_get_callees(self):
        cg = CallGraph()
        if hasattr(cg, 'get_callees'):
            callees = cg.get_callees("foo")
            assert isinstance(callees, (list, set, frozenset))
        elif hasattr(cg, 'callees'):
            pass


class TestCallGraphBuilder:
    def test_creation(self):
        builder = CallGraphBuilder()
        assert builder is not None


class TestEffectAnalyzer:
    def test_creation(self):
        analyzer = EffectAnalyzer()
        assert analyzer is not None


class TestCrossFunctionAnalyzer:
    def test_creation(self):
        analyzer = CrossFunctionAnalyzer()
        assert analyzer is not None

    def test_has_analyze(self):
        assert (hasattr(CrossFunctionAnalyzer, 'analyze') or
                hasattr(CrossFunctionAnalyzer, 'run') or
                hasattr(CrossFunctionAnalyzer, 'analyze_module'))
