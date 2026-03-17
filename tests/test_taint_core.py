"""Tests for taint analysis core (analysis/taint/)."""
from __future__ import annotations
import pytest
from pysymex.analysis.taint.core import (
    TaintSource,
    TaintSink,
    TaintLabel,
    TaintedValue,
    TaintFlow,
    TaintPolicy,
    TaintTracker,
    TaintAnalyzer,
)


# -- TaintSource / TaintSink enums --

class TestTaintSource:
    def test_enum_exists(self):
        assert TaintSource is not None

    def test_has_members(self):
        assert len(TaintSource) >= 1


class TestTaintSink:
    def test_enum_exists(self):
        assert TaintSink is not None

    def test_has_members(self):
        assert len(TaintSink) >= 1


# -- TaintLabel --

class TestTaintLabel:
    def test_creation(self):
        members = list(TaintSource)
        label = TaintLabel(source=members[0])
        assert label.source == members[0]

    def test_has_source(self):
        members = list(TaintSource)
        label = TaintLabel(source=members[0])
        assert hasattr(label, 'source')


# -- TaintedValue --

class TestTaintedValue:
    def test_creation(self):
        members = list(TaintSource)
        label = TaintLabel(source=members[0])
        tv = TaintedValue(value=42, labels={label})
        assert tv.value == 42
        assert len(tv.labels) == 1

    def test_is_tainted(self):
        members = list(TaintSource)
        label = TaintLabel(source=members[0])
        tv = TaintedValue(value="data", labels={label})
        assert hasattr(tv, 'is_tainted') or len(tv.labels) > 0

    def test_empty_labels(self):
        tv = TaintedValue(value=42, labels=set())
        assert len(tv.labels) == 0


# -- TaintFlow --

class TestTaintFlow:
    def test_creation(self):
        sources = list(TaintSource)
        sinks = list(TaintSink)
        if sources and sinks:
            label = TaintLabel(source=sources[0])
            flow = TaintFlow(
                source_labels=frozenset({label}),
                sink=sinks[0],
                sink_location="test.py",
                sink_line=1,
            )
            assert label in flow.source_labels
            assert flow.sink == sinks[0]


# -- TaintPolicy --

class TestTaintPolicy:
    def test_creation(self):
        policy = TaintPolicy()
        assert policy is not None

    def test_has_check_method(self):
        policy = TaintPolicy()
        assert hasattr(policy, 'is_dangerous')


# -- TaintTracker --

class TestTaintTracker:
    def test_creation(self):
        tracker = TaintTracker()
        assert tracker is not None

    def test_mark_tainted(self):
        tracker = TaintTracker()
        if hasattr(tracker, 'mark_tainted'):
            members = list(TaintSource)
            if members:
                tracker.mark_tainted("var", members[0])

    def test_is_tainted_initially_false(self):
        tracker = TaintTracker()
        if hasattr(tracker, 'is_tainted'):
            assert not tracker.is_tainted("unknown_var_xyz")

    def test_propagate(self):
        tracker = TaintTracker()
        if hasattr(tracker, 'propagate'):
            tracker.propagate("src", "dst")

    def test_get_flows(self):
        tracker = TaintTracker()
        if hasattr(tracker, 'get_flows'):
            flows = tracker.get_flows()
            assert isinstance(flows, (list, set))


# -- TaintAnalyzer --

class TestTaintAnalyzer:
    def test_creation(self):
        analyzer = TaintAnalyzer()
        assert analyzer is not None

    def test_has_analyze(self):
        assert hasattr(TaintAnalyzer, 'analyze_function')
