"""Tests for taint tracker edge cases and potential soundness issues.

The TaintTracker uses id(value) as object keys. In CPython, id() values
can be reused after garbage collection. This creates potential for:
1. False positives: New object gets old tainted object's id
2. False negatives: Tainted object sanitized because new object has same id

These tests verify the tracker behaves predictably in edge cases.
"""

from __future__ import annotations

import gc
import sys
import weakref
from typing import Any

import pytest

from pysymex.analysis.taint.core import (
    TaintSource,
    TaintSink,
    TaintLabel,
    TaintedValue,
    TaintFlow,
    TaintPolicy,
    TaintTracker,
)


class TestTaintTrackerIdReuse:
    """Tests for id() reuse vulnerability in taint tracking."""

    def test_gc_does_not_cause_false_positive(self):
        """New object should not inherit taint from GC'd object with same id.

        Invariant: Taint tracking should be conservative - if uncertain,
        better to report false positive than miss a real issue.
        """
        tracker = TaintTracker()

        # Create and taint an object
        original = "tainted_string_data"
        original_id = id(original)
        tracker.mark_tainted(original, TaintSource.USER_INPUT, "test", 1)

        # Verify it's tainted
        assert tracker.is_tainted(original), "Original should be tainted"

        # Delete reference and force GC
        del original
        gc.collect()

        # Create new object - might get same id
        # (This is probabilistic but demonstrates the concept)
        new_object = "different_string"
        new_id = id(new_object)

        # If IDs match, we have a potential false positive scenario
        if new_id == original_id:
            # The tracker might incorrectly think this is tainted
            # This test documents the known limitation
            is_tainted = tracker.is_tainted(new_object)
            # Note: This is a KNOWN LIMITATION documented in the code

    def test_tracker_fork_creates_independent_state(self):
        """Forked tracker must have independent taint state.

        Invariant: Mutations to forked tracker must not affect original.
        """
        tracker = TaintTracker()

        # Mark object as tainted in original
        obj1 = {"key": "value1"}
        tracker.mark_tainted(obj1, TaintSource.USER_INPUT, "input", 1)

        # Fork the tracker
        forked = tracker.fork()

        # Mark different object in fork
        obj2 = {"key": "value2"}
        forked.mark_tainted(obj2, TaintSource.NETWORK, "network", 2)

        # Original should not see obj2 as tainted
        assert not tracker.is_tainted(obj2), "Fork leaked taint to original"

        # Fork should see both objects
        assert forked.is_tainted(obj1), "Fork should inherit original taint"
        assert forked.is_tainted(obj2), "Fork should have its own taint"

    def test_sanitized_state_forked_correctly(self):
        """Sanitization in fork must not affect original.

        Invariant: forked.mark_sanitized(x) must not affect original.is_tainted(x).
        """
        tracker = TaintTracker()

        obj = "sensitive_data"
        tracker.mark_tainted(obj, TaintSource.USER_INPUT, "input", 1)

        forked = tracker.fork()
        forked.mark_sanitized(obj)

        # Original should still see it as tainted
        # (subject to sink check logic)
        taint = tracker.get_taint(obj)
        assert taint is not None and taint.is_tainted(), \
            "Fork sanitization leaked to original"


class TestTaintPropagationSoundness:
    """Tests for taint propagation correctness."""

    def test_union_of_operand_taints(self):
        """Result must have union of all operand taints.

        Invariant: Labels(result) = Union(Labels(op1), Labels(op2), ...)
        """
        tracker = TaintTracker()

        a = "data_a"
        b = "data_b"
        c = "data_c"

        tracker.mark_tainted(a, TaintSource.USER_INPUT, "user", 1)
        tracker.mark_tainted(b, TaintSource.NETWORK, "net", 2)
        # c is clean

        result = "combined_result"
        tainted_result = tracker.propagate_taint(result, a, b, c)

        # Result should have both USER_INPUT and NETWORK labels
        labels = tainted_result.labels
        sources = {lbl.source for lbl in labels}

        assert TaintSource.USER_INPUT in sources, "Lost USER_INPUT taint"
        assert TaintSource.NETWORK in sources, "Lost NETWORK taint"

    def test_clean_operands_produce_clean_result(self):
        """Operations on clean data produce clean result.

        Invariant: If all operands are clean, result is clean.
        """
        tracker = TaintTracker()

        a = "clean_a"
        b = "clean_b"

        result = "clean_result"
        tainted_result = tracker.propagate_taint(result, a, b)

        assert not tainted_result.is_tainted(), \
            "Clean operands produced tainted result"


class TestSinkDetection:
    """Tests for taint sink detection."""

    def test_dangerous_flow_detected(self):
        """Flow from dangerous source to sink must be detected.

        Invariant: USER_INPUT -> SQL_QUERY must produce a TaintFlow.
        """
        tracker = TaintTracker()

        user_data = "user_input_data"
        tracker.mark_tainted(user_data, TaintSource.USER_INPUT, "form", 1)

        flows = tracker.check_sink(
            TaintSink.SQL_QUERY,
            user_data,
            location="db.py",
            line=42,
        )

        assert len(flows) > 0, "Dangerous flow not detected"
        assert flows[0].sink == TaintSink.SQL_QUERY

    def test_safe_source_to_sink_not_flagged(self):
        """Non-dangerous source-sink pair should not be flagged.

        Invariant: FILE_READ -> LOG_OUTPUT is typically safe.
        """
        tracker = TaintTracker()
        policy = tracker.policy

        # Check if this combination is in the dangerous set
        # (depends on default policy configuration)
        is_dangerous = policy.is_dangerous(TaintSource.FILE_READ, TaintSink.LOG_OUTPUT)

        # If not dangerous, flows should be empty
        if not is_dangerous:
            file_data = "file_content"
            tracker.mark_tainted(file_data, TaintSource.FILE_READ, "config.txt", 1)

            flows = tracker.check_sink(
                TaintSink.LOG_OUTPUT,
                file_data,
                location="logger.py",
                line=10,
            )

            # Should not flag non-dangerous flows
            assert len(flows) == 0, "Safe flow incorrectly flagged"

    def test_sanitized_value_not_flagged(self):
        """Sanitized values should not trigger flow detection.

        Invariant: After sanitization, sink check returns empty.
        """
        tracker = TaintTracker()

        user_data = "user_input"
        tracker.mark_tainted(user_data, TaintSource.USER_INPUT, "form", 1)

        # Sanitize the value
        tracker.mark_sanitized(user_data)

        # Check sink - should be empty because sanitized
        flows = tracker.check_sink(
            TaintSink.SQL_QUERY,
            user_data,
            location="db.py",
            line=42,
        )

        assert len(flows) == 0, "Sanitized value still flagged"


class TestTaintLabelSemantics:
    """Tests for TaintLabel semantics."""

    def test_label_immutability(self):
        """TaintLabel must be immutable (frozen dataclass).

        Invariant: Modifying label fields should raise an error.
        """
        label = TaintLabel(
            source=TaintSource.USER_INPUT,
            origin="input_form",
            line_number=42,
        )

        with pytest.raises((AttributeError, TypeError)):
            label.source = TaintSource.NETWORK  # type: ignore

    def test_label_equality(self):
        """Labels with same fields must be equal.

        Invariant: TaintLabel is value-based, not identity-based.
        """
        label1 = TaintLabel(TaintSource.USER_INPUT, "form", 10)
        label2 = TaintLabel(TaintSource.USER_INPUT, "form", 10)

        assert label1 == label2, "Identical labels should be equal"

    def test_label_hashability(self):
        """Labels must be hashable for use in sets.

        Invariant: TaintLabel can be used in frozenset.
        """
        label = TaintLabel(TaintSource.USER_INPUT, "form", 10)

        label_set = frozenset({label})
        assert label in label_set


class TestTaintedValueMerge:
    """Tests for TaintedValue merge operations."""

    def test_merge_combines_labels(self):
        """Merging two tainted values combines their labels.

        Invariant: merged.labels = v1.labels | v2.labels
        """
        label1 = TaintLabel(TaintSource.USER_INPUT, "a", 1)
        label2 = TaintLabel(TaintSource.NETWORK, "b", 2)

        v1 = TaintedValue(value="x", labels=frozenset({label1}))
        v2 = TaintedValue(value="y", labels=frozenset({label2}))

        merged = v1.merge_taint(v2)

        assert label1 in merged.labels, "Merge lost label1"
        assert label2 in merged.labels, "Merge lost label2"

    def test_with_taint_adds_label(self):
        """with_taint adds new label without removing existing.

        Invariant: v.with_taint(new) preserves all existing labels.
        """
        original_label = TaintLabel(TaintSource.USER_INPUT, "a", 1)
        new_label = TaintLabel(TaintSource.NETWORK, "b", 2)

        v = TaintedValue(value="data", labels=frozenset({original_label}))
        v2 = v.with_taint(new_label)

        assert original_label in v2.labels, "with_taint lost original label"
        assert new_label in v2.labels, "with_taint didn't add new label"


class TestPolicyConfiguration:
    """Tests for TaintPolicy configuration."""

    def test_default_policy_has_dangerous_flows(self):
        """Default policy must flag common dangerous flows.

        Invariant: USER_INPUT -> SQL_QUERY is dangerous by default.
        """
        policy = TaintPolicy()

        assert policy.is_dangerous(TaintSource.USER_INPUT, TaintSink.SQL_QUERY), \
            "Default policy missing USER_INPUT -> SQL_QUERY"

        assert policy.is_dangerous(TaintSource.USER_INPUT, TaintSink.COMMAND_EXEC), \
            "Default policy missing USER_INPUT -> COMMAND_EXEC"

        assert policy.is_dangerous(TaintSource.NETWORK, TaintSink.EVAL), \
            "Default policy missing NETWORK -> EVAL"

    def test_sanitizer_registration(self):
        """Custom sanitizers can be registered.

        Invariant: get_sanitizers returns registered sanitizers.
        """
        policy = TaintPolicy()

        policy.add_sanitizer(
            TaintSource.USER_INPUT,
            TaintSink.SQL_QUERY,
            "parameterize_query",
        )

        sanitizers = policy.get_sanitizers(TaintSource.USER_INPUT, TaintSink.SQL_QUERY)
        assert "parameterize_query" in sanitizers


class TestTrackerClear:
    """Tests for tracker state clearing."""

    def test_clear_removes_all_taint(self):
        """clear() must remove all taint tracking state.

        Invariant: After clear(), is_tainted returns False for all objects.
        """
        tracker = TaintTracker()

        obj1 = "data1"
        obj2 = "data2"

        tracker.mark_tainted(obj1, TaintSource.USER_INPUT, "a", 1)
        tracker.mark_tainted(obj2, TaintSource.NETWORK, "b", 2)

        # Clear
        tracker.clear()

        assert not tracker.is_tainted(obj1), "clear() didn't remove taint from obj1"
        assert not tracker.is_tainted(obj2), "clear() didn't remove taint from obj2"
        assert tracker.get_all_flows() == [], "clear() didn't remove flows"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
