"""Tests for pysymex.tracing.analyzer — filter pipeline, stream_events, helpers."""

from __future__ import annotations

import json
from pathlib import Path

from pysymex.tracing.analyzer import (
    FilterPipeline,
    SummaryAccumulator,
    _as_dict,
    _as_float,
    _as_int,
    _as_list,
    _as_str,
    _constraints_contain,
    _format_fields,
    _format_pretty,
    _has_stack_pop,
    _is_object_dict,
    _is_object_list,
    _list_contains,
    _str_contains,
    build_parser,
    build_pipeline,
    stream_events,
)


class TestFilterPipeline:
    """Tests for FilterPipeline composable chain."""

    def test_empty_pipeline_matches_all(self) -> None:
        """Empty pipeline accepts everything."""
        p = FilterPipeline()
        assert p.matches({"event_type": "step"}) is True

    def test_add_single_filter(self) -> None:
        """Single filter works."""
        p = FilterPipeline()
        p.add(lambda e: e.get("event_type") == "step")
        assert p.matches({"event_type": "step"}) is True
        assert p.matches({"event_type": "issue"}) is False

    def test_add_multiple_filters_and_conjunction(self) -> None:
        """Multiple filters are AND-ed."""
        p = FilterPipeline()
        p.add(lambda e: e.get("event_type") == "step")
        p.add(lambda e: e.get("pc") == 3)
        assert p.matches({"event_type": "step", "pc": 3}) is True
        assert p.matches({"event_type": "step", "pc": 5}) is False

    def test_len(self) -> None:
        """len() returns number of filters."""
        p = FilterPipeline()
        assert len(p) == 0
        p.add(lambda e: True)
        assert len(p) == 1


class TestStreamEvents:
    """Tests for stream_events JSONL reader."""

    def test_reads_valid_jsonl(self, tmp_path: Path) -> None:
        """Reads valid JSONL lines."""
        f = tmp_path / "trace.jsonl"
        f.write_text('{"seq":1}\n{"seq":2}\n', encoding="utf-8")
        rows = list(stream_events(str(f)))
        assert len(rows) == 2
        assert rows[0][1]["seq"] == 1
        assert rows[1][1]["seq"] == 2

    def test_skips_blank_lines(self, tmp_path: Path) -> None:
        """Blank lines are skipped."""
        f = tmp_path / "trace.jsonl"
        f.write_text('{"seq":1}\n\n{"seq":2}\n', encoding="utf-8")
        rows = list(stream_events(str(f)))
        assert len(rows) == 2

    def test_skips_malformed_json(self, tmp_path: Path) -> None:
        """Malformed JSON lines are skipped."""
        f = tmp_path / "trace.jsonl"
        f.write_text('{"seq":1}\nnot-json\n{"seq":2}\n', encoding="utf-8")
        rows = list(stream_events(str(f)))
        assert len(rows) == 2

    def test_empty_file(self, tmp_path: Path) -> None:
        """Empty file yields nothing."""
        f = tmp_path / "trace.jsonl"
        f.write_text("", encoding="utf-8")
        rows = list(stream_events(str(f)))
        assert rows == []


class TestHelperFunctions:
    """Tests for _str_contains, _list_contains, _as_dict, etc."""

    def test_str_contains_true(self) -> None:
        """Returns True when substring found."""
        assert _str_contains("hello world", "world") is True

    def test_str_contains_false(self) -> None:
        """Returns False when substring not found."""
        assert _str_contains("hello", "world") is False

    def test_str_contains_none(self) -> None:
        """Returns False for None."""
        assert _str_contains(None, "x") is False

    def test_list_contains_true(self) -> None:
        """Returns True when item found."""
        assert _list_contains(["abc", "def"], "ab") is True

    def test_list_contains_false(self) -> None:
        """Returns False when item not found."""
        assert _list_contains(["abc", "def"], "xyz") is False

    def test_list_contains_none(self) -> None:
        """Returns False for None."""
        assert _list_contains(None, "x") is False

    def test_constraints_contain_true(self) -> None:
        """Finds substring in constraint smtlib field."""
        constraints: list[object] = [{"smtlib": "(> x 0)"}]
        assert _constraints_contain(constraints, "x") is True

    def test_constraints_contain_false(self) -> None:
        """Returns False when not found."""
        constraints: list[object] = [{"smtlib": "(> y 0)"}]
        assert _constraints_contain(constraints, "x") is False

    def test_constraints_contain_empty(self) -> None:
        """Returns False for empty list."""
        assert _constraints_contain([], "x") is False

    def test_as_dict_returns_dict(self) -> None:
        """_as_dict normalizes a dict."""
        result = _as_dict({"a": 1})
        assert result is not None
        assert result["a"] == 1

    def test_as_dict_returns_none_for_non_dict(self) -> None:
        """_as_dict returns None for non-dict."""
        assert _as_dict([1, 2]) is None

    def test_as_list_returns_list(self) -> None:
        """_as_list returns list for list."""
        result = _as_list([1, 2])
        assert result == [1, 2]

    def test_as_list_returns_none_for_non_list(self) -> None:
        """_as_list returns None for non-list."""
        assert _as_list({"a": 1}) is None

    def test_as_str(self) -> None:
        """_as_str returns str for str, None otherwise."""
        assert _as_str("hello") == "hello"
        assert _as_str(123) is None

    def test_as_int(self) -> None:
        """_as_int returns int for int, None otherwise."""
        assert _as_int(42) == 42
        assert _as_int("42") is None

    def test_as_float(self) -> None:
        """_as_float returns float for numeric, None otherwise."""
        assert _as_float(3.14) == 3.14
        assert _as_float(5) == 5.0
        assert _as_float("x") is None

    def test_has_stack_pop_true(self) -> None:
        """_has_stack_pop returns True when popped > 0."""
        event: dict[str, object] = {"stack_diff": {"popped": 2}}
        assert _has_stack_pop(event) is True

    def test_has_stack_pop_false(self) -> None:
        """_has_stack_pop returns False when no stack_diff."""
        assert _has_stack_pop({}) is False

    def test_is_object_dict(self) -> None:
        """_is_object_dict returns True for dict."""
        assert _is_object_dict({"a": 1}) is True
        assert _is_object_dict([1]) is False

    def test_is_object_list(self) -> None:
        """_is_object_list returns True for list."""
        assert _is_object_list([1]) is True
        assert _is_object_list({"a": 1}) is False


class TestFormatFunctions:
    """Tests for output formatting."""

    def test_format_pretty(self) -> None:
        """_format_pretty produces indented JSON."""
        event: dict[str, object] = {"seq": 1, "event_type": "step"}
        result = _format_pretty(event)
        parsed = json.loads(result)
        assert parsed["seq"] == 1

    def test_format_fields(self) -> None:
        """_format_fields extracts only requested fields."""
        event: dict[str, object] = {"seq": 1, "event_type": "step", "pc": 10}
        result = _format_fields(event, ["seq", "pc"])
        parsed = json.loads(result)
        assert "seq" in parsed
        assert "pc" in parsed
        assert "event_type" not in parsed


class TestSummaryAccumulator:
    """Tests for SummaryAccumulator statistics."""

    def test_empty(self) -> None:
        """Empty accumulator has zero total."""
        acc = SummaryAccumulator()
        assert acc.total == 0

    def test_record(self) -> None:
        """record() increments counters."""
        acc = SummaryAccumulator()
        acc.record({"event_type": "step", "seq": 1})
        acc.record({"event_type": "step", "seq": 2})
        acc.record({"event_type": "issue", "seq": 3})
        assert acc.total == 3
        assert acc.by_type["step"] == 2
        assert acc.by_type["issue"] == 1

    def test_first_last_seq(self) -> None:
        """first_seq and last_seq are tracked per type."""
        acc = SummaryAccumulator()
        acc.record({"event_type": "step", "seq": 10})
        acc.record({"event_type": "step", "seq": 20})
        assert acc.first_seq["step"] == 10
        assert acc.last_seq["step"] == 20

    def test_render(self) -> None:
        """render() produces markdown-style table."""
        acc = SummaryAccumulator()
        acc.record({"event_type": "step", "seq": 1})
        text = acc.render()
        assert "pysymex Trace Summary" in text
        assert "step" in text


class TestBuildPipeline:
    """Tests for build_pipeline from CLI args."""

    def test_event_type_filter(self) -> None:
        """--event-type filters by event_type."""
        parser = build_parser()
        args = parser.parse_args(["--event-type", "step"])
        pipeline = build_pipeline(args)
        assert pipeline.matches({"event_type": "step"}) is True
        assert pipeline.matches({"event_type": "issue"}) is False

    def test_opcode_filter(self) -> None:
        """--opcode filters by opcode."""
        parser = build_parser()
        args = parser.parse_args(["--opcode", "LOAD_ATTR"])
        pipeline = build_pipeline(args)
        assert pipeline.matches({"opcode": "LOAD_ATTR"}) is True
        assert pipeline.matches({"opcode": "STORE_FAST"}) is False

    def test_seq_filter(self) -> None:
        """--seq filters by exact seq number."""
        parser = build_parser()
        args = parser.parse_args(["--seq", "42"])
        pipeline = build_pipeline(args)
        assert pipeline.matches({"seq": 42}) is True
        assert pipeline.matches({"seq": 43}) is False

    def test_path_id_filter(self) -> None:
        """--path-id filters by path_id."""
        parser = build_parser()
        args = parser.parse_args(["--path-id", "3"])
        pipeline = build_pipeline(args)
        assert pipeline.matches({"path_id": 3}) is True
        assert pipeline.matches({"path_id": 4}) is False

    def test_depth_min_filter(self) -> None:
        """--depth-min filters by minimum depth."""
        parser = build_parser()
        args = parser.parse_args(["--depth-min", "10"])
        pipeline = build_pipeline(args)
        assert pipeline.matches({"depth": 15}) is True
        assert pipeline.matches({"depth": 5}) is False
