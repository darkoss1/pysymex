# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownMemberType=false
"""Tests for pysymex.tracing.analyzer.stream — JSONL trace streaming and formatting."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pysymex.tracing.analyzer.stream import (
    stream_events,
    SummaryAccumulator,
    format_pretty,
    format_fields,
)


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

    def test_reads_utf8_bom_file(self, tmp_path: Path) -> None:
        """UTF-8 BOM on first line is ignored."""
        f = tmp_path / "trace.jsonl"
        f.write_text('\ufeff{"seq":1}\n{"seq":2}\n', encoding="utf-8")
        rows = list(stream_events(str(f)))
        assert len(rows) == 2
        assert rows[0][1]["seq"] == 1

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

    def test_render_includes_latency_tables(self) -> None:
        """render() includes latency aggregates when latency fields are present."""
        acc = SummaryAccumulator()
        acc.record(
            {
                "event_type": "step",
                "seq": 1,
                "path_id": 7,
                "opcode": "LOAD_FAST",
                "step_latency_ms": 1.0,
            }
        )
        acc.record(
            {
                "event_type": "step",
                "seq": 2,
                "path_id": 7,
                "opcode": "LOAD_FAST",
                "step_latency_ms": 3.0,
            }
        )
        acc.record(
            {
                "event_type": "solve",
                "seq": 3,
                "path_id": 9,
                "result": "sat",
                "cache_hit": True,
                "solver_latency_ms": 10.0,
            }
        )

        text = acc.render()

        assert "Latency Summary" in text
        assert "Solver Outcomes" in text
        assert "Cache hit rate: 100.0%" in text
        assert "Slowest Paths" in text
        assert "Slowest Step Opcodes" in text
        assert "LOAD_FAST" in text
        assert "2.000" in text

    def test_render_includes_path_feasibility_policy_latency(self) -> None:
        acc = SummaryAccumulator()
        acc.record(
            {
                "event_type": "path_feasibility",
                "seq": 4,
                "path_id": 10,
                "policy_latency_ms": 2.5,
            }
        )

        text = acc.render()

        assert "path_feasibility" in text
        assert "2.500" in text

    def test_render_includes_deep_diagnostic_outcomes(self) -> None:
        acc = SummaryAccumulator()
        acc.record(
            {
                "event_type": "detector_query",
                "seq": 10,
                "pc": 44,
                "source_line": 91,
                "detector_name": "KeyErrorDetector",
                "issue_kind": "KEY_ERROR",
                "result": False,
                "result_source": "inconclusive_prefix_unknown",
            }
        )
        acc.record(
            {
                "event_type": "path_feasibility",
                "seq": 11,
                "result": "inconclusive",
                "result_source": "solver_unknown",
            }
        )
        acc.record(
            {
                "event_type": "fallback",
                "seq": 12,
                "label": "solver_unknown_detector_query",
                "kind": "unknown",
            }
        )

        text = acc.render()

        assert "Detector Query Outcomes" in text
        assert "inconclusive_prefix_unknown" in text
        assert "Path Feasibility Outcomes" in text
        assert "Uncertain Detector Sites" in text
        assert "KeyErrorDetector" in text
        assert "KEY_ERROR" in text
        assert "Fallback Labels" in text
        assert "solver_unknown_detector_query" in text


class TestFormatFunctions:
    """Tests for output formatting."""

    def test_format_pretty(self) -> None:
        """_format_pretty produces indented JSON."""
        event: dict[str, object] = {"seq": 1, "event_type": "step"}
        result: Any = format_pretty(event)
        parsed = json.loads(result)
        assert parsed["seq"] == 1

    def test_format_fields(self) -> None:
        """_format_fields extracts only requested fields."""
        event: dict[str, object] = {"seq": 1, "event_type": "step", "pc": 10}
        result: Any = format_fields(event, ["seq", "pc"])
        parsed = json.loads(result)
        assert "seq" in parsed
        assert "pc" in parsed
        assert "event_type" not in parsed
