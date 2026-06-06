# pyright: reportUnknownVariableType=false, reportUnknownArgumentType=false, reportUnknownMemberType=false
"""Tests for tracing analyzer filter pipeline composition and basic CLI filters."""

from __future__ import annotations

from pysymex.tracing.analyzer.pipeline import FilterPipeline, build_pipeline
from tests.unit.tracing.analyzer.pipeline_args import make_pipeline_args


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


class TestBuildPipeline:
    """Tests for build_pipeline from CLI args."""

    def test_event_type_filter(self) -> None:
        """--event-type filters by event_type."""
        pipeline = build_pipeline(make_pipeline_args(event_type=["step"]))
        assert pipeline.matches({"event_type": "step"}) is True
        assert pipeline.matches({"event_type": "issue"}) is False

    def test_opcode_filter(self) -> None:
        """--opcode filters by opcode."""
        pipeline = build_pipeline(make_pipeline_args(opcode="LOAD_ATTR"))
        assert pipeline.matches({"opcode": "LOAD_ATTR"}) is True
        assert pipeline.matches({"opcode": "STORE_FAST"}) is False

    def test_seq_filter(self) -> None:
        """--seq filters by exact seq number."""
        pipeline = build_pipeline(make_pipeline_args(seq=42))
        assert pipeline.matches({"seq": 42}) is True
        assert pipeline.matches({"seq": 43}) is False

    def test_seq_range_filter_includes_zero(self) -> None:
        """--seq-range treats seq=0 as a real sequence number."""
        pipeline = build_pipeline(make_pipeline_args(seq_range=(0, 0)))
        assert pipeline.matches({"seq": 0}) is True
        assert pipeline.matches({"seq": 1}) is False

    def test_path_id_filter(self) -> None:
        """--path-id filters by path_id."""
        pipeline = build_pipeline(make_pipeline_args(path_id=3))
        assert pipeline.matches({"path_id": 3}) is True
        assert pipeline.matches({"path_id": 4}) is False

    def test_pc_range_filter_includes_zero(self) -> None:
        """--pc-range treats pc=0 as a real program counter."""
        pipeline = build_pipeline(make_pipeline_args(pc_range=(0, 0)))
        assert pipeline.matches({"pc": 0}) is True
        assert pipeline.matches({"pc": 2}) is False

    def test_depth_min_filter(self) -> None:
        """--depth-min filters by minimum depth."""
        pipeline = build_pipeline(make_pipeline_args(depth_min=10))
        assert pipeline.matches({"depth": 15}) is True
        assert pipeline.matches({"depth": 5}) is False

    def test_depth_max_filter_includes_zero(self) -> None:
        """--depth-max treats depth=0 as a real depth."""
        pipeline = build_pipeline(make_pipeline_args(depth_max=0))
        assert pipeline.matches({"depth": 0}) is True
        assert pipeline.matches({"depth": 1}) is False

    def test_solver_latency_range_includes_zero(self) -> None:
        """Solver latency bounds treat 0.0 ms as a real measurement."""
        pipeline = build_pipeline(
            make_pipeline_args(solver_latency_min=0.0, solver_latency_max=0.0)
        )
        assert pipeline.matches({"solver_latency_ms": 0.0}) is True
        assert pipeline.matches({"solver_latency_ms": 1.0}) is False

    def test_step_latency_range_includes_zero(self) -> None:
        """Step latency bounds treat 0.0 ms as a real measurement."""
        pipeline = build_pipeline(make_pipeline_args(step_latency_min=0.0, step_latency_max=0.0))
        assert pipeline.matches({"step_latency_ms": 0.0}) is True
        assert pipeline.matches({"step_latency_ms": 1.0}) is False

    def test_confidence_range_includes_zero(self) -> None:
        """Issue confidence bounds treat 0.0 as a real score."""
        pipeline = build_pipeline(make_pipeline_args(confidence=(0.0, 0.0)))
        assert pipeline.matches({"confidence": 0.0}) is True
        assert pipeline.matches({"confidence": 0.5}) is False
