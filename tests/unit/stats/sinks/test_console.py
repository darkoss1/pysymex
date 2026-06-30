from __future__ import annotations

from unittest.mock import MagicMock, patch

from pysymex._internal.stats.sinks.console import (
    ConsoleSink,
    format_metric_value,
    plain_text_metrics,
)


class TestConsoleSink:
    """Test suite for stats/sinks/console.py."""

    def test_write_updates_last_metrics(self) -> None:
        """Verify that write() stores the latest metrics snapshot."""
        sink = ConsoleSink()
        metrics: dict[str, float | int | str] = {"foo": 3.14159265}
        sink.write(metrics)
        assert sink.last_metrics == {"foo": 3.14159265}

    def test_write_updates_live_display_when_active(self) -> None:
        """Verify that write() calls live.update() when the live display is active."""
        sink = ConsoleSink()
        mock_live = MagicMock()
        sink.live = mock_live
        metrics: dict[str, float | int | str] = {"total_paths_explored": 42.0}
        sink.write(metrics)
        mock_live.update.assert_called_once()

    def test_write_does_not_crash_without_live(self) -> None:
        """Verify that write() works silently when live display is not started."""
        sink = ConsoleSink()
        metrics: dict[str, float | int | str] = {"status": "ok"}
        sink.write(metrics)
        assert sink.last_metrics == {"status": "ok"}

    def test_start_initializes_live_display(self) -> None:
        """Verify that start() sets up the Rich Live context."""
        sink = ConsoleSink()
        with patch("rich.live.Live") as mock_live_cls:
            mock_live_instance = MagicMock()
            mock_live_cls.return_value = mock_live_instance
            with patch("rich.console.Console"):
                sink.start()
                mock_live_instance.start.assert_called_once()
                # Cleanup
        sink.live = None
        sink.started = False

    def test_stop_prints_final_summary_when_live_is_none(self) -> None:
        """Verify that stop() prints a final summary when live is None."""
        sink = ConsoleSink()
        sink.started = True
        sink.last_metrics = {"total_paths_explored": 100.0}
        sink.live = None
        with patch.object(sink, "_print_final_summary") as mock_summary:
            sink.stop()
            mock_summary.assert_called_once_with({"total_paths_explored": 100.0})
        assert sink.live is None

    def test_stop_updates_and_stops_live(self) -> None:
        """Verify that stop() updates and stops live when active."""
        sink = ConsoleSink()
        sink.started = True
        sink.last_metrics = {"total_paths_explored": 100.0}
        mock_live = MagicMock()
        sink.live = mock_live
        with patch.object(sink, "_print_final_summary") as mock_summary:
            sink.stop()
            mock_summary.assert_not_called()
        mock_live.update.assert_called_once()
        mock_live.stop.assert_called_once()
        assert sink.live is None

    def test_stop_idempotent(self) -> None:
        """Verify that calling stop() when not started is a no-op."""
        sink = ConsoleSink()
        sink.stop()  # Should not raise

    def test_format_metric_value_float_memory(self) -> None:
        """Verify memory metrics are formatted with 1 decimal and unit."""
        result = format_metric_value("max_memory_mb", 123.456)
        assert result == "123.5 MB"

    def test_format_metric_value_float_rate(self) -> None:
        """Verify rate metrics include unit suffix."""
        result = format_metric_value("path_exploration_rate", 1234.5)
        assert result == "1,234.5 paths/s"

    def test_plain_text_metrics_uses_honest_solver_labels(self) -> None:
        """Verify solver counters use explicit human-facing labels."""
        rendered = plain_text_metrics(
            {
                "solver_queries": 3,
                "solver_unknown": 1,
            }
        )
        assert "Solver Queries" in rendered
        assert "Solver Unknown" in rendered

    def test_format_metric_value_int(self) -> None:
        """Verify integer values are formatted directly."""
        result = format_metric_value("total_paths_explored", 42)
        assert result == "42"

    def test_format_metric_value_string(self) -> None:
        """Verify string values are passed through."""
        result = format_metric_value("status", "ok")
        assert result == "ok"

    def test_plain_text_metrics_formats_correctly(self) -> None:
        """Verify the plain-text fallback produces a readable format."""
        metrics: dict[str, float | int | str] = {
            "total_paths_explored": 100.0,
            "max_memory_mb": 50.5,
        }
        output = plain_text_metrics(metrics)
        assert "=== Engine Statistics ===" in output
        assert "Paths Explored" in output
        assert "Peak Memory" in output

    def test_plain_text_metrics_float_format(self) -> None:
        """Verify plain-text fallback formats floats with 4 decimal places."""
        metrics: dict[str, float | int | str] = {"foo": 3.14159265}
        output = plain_text_metrics(metrics)
        assert "3.1416" in output

    def test_plain_text_metrics_string_format(self) -> None:
        """Verify plain-text fallback formats strings correctly."""
        metrics: dict[str, float | int | str] = {"status": "ok"}
        output = plain_text_metrics(metrics)
        assert "status" in output.lower() or "Status" in output
        assert "ok" in output

    def test_build_table_returns_rich_panel(self) -> None:
        """Verify build_table produces a Rich Panel object."""
        from rich.panel import Panel

        metrics: dict[str, float | int | str] = {"total_paths_explored": 42.0}
        panel = ConsoleSink.build_table(metrics)
        assert isinstance(panel, Panel)

    def test_build_table_empty_metrics(self) -> None:
        """Verify build_table handles empty metrics gracefully."""
        from rich.panel import Panel

        panel = ConsoleSink.build_table({})
        assert isinstance(panel, Panel)
