from __future__ import annotations

from unittest.mock import MagicMock, patch

from pysymex.stats.sinks.console import (
    ConsoleSink,
    _format_metric_value,  # pyright: ignore[reportPrivateUsage]  # white-box test for format helper
    _plain_text_metrics,  # pyright: ignore[reportPrivateUsage]  # white-box test for fallback formatter
)


class TestConsoleSink:
    """Test suite for stats/sinks/console.py."""

    def test_write_updates_last_metrics(self) -> None:
        """Verify that write() stores the latest metrics snapshot."""
        sink = ConsoleSink()
        metrics: dict[str, float | int | str] = {"foo": 3.14159265}
        sink.write(metrics)
        assert sink._last_metrics == {"foo": 3.14159265}  # pyright: ignore[reportPrivateUsage]  # white-box test

    def test_write_updates_live_display_when_active(self) -> None:
        """Verify that write() calls live.update() when the live display is active."""
        sink = ConsoleSink()
        mock_live = MagicMock()
        sink._live = mock_live  # pyright: ignore[reportPrivateUsage]  # white-box test
        metrics: dict[str, float | int | str] = {"total_paths_explored": 42.0}
        sink.write(metrics)
        mock_live.update.assert_called_once()

    def test_write_does_not_crash_without_live(self) -> None:
        """Verify that write() works silently when live display is not started."""
        sink = ConsoleSink()
        metrics: dict[str, float | int | str] = {"status": "ok"}
        sink.write(metrics)
        assert sink._last_metrics == {"status": "ok"}  # pyright: ignore[reportPrivateUsage]  # white-box test

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
        sink._live = None  # pyright: ignore[reportPrivateUsage]  # white-box test cleanup
        sink._started = False  # pyright: ignore[reportPrivateUsage]  # white-box test cleanup

    def test_stop_prints_final_summary(self) -> None:
        """Verify that stop() prints a final summary of the last metrics."""
        sink = ConsoleSink()
        sink._started = True  # pyright: ignore[reportPrivateUsage]  # white-box test setup
        sink._last_metrics = {"total_paths_explored": 100.0}  # pyright: ignore[reportPrivateUsage]  # white-box test setup
        mock_live = MagicMock()
        sink._live = mock_live  # pyright: ignore[reportPrivateUsage]  # white-box test setup
        with patch.object(sink, "_print_final_summary") as mock_summary:
            sink.stop()
            mock_summary.assert_called_once_with({"total_paths_explored": 100.0})
        assert sink._live is None  # pyright: ignore[reportPrivateUsage]  # white-box test

    def test_stop_idempotent(self) -> None:
        """Verify that calling stop() when not started is a no-op."""
        sink = ConsoleSink()
        sink.stop()  # Should not raise

    def test_format_metric_value_float_memory(self) -> None:
        """Verify memory metrics are formatted with 1 decimal and unit."""
        result = _format_metric_value("max_memory_mb", 123.456)
        assert result == "123.5 MB"

    def test_format_metric_value_float_rate(self) -> None:
        """Verify rate metrics include unit suffix."""
        result = _format_metric_value("path_exploration_rate", 1234.5)
        assert result == "1,234.5 paths/s"

    def test_format_metric_value_ratio(self) -> None:
        """Verify ratio metrics are formatted with 4 decimal places."""
        result = _format_metric_value("sat_unsat_ratio", 0.75)
        assert result == "0.7500"

    def test_format_metric_value_int(self) -> None:
        """Verify integer values are formatted directly."""
        result = _format_metric_value("total_paths_explored", 42)
        assert result == "42"

    def test_format_metric_value_string(self) -> None:
        """Verify string values are passed through."""
        result = _format_metric_value("status", "ok")
        assert result == "ok"

    def test_plain_text_metrics_formats_correctly(self) -> None:
        """Verify the plain-text fallback produces a readable format."""
        metrics: dict[str, float | int | str] = {
            "total_paths_explored": 100.0,
            "max_memory_mb": 50.5,
        }
        output = _plain_text_metrics(metrics)
        assert "=== Engine Statistics ===" in output
        assert "Paths Explored" in output
        assert "Peak Memory" in output

    def test_plain_text_metrics_float_format(self) -> None:
        """Verify plain-text fallback formats floats with 4 decimal places."""
        metrics: dict[str, float | int | str] = {"foo": 3.14159265}
        output = _plain_text_metrics(metrics)
        assert "3.1416" in output

    def test_plain_text_metrics_string_format(self) -> None:
        """Verify plain-text fallback formats strings correctly."""
        metrics: dict[str, float | int | str] = {"status": "ok"}
        output = _plain_text_metrics(metrics)
        assert "status" in output.lower() or "Status" in output
        assert "ok" in output

    def test_build_table_returns_rich_table(self) -> None:
        """Verify _build_table produces a Rich Table object."""
        from rich.table import Table

        metrics: dict[str, float | int | str] = {"total_paths_explored": 42.0}
        table = ConsoleSink._build_table(metrics)  # pyright: ignore[reportPrivateUsage]  # white-box test
        assert isinstance(table, Table)

    def test_build_table_empty_metrics(self) -> None:
        """Verify _build_table handles empty metrics gracefully."""
        from rich.table import Table

        table = ConsoleSink._build_table({})  # pyright: ignore[reportPrivateUsage]  # white-box test
        assert isinstance(table, Table)
