from __future__ import annotations

from unittest.mock import patch

from pysymex.stats.sinks.console import ConsoleSink


class TestConsoleSink:
    """Test suite for stats/sinks/console.py."""

    def test_write_prints_float_formatted(self) -> None:
        """Verify that ConsoleSink formats floats with 4 decimal places."""
        sink = ConsoleSink()
        metrics: dict[str, float | int | str] = {"foo": 3.14159265}

        with patch("builtins.print") as mock_print:
            sink.write(metrics)

        mock_print.assert_called_once()
        args, _ = mock_print.call_args
        output = args[0]
        assert "foo: 3.1416" in output

    def test_write_prints_string_formatted(self) -> None:
        """Verify that ConsoleSink formats strings correctly."""
        sink = ConsoleSink()
        metrics: dict[str, float | int | str] = {"status": "ok"}

        with patch("builtins.print") as mock_print:
            sink.write(metrics)

        mock_print.assert_called_once()
        args, _ = mock_print.call_args
        output = args[0]
        assert "status: ok" in output
