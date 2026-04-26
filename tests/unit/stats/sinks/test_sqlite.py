from __future__ import annotations

import pathlib
import sqlite3
from typing import Generator

import pytest

from pysymex.stats.sinks.sqlite import SQLiteSink


class TestSQLiteSink:
    """Test suite for stats/sinks/sqlite.py."""

    def test_initialization_creates_db_and_schema(self, tmp_path: pathlib.Path) -> None:
        """Verify that SQLiteSink initializes, creates file and schema."""
        db_path = tmp_path / "stats.db"
        sink = SQLiteSink(str(db_path))

        assert db_path.exists()

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='metrics'")
        assert cursor.fetchone() is not None

    def test_write_inserts_numeric_metrics(self, tmp_path: pathlib.Path) -> None:
        """Verify that numeric metrics are inserted into the value column."""
        db_path = tmp_path / "stats.db"
        sink = SQLiteSink(str(db_path))

        metrics: dict[str, float | int | str] = {"mem": 1024, "rate": 2.5}
        sink.write(metrics)

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT key, value, string_value FROM metrics ORDER BY key")
        rows = cursor.fetchall()

        assert len(rows) == 2
        assert rows[0] == ("mem", 1024.0, None)
        assert rows[1] == ("rate", 2.5, None)

    def test_write_inserts_string_metrics(self, tmp_path: pathlib.Path) -> None:
        """Verify that string metrics are inserted into the string_value column."""
        db_path = tmp_path / "stats.db"
        sink = SQLiteSink(str(db_path))

        metrics: dict[str, float | int | str] = {"status": "success"}
        sink.write(metrics)

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT key, value, string_value FROM metrics")
        rows = cursor.fetchall()

        assert len(rows) == 1
        assert rows[0] == ("status", None, "success")
