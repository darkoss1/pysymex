# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""SQLite stats sink for historical metrics persistence.

Saves metrics directly to a local SQLite database using Write-Ahead Logging (WAL)
mode to handle concurrent reads/writes and background flushing.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .base import StatsSink


class SQLiteSink(StatsSink):
    """Historical persistence layer (WAL enabled)."""

    def __init__(self, db_path: str = "~/.pysymex/stats.db") -> None:
        """Initialize the SQLite statistics sink.

        Expands the target database path, ensures containing directories (and their
        corresponding .gitignore files) exist, establishes the connection with WAL mode
        enabled, and creates the metrics schema.

        Args:
            db_path: Path where the SQLite stats database file is stored.
        """
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        from pysymex.pathing import ensure_pysymex_gitignore

        ensure_pysymex_gitignore(self.db_path.parent)
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._setup_schema()

    def _setup_schema(self) -> None:
        """Initialize the database schema for persisting metrics.

        Creates the 'metrics' table if it does not exist and builds an index on
        the metric name key to accelerate analytical queries.
        """
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    key TEXT NOT NULL,
                    value REAL,
                    string_value TEXT
                )
            """)
            self.conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_key ON metrics(key)")

    def write(self, metrics: dict[str, float | int | str]) -> None:
        """Persist a snapshot of metrics to the SQLite database.

        Classifies metrics into numeric and string values and bulk inserts them into
        the database within a single transaction.

        Args:
            metrics: A dictionary containing metric name keys mapped to float, int, or
                str values.
        """
        cursor = self.conn.cursor()
        numeric_values: list[tuple[str, float]] = []
        string_values: list[tuple[str, str]] = []

        for k, v in metrics.items():
            if isinstance(v, (int, float)):
                numeric_values.append((k, float(v)))
            else:
                string_values.append((k, str(v)))

        if numeric_values:
            cursor.executemany("INSERT INTO metrics (key, value) VALUES (?, ?)", numeric_values)
        if string_values:
            cursor.executemany(
                "INSERT INTO metrics (key, string_value) VALUES (?, ?)", string_values
            )

        self.conn.commit()
