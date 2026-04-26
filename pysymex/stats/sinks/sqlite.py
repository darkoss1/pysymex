# pysymex: Python Symbolic Execution & Formal Verification
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

from __future__ import annotations

import sqlite3
from pathlib import Path

from .base import StatsSink


class SQLiteSink(StatsSink):
    """Historical persistence layer (WAL enabled)."""

    def __init__(self, db_path: str = "~/.pysymex/stats.db") -> None:
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._setup_schema()

    def _setup_schema(self) -> None:
        with self._conn:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    key TEXT NOT NULL,
                    value REAL,
                    string_value TEXT
                )
            """)
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_key ON metrics(key)")

    def write(self, metrics: dict[str, float | int | str]) -> None:
        cursor = self._conn.cursor()
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

        self._conn.commit()
