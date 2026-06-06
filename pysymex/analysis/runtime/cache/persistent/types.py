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

"""SQLite schema DDL and row model for the persistent cache."""

from __future__ import annotations

import time
from dataclasses import dataclass

PERSISTENT_CACHE_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    key TEXT PRIMARY KEY,
    key_type TEXT NOT NULL,
    value_hash TEXT NOT NULL,
    value_blob BLOB NOT NULL,
    created_at REAL NOT NULL,
    accessed_at REAL NOT NULL,
    access_count INTEGER DEFAULT 1,
    dependencies TEXT DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS cache_deps (
    cache_key TEXT NOT NULL,
    dependency TEXT NOT NULL,
    PRIMARY KEY (cache_key, dependency),
    FOREIGN KEY (cache_key) REFERENCES cache(key) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_key_type ON cache(key_type);
CREATE INDEX IF NOT EXISTS idx_created_at ON cache(created_at);
CREATE INDEX IF NOT EXISTS idx_accessed_at ON cache(accessed_at);
CREATE INDEX IF NOT EXISTS idx_cache_deps_dep ON cache_deps(dependency);
"""


@dataclass
class CacheEntry:
    """In-memory representation of a single row in the ``cache`` table.

    ``value_blob`` stores the BLAKE2b-signed pickle; ``dependencies`` is
    a JSON-encoded list of dependency key strings.
    """

    key: str
    key_type: str
    value_hash: str
    value_blob: bytes
    created_at: float
    accessed_at: float
    access_count: int
    dependencies: str

    @property
    def age(self) -> float:
        """Seconds elapsed since this entry was created."""
        return time.time() - self.created_at


__all__ = ["CacheEntry", "PERSISTENT_CACHE_SCHEMA"]
