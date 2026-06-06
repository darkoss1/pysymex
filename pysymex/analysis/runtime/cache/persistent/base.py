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

"""SQLite connection lifecycle and schema management for persistent cache storage."""

from __future__ import annotations

import os
import sqlite3
import tempfile
import threading
from pathlib import Path

from pysymex.analysis.runtime.cache.integrity import CacheIntegrity
from pysymex.analysis.runtime.cache.persistent.types import PERSISTENT_CACHE_SCHEMA
from pysymex.logger import get_logger

logger = get_logger(__name__)


class PersistentCacheBase:
    """SQLite-backed persistent cache lifecycle manager.

    Manages the database connection (WAL mode, foreign keys, normal sync),
    BLAKE2b integrity via ``CacheIntegrity``, schema initialisation, batched
    access-timestamp updates, and best-effort background cleanup.
    Supports pickling (connection and lock are stripped and restored).
    """

    SCHEMA = PERSISTENT_CACHE_SCHEMA

    @staticmethod
    def _is_writable_directory(path: Path) -> bool:
        """Return True when ``path`` can be created and written to."""
        probe = path / ".pysymex_write_probe"
        try:
            path.mkdir(parents=True, exist_ok=True)
            from pysymex.pathing import ensure_pysymex_gitignore

            ensure_pysymex_gitignore(path)
            probe.write_bytes(b"ok")
            probe.unlink(missing_ok=True)
            return True
        except OSError:
            logger.debug("Cache directory is not writable: %s", path, exc_info=True)
            return False

    @classmethod
    def _default_db_path(cls) -> Path:
        """Return a default database path, checking environment variables and candidate directories.

        Tries, in order:
        1. ``PYSYMEX_CACHE_DB`` environment variable (direct path).
        2. ``PYSYMEX_CACHE_DIR`` environment variable.
        3. ``~/.pysymex``, ``$TMPDIR/pysymex``, ``$CWD/.pysymex``.
        """
        explicit_db = os.environ.get("PYSYMEX_CACHE_DB")
        if explicit_db:
            return Path(explicit_db)

        candidate_dirs: list[Path] = []
        explicit_dir = os.environ.get("PYSYMEX_CACHE_DIR")
        if explicit_dir:
            candidate_dirs.append(Path(explicit_dir))

        candidate_dirs.extend(
            [
                Path.home() / ".pysymex",
                Path(tempfile.gettempdir()) / "pysymex",
                Path.cwd() / ".pysymex",
            ]
        )

        for directory in candidate_dirs:
            if cls._is_writable_directory(directory):
                return directory / "cache.db"

        return candidate_dirs[-1] / "cache.db"

    def __init__(
        self,
        db_path: Path | None = None,
        max_entries: int = 10000,
        max_age_days: int = 30,
    ) -> None:
        """Initialize a PersistentCacheBase instance.

        Args:
            db_path (Path | None): Optional Path to the SQLite database.
            max_entries (int): Capacity limit on cached database entries. Defaults to 10000.
            max_age_days (int): Stale entry age limit in days. Defaults to 30.
        """
        self.db_path = db_path or self._default_db_path()
        self.max_entries = max_entries
        self.max_age_days = max_age_days
        self._integrity = CacheIntegrity(self.db_path.parent / "cache.key")
        self.lock = threading.RLock()
        self.conn: sqlite3.Connection | None = None
        self._pending_access_updates: dict[str, tuple[float, int]] = {}
        self._ensure_directory()
        self._init_database()
        threading.Thread(target=self._run_cleanup_safe, daemon=True).start()

    def _run_cleanup_safe(self) -> None:
        """Run background database cleanup, swallowing and logging any failures."""
        try:
            self.cleanup()
        except Exception:
            logger.debug("Persistent cache background cleanup failed", exc_info=True)

    def cleanup(self) -> int:
        """Clean up old and excess entries."""
        raise NotImplementedError

    def _ensure_directory(self) -> None:
        """Create the parent directory and add a ``.gitignore`` if needed."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        from pysymex.pathing import ensure_pysymex_gitignore

        ensure_pysymex_gitignore(self.db_path.parent)

    def _init_database(self) -> None:
        """Run the ``PERSISTENT_CACHE_SCHEMA`` DDL against the current connection."""
        conn = self._get_connection()
        conn.executescript(self.SCHEMA)
        conn.commit()

    def _get_connection(self) -> sqlite3.Connection:
        """Return the thread-safe connection, creating it lazily with WAL mode."""
        with self.lock:
            if self.conn is None:
                self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
                self.conn.row_factory = sqlite3.Row
                self.conn.execute("PRAGMA journal_mode=WAL")
                self.conn.execute("PRAGMA foreign_keys=ON")
                self.conn.execute("PRAGMA synchronous=NORMAL")
            return self.conn

    def _flush_access_updates_locked(self) -> None:
        """Write batched ``(accessed_at, access_count)`` updates to the database.

        Must be called while ``self.lock`` is held.
        """
        if not self._pending_access_updates:
            return

        updates = [(stats[0], stats[1], key) for key, stats in self._pending_access_updates.items()]
        self._pending_access_updates.clear()

        conn = self._get_connection()
        conn.executemany(
            """
            UPDATE cache
            SET accessed_at = max(accessed_at, ?), access_count = access_count + ?
            WHERE key = ?
            """,
            updates,
        )
        conn.commit()

    def close(self) -> None:
        """Flush pending updates, checkpoint the WAL, and close the connection."""
        with self.lock:
            self._flush_access_updates_locked()
            if self.conn is not None:
                try:
                    self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.Error:
                    logger.debug("Persistent cache WAL checkpoint failed", exc_info=True)
                self.conn.close()
                self.conn = None

    def __del__(self) -> None:
        """Best-effort close to avoid leaking SQLite connections in tests."""
        try:
            self.close()
        except Exception:
            logger.debug("Persistent cache finalizer failed", exc_info=True)

    def __getstate__(self) -> dict[str, object]:
        """Prepare the persistent cache state for pickling.

        Clears synchronization locks and open connection handles to avoid serialization errors.

        Returns:
            dict[str, object]: Serializable cache state.
        """
        state = self.__dict__.copy()
        state["lock"] = None
        state["conn"] = None
        return state

    def __setstate__(self, state: dict[str, object]) -> None:
        """Restore the persistent cache state from pickled state.

        Re-initializes fresh reentrant locks and empty connection/access structures.

        Args:
            state (dict[str, object]): Unpickled state dictionary.
        """
        self.__dict__.update(state)
        self.lock = threading.RLock()
        self.conn = None
        self._pending_access_updates = {}


__all__ = ["PersistentCacheBase"]
