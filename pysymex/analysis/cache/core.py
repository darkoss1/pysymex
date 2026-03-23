"""Core cache infrastructure: key types, hash functions, LRU cache,
persistent SQLite cache, and tiered (memory + persistent) cache.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import pickle
import secrets
import sqlite3
import stat
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import (
    Any,
    Generic,
    TypeVar,
)

from pysymex._constants import HMAC_DIGEST, HMAC_KEY_SIZE, HMAC_TAG_SIZE

logger = logging.getLogger(__name__)

T = TypeVar("T")
K = TypeVar("K")
V = TypeVar("V")


class CacheKeyType(Enum):
    """Types of cache keys."""

    FUNCTION = auto()
    BYTECODE = auto()
    MODULE = auto()
    SUMMARY = auto()
    VERIFICATION = auto()
    CUSTOM = auto()


class _CacheIntegrity:
    """Manages HMAC signing and verification for persistent cache blobs.

    A per-machine secret key is generated on first use and stored at
    ``~/.pysymex/cache.key`` with owner-only permissions.  Every blob
    written to SQLite is prefixed with a 32-byte HMAC-SHA256 tag.  On
    read, the tag is verified before ``pickle.loads`` is called.

    If the key file is missing or has been tampered with, the entire
    cache is wiped to prevent deserialization of untrusted data.
    """

    def __init__(self, key_path: Path) -> None:
        self._key_path = key_path
        self._key: bytes | None = None

    def _restrict_key_permissions(self) -> None:
        """Restrict key permissions."""
        try:
            self._key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            logger.debug("Failed to tighten cache key permissions", exc_info=True)

    def _write_key_file(self, key: bytes) -> None:
        """Write key file."""
        fd = os.open(
            self._key_path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            stat.S_IRUSR | stat.S_IWUSR,
        )
        with os.fdopen(fd, "wb") as handle:
            handle.write(key)
        self._restrict_key_permissions()

    def _load_or_create_key(self) -> bytes:
        """Load or create key."""
        if self._key is not None:
            return self._key
        if self._key_path.exists():
            raw = self._key_path.read_bytes()
            if len(raw) == HMAC_KEY_SIZE:
                self._restrict_key_permissions()
                self._key = raw
                return raw
            logger.warning("Corrupt HMAC key file — regenerating")
        self._key_path.parent.mkdir(parents=True, exist_ok=True)
        key = secrets.token_bytes(HMAC_KEY_SIZE)
        self._write_key_file(key)
        self._key = key
        return key

    def sign(self, blob: bytes) -> bytes:
        """Return ``tag || blob`` where tag is HMAC-SHA256."""
        key = self._load_or_create_key()
        tag = hmac.new(key, blob, HMAC_DIGEST).digest()
        return tag + blob

    def verify_and_extract(self, signed_blob: bytes) -> bytes | None:
        """Verify HMAC tag and return raw blob, or None if invalid."""
        if len(signed_blob) < HMAC_TAG_SIZE:
            return None
        tag = signed_blob[:HMAC_TAG_SIZE]
        blob = signed_blob[HMAC_TAG_SIZE:]
        key = self._load_or_create_key()
        expected = hmac.new(key, blob, HMAC_DIGEST).digest()
        if hmac.compare_digest(tag, expected):
            return blob
        return None

    def reset_key(self) -> None:
        """Delete the key file — forces cache wipe on next access."""
        self._key = None
        if self._key_path.exists():
            self._key_path.unlink()


@dataclass(frozen=True)
class CacheKey:
    """Immutable cache key."""

    key_type: CacheKeyType
    identifier: str
    version: str = "1.0"

    def __hash__(self) -> int:
        """Return the hash value of the object."""
        return hash((self.key_type, self.identifier, self.version))

    def to_string(self) -> str:
        """Convert to string representation."""
        return f"{self .key_type .name }:{self .identifier }:{self .version }"

    @classmethod
    def from_string(cls, s: str) -> CacheKey:
        """Parse from string representation."""
        parts = s.split(":", 2)
        if len(parts) != 3:
            raise ValueError(f"Invalid cache key string: {s }")
        return cls(
            key_type=CacheKeyType[parts[0]],
            identifier=parts[1],
            version=parts[2],
        )


def hash_bytecode(code: bytes) -> str:
    """Hash bytecode for caching."""
    return hashlib.sha256(code).hexdigest()


def hash_function(func_name: str, code: bytes, signature: str = "") -> str:
    """Hash a function for caching."""
    content = f"{func_name }:{signature }:".encode() + code
    return hashlib.sha256(content).hexdigest()


def hash_file(path: Path) -> str:
    """Hash a file for caching."""
    content = path.read_bytes()
    return hashlib.sha256(content).hexdigest()


def hash_dict(d: dict[str, object]) -> str:
    """Hash a dictionary for caching."""
    content = json.dumps(d, sort_keys=True, default=str)
    return hashlib.sha256(content.encode()).hexdigest()


class LRUCache(Generic[K, V]):
    """Thread-safe LRU cache with size limit.
    Keeps most recently used items in memory up to a maximum size.
    """

    def __init__(self, maxsize: int = 1000):
        self.maxsize = maxsize
        self._cache: OrderedDict[K, V] = OrderedDict()
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0

    def get(self, key: K, default: V | None = None) -> V | None:
        """Get item from cache."""
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                self._hits += 1
                return self._cache[key]
            self._misses += 1
            return default

    def put(self, key: K, value: V) -> None:
        """Put item in cache."""
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = value
            while len(self._cache) > self.maxsize:
                self._cache.popitem(last=False)

    def remove(self, key: K) -> bool:
        """Remove item from cache."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    def clear(self) -> None:
        """Clear all items."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0

    def __contains__(self, key: K) -> bool:
        """Contains."""
        with self._lock:
            return key in self._cache

    def __len__(self) -> int:
        """Return the number of elements in the container."""
        with self._lock:
            return len(self._cache)

    @property
    def hit_rate(self) -> float:
        """Get cache hit rate."""
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    def stats(self) -> dict[str, object]:
        """Get cache statistics."""
        with self._lock:
            return {
                "size": len(self._cache),
                "maxsize": self.maxsize,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": self.hit_rate,
            }


@dataclass
class CacheEntry:
    """Entry in persistent cache."""

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
        """Get age in seconds."""
        return time.time() - self.created_at


class PersistentCache:
    """SQLite-backed persistent cache.
    Provides durable storage of analysis results with automatic
    cleanup and dependency tracking.
    """

    SCHEMA = """
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

    def __init__(
        self,
        db_path: Path | None = None,
        max_entries: int = 10000,
        max_age_days: int = 30,
    ):
        self.db_path = db_path or Path.home() / ".pysymex" / "cache.db"
        self.max_entries = max_entries
        self.max_age_days = max_age_days
        self._integrity = _CacheIntegrity(
            self.db_path.parent / "cache.key",
        )
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._ensure_directory()
        self._init_database()

    def _ensure_directory(self) -> None:
        """Ensure cache directory exists."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _init_database(self) -> None:
        """Initialize database schema."""
        conn = self._get_connection()
        conn.executescript(self.SCHEMA)
        conn.commit()

    def _get_connection(self) -> sqlite3.Connection:
        """Return the persistent connection, creating it on first call."""
        with self._lock:
            if self._conn is None:
                self._conn = sqlite3.connect(
                    str(self.db_path),
                    check_same_thread=False,
                )
                self._conn.row_factory = sqlite3.Row
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("PRAGMA foreign_keys=ON")
                self._conn.execute("PRAGMA synchronous=NORMAL")
            return self._conn

    def _connect(self) -> sqlite3.Connection:
        """Return the persistent connection (backward-compat alias)."""
        return self._get_connection()

    def close(self) -> None:
        """Close the persistent SQLite connection if it is open."""
        with self._lock:
            if self._conn is not None:
                # Checkpoint WAL to release files on Windows
                try:
                    self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.Error:
                    pass
                self._conn.close()
                self._conn = None

    def get(self, key: CacheKey) -> object | None:
        """Get value from cache, verifying HMAC integrity before deserialization."""
        key_str = key.to_string()
        with self._lock:
            conn = self._get_connection()
            cursor = conn.execute("SELECT * FROM cache WHERE key = ?", (key_str,))
            row = cursor.fetchone()
            if row:
                conn.execute(
                    """
                    UPDATE cache 
                    SET accessed_at = ?, access_count = access_count + 1
                    WHERE key = ?
                    """,
                    (time.time(), key_str),
                )
                conn.commit()
                try:
                    raw_blob = self._integrity.verify_and_extract(
                        row["value_blob"],
                    )
                    if raw_blob is None:
                        logger.warning(
                            "HMAC verification failed for cache key %s — " "removing tainted entry",
                            key_str,
                        )
                        conn.execute(
                            "DELETE FROM cache WHERE key = ?",
                            (key_str,),
                        )
                        conn.commit()
                        return None
                    return pickle.loads(raw_blob)
                except (pickle.UnpicklingError, ValueError, TypeError, EOFError):
                    logger.debug(
                        "Failed to deserialize cache entry %s",
                        key_str,
                        exc_info=True,
                    )
                    return None
        return None

    def put(
        self,
        key: CacheKey,
        value: object,
        dependencies: list[CacheKey] | None = None,
    ) -> bool:
        """Put value in cache with HMAC-signed serialization."""
        key_str = key.to_string()
        try:
            raw_blob = pickle.dumps(value)
            signed_blob = self._integrity.sign(raw_blob)
            value_hash = hashlib.sha256(raw_blob).hexdigest()
            dep_list = dependencies or []
            dep_json = json.dumps([d.to_string() for d in dep_list])
            now = time.time()
            with self._lock:
                conn = self._get_connection()
                conn.execute(
                    """
                    INSERT OR REPLACE INTO cache 
                    (key, key_type, value_hash, value_blob, created_at, 
                     accessed_at, access_count, dependencies)
                    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                    """,
                    (key_str, key.key_type.name, value_hash, signed_blob, now, now, dep_json),
                )
                conn.execute(
                    "DELETE FROM cache_deps WHERE cache_key = ?",
                    (key_str,),
                )
                if dep_list:
                    conn.executemany(
                        "INSERT OR IGNORE INTO cache_deps (cache_key, dependency) VALUES (?, ?)",
                        [(key_str, d.to_string()) for d in dep_list],
                    )
                conn.commit()
            return True
        except (pickle.PicklingError, TypeError, OSError):
            logger.debug(
                "Failed to cache entry %s",
                key_str,
                exc_info=True,
            )
            return False

    def remove(self, key: CacheKey) -> bool:
        """Remove entry from cache."""
        key_str = key.to_string()
        with self._lock:
            conn = self._get_connection()
            cursor = conn.execute("DELETE FROM cache WHERE key = ?", (key_str,))
            conn.commit()
            return cursor.rowcount > 0

    def invalidate_by_type(self, key_type: CacheKeyType) -> int:
        """Invalidate all entries of a type."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.execute("DELETE FROM cache WHERE key_type = ?", (key_type.name,))
            conn.commit()
            return cursor.rowcount

    def invalidate_dependencies(self, key: CacheKey) -> set[str]:
        """Invalidate all entries that depend on a key.

        Uses the normalized ``cache_deps`` table with an index on
        ``dependency`` for O(log N) lookup instead of a full table scan.
        """
        key_str = key.to_string()
        with self._lock:
            conn = self._get_connection()
            cursor = conn.execute(
                "SELECT cache_key FROM cache_deps WHERE dependency = ?",
                (key_str,),
            )
            invalidated = {row["cache_key"] for row in cursor}
            if invalidated:
                placeholders = ",".join("?" * len(invalidated))
                conn.execute(
                    f"DELETE FROM cache WHERE key IN ({placeholders })",
                    tuple(invalidated),
                )
            conn.commit()
        return invalidated

    def clear(self) -> int:
        """Clear all entries."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.execute("DELETE FROM cache")
            conn.commit()
            return cursor.rowcount

    def cleanup(self) -> int:
        """Clean up old and excess entries."""
        removed = 0
        now = time.time()
        max_age_seconds = self.max_age_days * 24 * 60 * 60
        with self._lock:
            conn = self._get_connection()
            cursor = conn.execute(
                "DELETE FROM cache WHERE created_at < ?", (now - max_age_seconds,)
            )
            removed += cursor.rowcount
            cursor = conn.execute("SELECT COUNT(*) FROM cache")
            count = cursor.fetchone()[0]
            if count > self.max_entries:
                excess = count - self.max_entries
                conn.execute(
                    """
                    DELETE FROM cache WHERE key IN (
                        SELECT key FROM cache 
                        ORDER BY accessed_at ASC 
                        LIMIT ?
                    )
                    """,
                    (excess,),
                )
                removed += excess
            conn.commit()
        return removed

    def stats(self) -> dict[str, object]:
        """Get cache statistics."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.execute("SELECT COUNT(*) FROM cache")
            count = cursor.fetchone()[0]
            cursor = conn.execute("SELECT key_type, COUNT(*) as cnt FROM cache GROUP BY key_type")
            by_type = {row["key_type"]: row["cnt"] for row in cursor}
            cursor = conn.execute("SELECT SUM(access_count) as total FROM cache")
            total_accesses = cursor.fetchone()["total"] or 0
            return {
                "db_path": str(self.db_path),
                "entry_count": count,
                "by_type": by_type,
                "total_accesses": total_accesses,
                "max_entries": self.max_entries,
            }

    def __contains__(self, key: CacheKey) -> bool:
        """Contains."""
        key_str = key.to_string()
        with self._lock:
            conn = self._get_connection()
            cursor = conn.execute("SELECT 1 FROM cache WHERE key = ?", (key_str,))
            return cursor.fetchone() is not None

    def __len__(self) -> int:
        """Return the number of elements in the container."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.execute("SELECT COUNT(*) FROM cache")
            return cursor.fetchone()[0]


class TieredCache:
    """Two-level cache with memory and persistent storage.
    Uses LRU cache for fast access and SQLite for persistence.
    """

    def __init__(
        self,
        memory_size: int = 1000,
        db_path: Path | None = None,
    ):
        self.memory = LRUCache[str, Any](maxsize=memory_size)
        self.persistent = PersistentCache(db_path=db_path)

    def get(self, key: CacheKey) -> object | None:
        """Get from cache, checking memory first."""
        key_str = key.to_string()
        value = self.memory.get(key_str)
        if value is not None:
            return value
        value = self.persistent.get(key)
        if value is not None:
            self.memory.put(key_str, value)
            return value
        return None

    def put(
        self,
        key: CacheKey,
        value: object,
        persist: bool = True,
        dependencies: list[CacheKey] | None = None,
    ) -> None:
        """Put in cache."""
        key_str = key.to_string()
        self.memory.put(key_str, value)
        if persist:
            self.persistent.put(key, value, dependencies)

    def remove(self, key: CacheKey) -> bool:
        """Remove from both caches."""
        key_str = key.to_string()
        mem_removed = self.memory.remove(key_str)
        pers_removed = self.persistent.remove(key)
        return mem_removed or pers_removed

    def clear(self) -> None:
        """Clear both caches."""
        self.memory.clear()
        self.persistent.clear()

    def stats(self) -> dict[str, object]:
        """Get combined statistics."""
        return {
            "memory": self.memory.stats(),
            "persistent": self.persistent.stats(),
        }
