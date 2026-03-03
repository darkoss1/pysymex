"""Core cache infrastructure: key types, hash functions, LRU cache,
persistent SQLite cache, and tiered (memory + persistent) cache.
"""

from __future__ import annotations


import hashlib

import json

import pickle

import sqlite3

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


@dataclass(frozen=True)
class CacheKey:
    """Immutable cache key."""

    key_type: CacheKeyType

    identifier: str

    version: str = "1.0"

    def __hash__(self) -> int:
        return hash((self.key_type, self.identifier, self.version))

    def to_string(self) -> str:
        """Convert to string representation."""

        return f"{self.key_type.name}:{self.identifier}:{self.version}"

    @classmethod
    def from_string(cls, s: str) -> CacheKey:
        """Parse from string representation."""

        parts = s.split(":", 2)

        if len(parts) != 3:
            raise ValueError(f"Invalid cache key string: {s}")

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

    content = f"{func_name}:{signature}:".encode() + code

    return hashlib.sha256(content).hexdigest()


def hash_file(path: Path) -> str:
    """Hash a file for caching."""

    content = path.read_bytes()

    return hashlib.sha256(content).hexdigest()


def hash_dict(d: dict[str, Any]) -> str:
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

    def get(self, key: K, default: V = None) -> V | None:
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
        with self._lock:
            return key in self._cache

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)

    @property
    def hit_rate(self) -> float:
        """Get cache hit rate."""

        total = self._hits + self._misses

        return self._hits / total if total > 0 else 0.0

    def stats(self) -> dict[str, Any]:
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
    CREATE INDEX IF NOT EXISTS idx_key_type ON cache(key_type);
    CREATE INDEX IF NOT EXISTS idx_created_at ON cache(created_at);
    CREATE INDEX IF NOT EXISTS idx_accessed_at ON cache(accessed_at);
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

        self._ensure_directory()

        self._init_database()

    def _ensure_directory(self) -> None:
        """Ensure cache directory exists."""

        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _init_database(self) -> None:
        """Initialize database schema."""

        with self._connect() as conn:
            conn.executescript(self.SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        """Create database connection."""

        conn = sqlite3.connect(str(self.db_path))

        conn.row_factory = sqlite3.Row

        return conn

    def get(self, key: CacheKey) -> Any | None:
        """Get value from cache."""

        key_str = key.to_string()

        with self._connect() as conn:
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

                try:
                    return pickle.loads(row["value_blob"])

                except Exception:
                    return None

        return None

    def put(
        self,
        key: CacheKey,
        value: Any,
        dependencies: list[CacheKey] | None = None,
    ) -> bool:
        """Put value in cache."""

        key_str = key.to_string()

        try:
            value_blob = pickle.dumps(value)

            value_hash = hashlib.sha256(value_blob).hexdigest()

            dep_json = json.dumps([d.to_string() for d in (dependencies or [])])

            now = time.time()

            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO cache 
                    (key, key_type, value_hash, value_blob, created_at, 
                     accessed_at, access_count, dependencies)
                    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                    """,
                    (key_str, key.key_type.name, value_hash, value_blob, now, now, dep_json),
                )

            return True

        except Exception:
            return False

    def remove(self, key: CacheKey) -> bool:
        """Remove entry from cache."""

        key_str = key.to_string()

        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM cache WHERE key = ?", (key_str,))

            return cursor.rowcount > 0

    def invalidate_by_type(self, key_type: CacheKeyType) -> int:
        """Invalidate all entries of a type."""

        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM cache WHERE key_type = ?", (key_type.name,))

            return cursor.rowcount

    def invalidate_dependencies(self, key: CacheKey) -> set[str]:
        """Invalidate all entries that depend on a key."""

        key_str = key.to_string()

        invalidated: set[str] = set()

        with self._connect() as conn:
            cursor = conn.execute("SELECT key, dependencies FROM cache")

            for row in cursor:
                deps = json.loads(row["dependencies"])

                if key_str in deps:
                    invalidated.add(row["key"])

            if invalidated:
                placeholders = ",".join("?" * len(invalidated))

                conn.execute(f"DELETE FROM cache WHERE key IN ({placeholders})", tuple(invalidated))

        return invalidated

    def clear(self) -> int:
        """Clear all entries."""

        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM cache")

            return cursor.rowcount

    def cleanup(self) -> int:
        """Clean up old and excess entries."""

        removed = 0

        now = time.time()

        max_age_seconds = self.max_age_days * 24 * 60 * 60

        with self._connect() as conn:
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

        return removed

    def stats(self) -> dict[str, Any]:
        """Get cache statistics."""

        with self._connect() as conn:
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
        key_str = key.to_string()

        with self._connect() as conn:
            cursor = conn.execute("SELECT 1 FROM cache WHERE key = ?", (key_str,))

            return cursor.fetchone() is not None

    def __len__(self) -> int:
        with self._connect() as conn:
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

    def get(self, key: CacheKey) -> Any | None:
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
        value: Any,
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

    def stats(self) -> dict[str, Any]:
        """Get combined statistics."""

        return {
            "memory": self.memory.stats(),
            "persistent": self.persistent.stats(),
        }
