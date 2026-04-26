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

"""
pysymex Scanner - type definitions
=====================================
Dataclasses and session-tracking types used by the scanner subsystem.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TypeAlias, TypeGuard, TypedDict

logger = logging.getLogger(__name__)

SerializedScalar: TypeAlias = str | int | float | bool | None
SerializedValue: TypeAlias = (
    SerializedScalar | list["SerializedValue"] | dict[str, "SerializedValue"]
)
IssueRecord: TypeAlias = dict[str, object]
IssueBreakdown: TypeAlias = dict[str, int]


class SessionSummary(TypedDict):
    files_scanned: int
    total_issues: int
    total_time: float
    avg_memory: float
    issue_breakdown: IssueBreakdown
    files_with_issues: int
    files_clean: int
    files_error: int


def _new_issue_records() -> list[IssueRecord]:
    """Create an empty typed list of scanner issues."""
    return []


def _is_object_dict(value: object) -> TypeGuard[dict[object, object]]:
    """Return True when *value* is a dictionary with object-like entries."""
    return isinstance(value, dict)


def _is_object_sequence(
    value: object,
) -> TypeGuard[list[object] | tuple[object, ...] | set[object]]:
    """Return True when *value* is a list-like container of objects."""
    return isinstance(value, (list, tuple, set))


@dataclass
class ScanResult:
    """Result of scanning a single file."""

    file_path: str
    timestamp: str
    issues: list[IssueRecord] = field(default_factory=_new_issue_records)
    code_objects: int = 0
    paths_explored: int = 0
    elapsed_time: float = 0.0
    avg_memory_mb: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict[str, SerializedValue]:
        """Serialise the result to a plain dictionary.

        Returns:
            Dict with keys ``file``, ``timestamp``, ``issues``,
            ``code_objects``, ``paths_explored``, and ``error``.
        """

        def _serialize(obj: object) -> SerializedValue:
            """Serialize."""
            if isinstance(obj, (str, int, float, bool, type(None))):
                return obj
            if _is_object_dict(obj):
                serialized_map: dict[str, SerializedValue] = {}
                for key_obj, value_obj in obj.items():
                    serialized_map[str(key_obj)] = _serialize(value_obj)
                return serialized_map
            if _is_object_sequence(obj):
                serialized_items: list[SerializedValue] = []
                for item_obj in obj:
                    serialized_items.append(_serialize(item_obj))
                return serialized_items
            return str(obj)

        return {
            "file": self.file_path,
            "timestamp": self.timestamp,
            "issues": _serialize(self.issues),
            "code_objects": self.code_objects,
            "paths_explored": self.paths_explored,
            "elapsed_time": self.elapsed_time,
            "avg_memory_mb": self.avg_memory_mb,
            "error": self.error,
        }

    def __repr__(self) -> str:
        return f"ScanResult({self.file_path}, issues={len(self.issues)}, error={self.error})"


class ScanResultBuilder:
    """Mutable builder for :class:`ScanResult`.

    Accumulates data during analysis and produces an immutable-style
    ``ScanResult`` via :meth:`build`.  Use this in functional-core
    analysis paths so interim mutation stays localised.
    """

    def __init__(self, file_path: str, timestamp: str | None = None) -> None:
        self.file_path = file_path
        self.timestamp = timestamp or datetime.now().isoformat()
        self.issues: list[IssueRecord] = []
        self.code_objects: int = 0
        self.paths_explored: int = 0
        self.elapsed_time: float = 0.0
        self.avg_memory_mb: float = 0.0
        self.error: str | None = None

    def add_issue(self, issue: IssueRecord) -> "ScanResultBuilder":
        """Append an issue dict and return *self* for chaining."""
        self.issues.append(issue)
        return self

    def set_error(self, error: str) -> "ScanResultBuilder":
        """Record a fatal error and return *self* for chaining."""
        self.error = error
        return self

    def add_paths(self, count: int) -> "ScanResultBuilder":
        """Increment explored-paths counter by *count* and return *self*."""
        self.paths_explored += count
        return self

    def set_performance(self, elapsed_time: float, avg_memory_mb: float) -> "ScanResultBuilder":
        """Set performance metrics."""
        self.elapsed_time = elapsed_time
        self.avg_memory_mb = avg_memory_mb
        return self

    def build(self) -> ScanResult:
        """Return a :class:`ScanResult` snapshot."""
        return ScanResult(
            file_path=self.file_path,
            timestamp=self.timestamp,
            issues=list(self.issues),
            code_objects=self.code_objects,
            paths_explored=self.paths_explored,
            elapsed_time=self.elapsed_time,
            avg_memory_mb=self.avg_memory_mb,
            error=self.error,
        )


class ScanSession:
    """Tracks all scans in a session.

    Holds a shared :class:`~pysymex.core.optimization.ConstraintCache`
    that persists across file scans within the session, enabling warm-start
    reuse of satisfiability results.
    """

    def __init__(self, log_file: Path | None = None, cache_size: int = 10_000) -> None:
        self.results: list[ScanResult] = []
        self.start_time = datetime.now()
        self.log_file = log_file or Path(
            f"scan_log_{self.start_time.strftime('%Y%m%d_%H%M%S')}.json"
        )

        self._constraint_cache: object | None = None
        self._cache_size = cache_size

    @property
    def constraint_cache(self) -> object:
        """Session-wide constraint cache (created on first access)."""
        if self._constraint_cache is None:
            from pysymex.core.optimization import ConstraintCache

            self._constraint_cache = ConstraintCache(max_size=self._cache_size)
        return self._constraint_cache

    def add_result(self, result: ScanResult) -> None:
        """Append *result* and persist the session log to disk."""
        self.results.append(result)
        self._save_log()

    def _save_log(self) -> None:
        """Save results to log file. Optimized to reduce overhead."""

        log_data = {
            "session_start": self.start_time.isoformat(),
            "last_update": datetime.now().isoformat(),
            "total_files": len(self.results),
            "total_issues": sum(len(r.issues) for r in self.results),
            "scans": [r.to_dict() for r in self.results],
        }
        try:
            with self.log_file.open("w", encoding="utf-8") as f:
                json.dump(log_data, f, separators=(",", ":"))
        except OSError:
            logger.error("Failed to write scan log to %s", self.log_file)

    def get_summary(self) -> SessionSummary:
        """Get session summary statistics."""
        total_issues = sum(len(r.issues) for r in self.results)
        total_time = sum(r.elapsed_time for r in self.results)
        memory_samples = [r.avg_memory_mb for r in self.results if r.avg_memory_mb > 0]
        avg_memory = sum(memory_samples) / len(memory_samples) if memory_samples else 0.0

        issue_counts: IssueBreakdown = {}
        for r in self.results:
            for issue in r.issues:
                kind_val = issue.get("kind", "UNKNOWN")
                kind = str(kind_val)
                issue_counts[kind] = issue_counts.get(kind, 0) + 1
        return {
            "files_scanned": len(self.results),
            "total_issues": total_issues,
            "total_time": total_time,
            "avg_memory": avg_memory,
            "issue_breakdown": issue_counts,
            "files_with_issues": sum(1 for r in self.results if r.issues),
            "files_clean": sum(1 for r in self.results if not r.issues and not r.error),
            "files_error": sum(1 for r in self.results if r.error),
        }
