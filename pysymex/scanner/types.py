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

"""
pysymex Scanner - type definitions
=====================================
Dataclasses and session-tracking types used by the scanner subsystem.
"""

import json
from pysymex.logger import get_logger
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TypeAlias, TypeGuard, TypedDict

from pysymex.analysis.scan.records import IssueRecord
from pysymex.config import is_object_dict


logger = get_logger(__name__)

SerializedScalar: TypeAlias = str | int | float | bool | None
SerializedValue: TypeAlias = (
    SerializedScalar | list["SerializedValue"] | dict[str, "SerializedValue"]
)
IssueBreakdown: TypeAlias = dict[str, int]


class SessionSummary(TypedDict):
    """Structure representing a summarized report of a scanning session.

    Attributes:
        files_scanned: Total number of files scanned.
        total_issues: Total number of issues found across all files.
        total_time: Total duration of the scan session in seconds.
        avg_memory: Average memory usage in MB across all files.
        issue_breakdown: A breakdown of issues by kind (e.g., {"ZERO_DIVISION": 2}).
        files_with_issues: Number of files that had at least one issue.
        files_clean: Number of files scanned with zero issues.
        files_error: Number of files that failed to scan due to an error.
        files_degraded: Number of files scanned that had degraded passes.
    """

    files_scanned: int
    total_issues: int
    total_time: float
    avg_memory: float
    issue_breakdown: IssueBreakdown
    files_with_issues: int
    files_clean: int
    files_error: int
    files_degraded: int


def _new_issue_records() -> list[IssueRecord]:
    """Create an empty typed list of scanner issues."""
    return []


def _is_object_sequence(
    value: object,
) -> TypeGuard[list[object] | tuple[object, ...]]:
    """Return True when *value* is a list-like container of objects."""
    return isinstance(value, (list, tuple))


def _is_object_set(value: object) -> TypeGuard[set[object] | frozenset[object]]:
    """Return True when *value* is an unordered set-like container."""
    return isinstance(value, (set, frozenset))


@dataclass
class ScanResult:
    """Result payload representing the outcomes of scanning a single source file.

    Maintains lists of discovered issues, counters for explored paths and code
    objects, performance metrics (execution time, average memory RSS usage), and
    fatal analysis errors or pass degradation records.

    Attributes:
        file_path: Absolute string path to the scanned Python file.
        timestamp: ISO-8601 string timestamp when the scan concluded.
        issues: List of resolved issue record dictionaries.
        code_objects: Total count of functions and classes discovered.
        paths_explored: Total count of VM symbolic execution paths analyzed.
        elapsed_time: Duration of the scan in seconds.
        avg_memory_mb: Average resident memory usage in megabytes.
        error: Consolidated scan error details, or None if successful.
        degraded_passes: Pass identifiers that failed to complete analysis fully.
    """

    file_path: str
    timestamp: str
    issues: list[IssueRecord] = field(default_factory=_new_issue_records)
    code_objects: int = 0
    paths_explored: int = 0
    elapsed_time: float = 0.0
    avg_memory_mb: float = 0.0
    error: str | None = None
    degraded_passes: list[str] = field(default_factory=list[str])
    solver_stats: dict[str, object] = field(default_factory=dict[str, object])

    def to_dict(self) -> dict[str, SerializedValue]:
        """Serialize the scan outcome details to a plain dictionary.

        Transforms collections, sets, nested dictionaries, and primitive scalar values
        into a serialization-safe nested dictionary format.

        Returns:
            A dictionary mapped with serialized JSON-compatible keys.
        """

        def _serialize(obj: object) -> SerializedValue:
            """Recursively transform an object into serialized scalars or structures."""
            if isinstance(obj, (str, int, float, bool, type(None))):
                return obj
            if is_object_dict(obj):
                serialized_map: dict[str, SerializedValue] = {}
                for key_obj, value_obj in obj.items():
                    serialized_map[str(key_obj)] = _serialize(value_obj)
                return serialized_map
            if _is_object_sequence(obj):
                serialized_items: list[SerializedValue] = []
                for item_obj in obj:
                    serialized_items.append(_serialize(item_obj))
                return serialized_items
            if _is_object_set(obj):
                serialized_items = [_serialize(item_obj) for item_obj in obj]
                return sorted(
                    serialized_items,
                    key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
                )
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
            "degraded_passes": _serialize(self.degraded_passes),
            "solver_stats": _serialize(self.solver_stats),
        }

    def __repr__(self) -> str:
        """Return a formatted string representation of the ScanResult instance.

        Returns:
            Developer-friendly representation of path, issue count, and errors.
        """
        return f"ScanResult({self.file_path}, issues={len(self.issues)}, error={self.error})"


class ScanResultBuilder:
    """Builder orchestrating incremental construction of a :class:`ScanResult`.

    Accumulates found issues, counts, performance data, and potential exceptions.
    Produces an immutable-style snapshot result. Use this inside functional
    passes to prevent side-effect leakage.
    """

    def __init__(self, file_path: str, timestamp: str | None = None) -> None:
        """Initialize a new ScanResultBuilder instance.

        Args:
            file_path: The file path of the source file being scanned.
            timestamp: ISO 8601 string timestamp. Defaults to the current system time.
        """
        self.file_path = file_path
        self.timestamp = timestamp or datetime.now().isoformat()
        self.issues: list[IssueRecord] = []
        self.code_objects: int = 0
        self.paths_explored: int = 0
        self.elapsed_time: float = 0.0
        self.avg_memory_mb: float = 0.0
        self.error: str | None = None
        self.degraded_passes: list[str] = []
        self.solver_stats: dict[str, object] = {}

    def add_issue(self, issue: IssueRecord) -> "ScanResultBuilder":
        """Append an issue record dict to the internal issues list.

        Args:
            issue: The issue dict mapping.

        Returns:
            The builder instance itself to support method chaining.
        """
        self.issues.append(issue)
        return self

    def set_error(self, error: str) -> "ScanResultBuilder":
        """Record a fatal scanning or parsing error message.

        Args:
            error: The error description.

        Returns:
            The builder instance itself to support method chaining.
        """
        self.error = error
        return self

    def add_paths(self, count: int) -> "ScanResultBuilder":
        """Add to the count of explored symbolic execution paths.

        Args:
            count: Path increment value.

        Returns:
            The builder instance itself to support method chaining.
        """
        self.paths_explored += count
        return self

    def set_performance(self, elapsed_time: float, avg_memory_mb: float) -> "ScanResultBuilder":
        """Set performance metrics.

        Args:
            elapsed_time: Duration of the scan in seconds.
            avg_memory_mb: Average memory usage in MB.

        Returns:
            The builder instance itself to support method chaining.
        """
        self.elapsed_time = elapsed_time
        self.avg_memory_mb = avg_memory_mb
        return self

    def build(self) -> ScanResult:
        """Produce a finished :class:`ScanResult` from the accumulated data.

        Returns:
            An immutable snapshot representation of the scan result.
        """
        return ScanResult(
            file_path=self.file_path,
            timestamp=self.timestamp,
            issues=list(self.issues),
            code_objects=self.code_objects,
            paths_explored=self.paths_explored,
            elapsed_time=self.elapsed_time,
            avg_memory_mb=self.avg_memory_mb,
            error=self.error,
            degraded_passes=list(self.degraded_passes),
            solver_stats=dict(self.solver_stats),
        )


class ScanSession:
    """Session container coordinating multiple single-file scans.

    Automatically serialises aggregated scan results to a JSON log file.
    """

    def __init__(self, log_file: Path | None = None) -> None:
        """Initialize a new ScanSession instance.

        Args:
            log_file: Target path to write the scan log file. Defaults to a timestamped file in the current directory.
        """
        self.results: list[ScanResult] = []
        self.start_time = datetime.now()
        self.log_file = log_file or Path(
            f"scan_log_{self.start_time.strftime('%Y%m%d_%H%M%S')}.json"
        )
        self.log_write_error: str | None = None

    def add_result(self, result: ScanResult) -> None:
        """Record a file scan result and update the log file on disk.

        Args:
            result: The completed result payload to record.

        Side Effects:
            - Appends ``result`` to ``self.results``.
            - Overwrites ``self.log_file`` with updated session statistics.
        """
        self.results.append(result)
        self._save_log()

    def _save_log(self) -> None:
        """Save session logs to the configured log file path.

        Side Effects:
            - Creates or overwrites a JSON log file.
            - Catches OSError and sets the `log_write_error` status.
        """

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
            self.log_write_error = None
        except OSError as exc:
            self.log_write_error = f"{type(exc).__name__}({exc})"
            logger.error("Failed to write scan log to %s", self.log_file, exc_info=True)

    def get_summary(self) -> SessionSummary:
        """Summarize statistics for all files scanned during this session.

        Returns:
            A :class:`SessionSummary` mapped with file and issues counts,
            durations, and average memory usage.
        """
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
            "files_clean": sum(
                1 for r in self.results if not r.issues and not r.error and not r.degraded_passes
            ),
            "files_error": sum(1 for r in self.results if r.error),
            "files_degraded": sum(1 for r in self.results if r.degraded_passes),
        }
