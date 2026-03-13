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

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result of scanning a single file."""

    file_path: str
    timestamp: str
    issues: list[dict[str, object]] = field(default_factory=list[dict[str, object]])
    code_objects: int = 0
    paths_explored: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialise the result to a plain dictionary.

        Returns:
            Dict with keys ``file``, ``timestamp``, ``issues``,
            ``code_objects``, ``paths_explored``, and ``error``.
        """

        def _serialize(obj: object) -> object:
            """Serialize."""
            if isinstance(obj, (str, int, float, bool, type(None))):
                return obj
            if isinstance(obj, dict):
                return {str(k): _serialize(v) for k, v in obj.items()}
            if isinstance(obj, (list, tuple, set)):
                return [_serialize(i) for i in obj]
            return str(obj)

        return {
            "file": self.file_path,
            "timestamp": self.timestamp,
            "issues": _serialize(self.issues),
            "code_objects": self.code_objects,
            "paths_explored": self.paths_explored,
            "error": self.error,
        }

    def __repr__(self) -> str:
        """Repr."""
        """Return a formal string representation."""
        return f"ScanResult({self.file_path}, issues={len(self.issues)}, error={self.error})"


class ScanResultBuilder:
    """Mutable builder for :class:`ScanResult`.

    Accumulates data during analysis and produces an immutable-style
    ``ScanResult`` via :meth:`build`.  Use this in functional-core
    analysis paths so interim mutation stays localised.
    """

    def __init__(self, file_path: str, timestamp: str | None = None) -> None:
        """Init."""
        """Initialize the class instance."""
        self.file_path = file_path
        self.timestamp = timestamp or datetime.now().isoformat()
        self.issues: list[dict[str, object]] = []
        self.code_objects: int = 0
        self.paths_explored: int = 0
        self.error: str | None = None

    def add_issue(self, issue: dict[str, object]) -> "ScanResultBuilder":
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

    def build(self) -> ScanResult:
        """Return a :class:`ScanResult` snapshot."""
        return ScanResult(
            file_path=self.file_path,
            timestamp=self.timestamp,
            issues=list(self.issues),
            code_objects=self.code_objects,
            paths_explored=self.paths_explored,
            error=self.error,
        )


class ScanSession:
    """Tracks all scans in a session.

    Holds a shared :class:`~pysymex.core.optimization.ConstraintCache`
    that persists across file scans within the session, enabling warm-start
    reuse of satisfiability results.
    """

    def __init__(self, log_file: Path | None = None, cache_size: int = 10_000):
        """Init."""
        """Initialize the class instance."""
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

    def _save_log(self):
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

    def get_summary(self) -> dict[str, object]:
        """Get session summary statistics."""
        total_issues = sum(len(r.issues) for r in self.results)
        issue_counts: dict[str, int] = {}
        for r in self.results:
            for issue in r.issues:
                kind = issue.get("kind", "UNKNOWN")
                issue_counts[kind] = issue_counts.get(kind, 0) + 1
        return {
            "files_scanned": len(self.results),
            "total_issues": total_issues,
            "issue_breakdown": issue_counts,
            "files_with_issues": sum(1 for r in self.results if r.issues),
            "files_clean": sum(1 for r in self.results if not r.issues and not r.error),
            "files_error": sum(1 for r in self.results if r.error),
        }
