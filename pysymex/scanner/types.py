"""
pysymex Scanner – type definitions
=====================================
Dataclasses and session-tracking types used by the scanner subsystem.
"""

import json

from dataclasses import dataclass, field

from datetime import datetime

from pathlib import Path

from typing import Any


@dataclass
class ScanResult:
    """Result of scanning a single file."""

    file_path: str

    timestamp: str

    issues: list[dict[str, Any]] = field(default_factory=list[dict[str, Any]])

    code_objects: int = 0

    paths_explored: int = 0

    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file_path,
            "timestamp": self.timestamp,
            "issues": self.issues,
            "code_objects": self.code_objects,
            "paths_explored": self.paths_explored,
            "error": self.error,
        }

    def __repr__(self) -> str:
        return f"ScanResult({self.file_path}, issues={len(self.issues)}, error={self.error})"


class ScanSession:
    """Tracks all scans in a session."""

    def __init__(self, log_file: Path | None = None):
        self.results: list[ScanResult] = []

        self.start_time = datetime.now()

        self.log_file = log_file or Path(
            f"scan_log_{self.start_time.strftime('%Y%m%d_%H%M%S')}.json"
        )

    def add_result(self, result: ScanResult):
        self.results.append(result)

        self._save_log()

    def _save_log(self):
        """Save results to log file."""

        log_data = {
            "session_start": self.start_time.isoformat(),
            "last_update": datetime.now().isoformat(),
            "total_files": len(self.results),
            "total_issues": sum(len(r.issues) for r in self.results),
            "scans": [r.to_dict() for r in self.results],
        }

        with open(self.log_file, "w", encoding="utf-8") as f:
            json.dump(log_data, f, indent=2)

    def get_summary(self) -> dict[str, Any]:
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
