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

"""Scanner result and serialization types."""

import json
from dataclasses import dataclass, field

from pysymex._internal.analysis.records import IssueRecord
from pysymex._internal.core.outcome import (
    AnalysisOutcome,
    OutcomeEvidence,
    OutcomePolicy,
)
from pysymex._internal.guards import RuntimeObjectGuards

SerializedScalar = str | int | float | bool | None
SerializedValue = SerializedScalar | list["SerializedValue"] | dict[str, "SerializedValue"]


def _new_issue_records() -> list[IssueRecord]:
    """Create an empty typed list of scanner issues."""
    return []


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
        paths_pruned: Total paths removed by exact feasibility or resource policy.
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
    paths_pruned: int = 0
    elapsed_time: float = 0.0
    avg_memory_mb: float = 0.0
    error: str | None = None
    degraded_passes: list[str] = field(default_factory=list[str])
    outcome_evidence: list[OutcomeEvidence] = field(default_factory=list[OutcomeEvidence])
    solver_stats: dict[str, object] = field(default_factory=dict[str, object])

    @property
    def outcome(self) -> AnalysisOutcome:
        """Return the top-level outcome classification of this scan."""
        return OutcomePolicy.classify(
            self.issues,
            self.degraded_passes,
            self.outcome_evidence,
        )[0]

    @property
    def outcome_subreason(self) -> str | None:
        """Return the detailed subreason for this scan's outcome classification."""
        return OutcomePolicy.classify(
            self.issues,
            self.degraded_passes,
            self.outcome_evidence,
        )[1]

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
            if RuntimeObjectGuards.dict(obj):
                serialized_map: dict[str, SerializedValue] = {}
                for key_obj, value_obj in obj.items():
                    serialized_map[str(key_obj)] = _serialize(value_obj)
                return serialized_map
            if RuntimeObjectGuards.list(obj) or RuntimeObjectGuards.tuple(obj):
                serialized_items: list[SerializedValue] = []
                for item_obj in obj:
                    serialized_items.append(_serialize(item_obj))
                return serialized_items
            if RuntimeObjectGuards.set(obj) or RuntimeObjectGuards.frozenset(obj):
                serialized_items = [_serialize(item_obj) for item_obj in obj]
                return sorted(
                    serialized_items,
                    key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
                )
            return str(obj)

        outcome, outcome_subreason = OutcomePolicy.classify(
            self.issues,
            self.degraded_passes,
            self.outcome_evidence,
        )
        return {
            "file": self.file_path,
            "timestamp": self.timestamp,
            "issues": _serialize(self.issues),
            "code_objects": self.code_objects,
            "paths_explored": self.paths_explored,
            "paths_pruned": self.paths_pruned,
            "elapsed_time": self.elapsed_time,
            "avg_memory_mb": self.avg_memory_mb,
            "error": self.error,
            "degraded_passes": _serialize(self.degraded_passes),
            "outcome_evidence": _serialize(OutcomePolicy.serialize_evidence(self.outcome_evidence)),
            "solver_stats": _serialize(self.solver_stats),
            "outcome": outcome.value,
            "outcome_subreason": outcome_subreason,
        }

    def __repr__(self) -> str:
        """Return a formatted string representation of the ScanResult instance.

        Returns:
            Developer-friendly representation of path, issue count, and errors.

        """
        return f"ScanResult({self.file_path}, issues={len(self.issues)}, error={self.error})"
