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

"""Detector-obligation state selection for runtime CEGIS execution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex._internal.execution.frontier.store.core import FrontierWorkStore

_DetectorCandidate = tuple[int, int, str, int]


@dataclass(slots=True)
class DetectorExecutionSelectionCache:
    """Cache detector-state selection for unchanged frontier inputs."""

    frontier_id: int | None = None
    frontier_version: int = -1
    state_id: int | None = None

    def select(self, frontier: FrontierWorkStore) -> int | None:
        """Return the best live detector-obligation state for immediate execution."""
        frontier_id = id(frontier)
        frontier_version = frontier.selection_version
        if self._matches(frontier_id, frontier_version):
            selected_state_id = self.state_id
            if selected_state_id is None or selected_state_id in frontier:
                return selected_state_id

        selected = _runtime_feature_candidate(frontier)
        if selected is None:
            selected = _capsule_candidate(frontier)

        selected_state_id = selected[3] if selected is not None else None
        self._store(frontier_id, frontier_version, selected_state_id)
        return selected_state_id

    def _matches(self, frontier_id: int, frontier_version: int) -> bool:
        return self.frontier_id == frontier_id and self.frontier_version == frontier_version

    def _store(self, frontier_id: int, frontier_version: int, state_id: int | None) -> None:
        self.frontier_id = frontier_id
        self.frontier_version = frontier_version
        self.state_id = state_id


def _runtime_feature_candidate(frontier: FrontierWorkStore) -> _DetectorCandidate | None:
    live_entries = frontier.entries
    best_state_id: int | None = None
    best_detector_count = 0
    best_resident_units = 0
    best_capsule_id = ""
    for state_id, features in frontier.runtime_features.items():
        if state_id not in live_entries:
            continue
        detector_count = features.detector_obligation_count
        if detector_count <= 0:
            continue
        resident_units = features.estimated_resident_units
        capsule_id = features.capsule_id
        if best_state_id is None or _is_better_candidate(
            detector_count,
            resident_units,
            capsule_id,
            state_id,
            best_detector_count,
            best_resident_units,
            best_capsule_id,
            best_state_id,
        ):
            best_state_id = state_id
            best_detector_count = detector_count
            best_resident_units = resident_units
            best_capsule_id = capsule_id
    if best_state_id is None:
        return None
    return (
        -best_detector_count,
        best_resident_units,
        best_capsule_id,
        best_state_id,
    )


def _is_better_candidate(
    detector_count: int,
    resident_units: int,
    capsule_id: str,
    state_id: int,
    best_detector_count: int,
    best_resident_units: int,
    best_capsule_id: str,
    best_state_id: int,
) -> bool:
    """Return whether a candidate outranks the current detector-first best."""
    if detector_count != best_detector_count:
        return detector_count > best_detector_count
    return (resident_units, capsule_id, state_id) < (
        best_resident_units,
        best_capsule_id,
        best_state_id,
    )


def _capsule_candidate(frontier: FrontierWorkStore) -> _DetectorCandidate | None:
    live_entries = frontier.entries
    best_state_id: int | None = None
    best_detector_count = 0
    best_resident_units = 0
    best_capsule_id = ""
    for state_id, capsule in frontier.capsules.items():
        if state_id not in live_entries:
            continue
        detector_count = capsule.footprint.detector_obligation_count
        if detector_count <= 0:
            continue
        resident_units = capsule.estimated_resident_units
        capsule_id = capsule.capsule_id
        if best_state_id is None or _is_better_candidate(
            detector_count,
            resident_units,
            capsule_id,
            state_id,
            best_detector_count,
            best_resident_units,
            best_capsule_id,
            best_state_id,
        ):
            best_state_id = state_id
            best_detector_count = detector_count
            best_resident_units = resident_units
            best_capsule_id = capsule_id
    if best_state_id is None:
        return None
    return (
        -best_detector_count,
        best_resident_units,
        best_capsule_id,
        best_state_id,
    )
