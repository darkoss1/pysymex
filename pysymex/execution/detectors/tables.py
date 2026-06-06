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

"""Detector dispatch-table construction for execution runs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex.analysis.detectors import Detector

if TYPE_CHECKING:
    from pysymex.analysis.detectors import DetectorRegistry
    from pysymex.execution.config.settings import ExecutionConfig

__all__ = [
    "DetectorRuntimeTables",
    "add_detector_to_dispatch",
    "build_detector_runtime_tables",
]


@dataclass(frozen=True, slots=True)
class DetectorRuntimeTables:
    """Detector lists used by the instruction-step dispatch path."""

    active_detectors: list[Detector]
    detector_dispatch: dict[str, list[Detector]]
    universal_detectors: list[Detector]


def build_detector_runtime_tables(
    *,
    config: ExecutionConfig,
    detector_registry: DetectorRegistry,
) -> DetectorRuntimeTables:
    """Build active detector lists and opcode dispatch tables from configuration."""
    disabled_names = _disabled_detector_names(config)
    active_detectors = [
        detector for detector in detector_registry.get_all() if detector.name not in disabled_names
    ]
    detector_dispatch: dict[str, list[Detector]] = {}
    universal_detectors: list[Detector] = []
    for detector in active_detectors:
        add_detector_to_dispatch(
            detector=detector,
            detector_dispatch=detector_dispatch,
            universal_detectors=universal_detectors,
        )
    return DetectorRuntimeTables(
        active_detectors=active_detectors,
        detector_dispatch=detector_dispatch,
        universal_detectors=universal_detectors,
    )


def add_detector_to_dispatch(
    *,
    detector: Detector,
    detector_dispatch: dict[str, list[Detector]],
    universal_detectors: list[Detector],
) -> None:
    """Register one detector in runtime dispatch tables."""
    opcodes = detector.relevant_opcodes
    if not opcodes:
        universal_detectors.append(detector)
        return
    for opcode in opcodes:
        detector_dispatch.setdefault(opcode, []).append(detector)


def _disabled_detector_names(config: ExecutionConfig) -> set[str]:
    """Return detector names disabled by execution configuration."""
    disabled_names: set[str] = set()
    if not config.detect_division_by_zero:
        disabled_names.add("division-by-zero")
    if not config.detect_assertion_errors:
        disabled_names.add("assertion-error")
    if not config.detect_index_errors:
        disabled_names.add("index-error")
    if not config.detect_type_errors:
        disabled_names.add("type-error")
    if not config.detect_overflow:
        disabled_names.update({"overflow", "bounded-overflow"})
    if not config.detect_value_errors:
        disabled_names.add("value-error")
    return disabled_names
