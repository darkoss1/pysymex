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

"""Statistical and event types for pysymex.

This module defines the schema and type aliases for statistics collection
and performance monitoring within the symbolic execution engine.
"""

from __future__ import annotations

import dataclasses
import enum
import time

MetricValue = float | int | str
MetadataScalar = str | int | float | bool | None
MetadataValue = MetadataScalar | list["MetadataValue"] | dict[str, "MetadataValue"]
Metadata = dict[str, MetadataValue]


def new_metadata() -> Metadata:
    """Return a typed empty metadata map."""
    return {}


class EventType(enum.StrEnum):
    """Statistical event types emitted or consumed by the engine.

    Attributes:
        PATH_EXPLORED: Emitted when a path is successfully explored.
        SOLVER_QUERY: Emitted when an SMT solver query is initiated.
        SOLVER_SAT: Emitted when a solver query returns satisfiable.
        SOLVER_UNSAT: Emitted when a solver query returns unsatisfiable.
        SOLVER_UNKNOWN: Emitted when a solver query returns unknown or times out.
        MEMORY_SAMPLE: Emitted for periodic memory usage samples.
        SCAN_AVG_MEMORY: Emitted with the final per-file scan-average memory value.

    """

    PATH_EXPLORED = "path_explored"
    SOLVER_QUERY = "solver_query"
    SOLVER_SAT = "solver_sat"
    SOLVER_UNSAT = "solver_unsat"
    SOLVER_UNKNOWN = "solver_unknown"
    MEMORY_SAMPLE = "memory_sample"
    SCAN_AVG_MEMORY = "scan_avg_memory"


@dataclasses.dataclass(slots=True)
class Event:
    """Represents a statistical or performance event emitted by the engine.

    Attributes:
        type: The type of the recorded event.
        value: A numeric metric associated with the event (e.g., duration, count).
        timestamp_ns: High-resolution timestamp of when the event occurred, in nanoseconds.
        metadata: Auxiliary key-value mapping containing additional context.

    """

    type: EventType
    value: float
    timestamp_ns: int = dataclasses.field(default_factory=time.perf_counter_ns)
    metadata: Metadata = dataclasses.field(default_factory=new_metadata)
