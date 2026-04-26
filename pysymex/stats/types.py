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

from __future__ import annotations

import dataclasses
import enum
import time
from typing import TypeAlias

MetricValue: TypeAlias = float | int | str
MetadataScalar: TypeAlias = str | int | float | bool | None
MetadataValue: TypeAlias = MetadataScalar | list["MetadataValue"] | dict[str, "MetadataValue"]
Metadata: TypeAlias = dict[str, MetadataValue]


def _new_metadata() -> Metadata:
    """Return a typed empty metadata map."""
    return {}


class EventType(str, enum.Enum):
    PATH_EXPLORED = "path_explored"
    PATH_PRUNED = "path_pruned"
    SOLVER_QUERY = "solver_query"
    SOLVER_SAT = "solver_sat"
    SOLVER_UNSAT = "solver_unsat"
    SOLVER_UNKNOWN = "solver_unknown"
    MEMORY_SAMPLE = "memory_sample"
    CPU_SAMPLE = "cpu_sample"
    BUG_FOUND = "bug_found"
    CODE_COVERAGE = "code_coverage"


@dataclasses.dataclass(slots=True)
class Event:
    type: EventType
    value: float
    timestamp_ns: int = dataclasses.field(default_factory=time.perf_counter_ns)
    metadata: Metadata = dataclasses.field(default_factory=_new_metadata)
