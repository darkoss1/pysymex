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

"""Shared backend typing contracts for acceleration backends.

This module centralizes backend metadata and error types so all backend
implementations can share one strongly-typed interface.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class BackendType(str, Enum):
    """Acceleration backend kinds."""

    SAT = "sat"
    CPU = "cpu"
    REFERENCE = "reference"


@dataclass(frozen=True, slots=True)
class BackendInfo:
    """Capabilities and runtime status for a backend implementation."""

    backend_type: BackendType
    name: str
    available: bool
    max_treewidth: int
    supports_async: bool = False
    device_memory_mb: int = 0
    compute_units: int = 1
    throughput_estimate: float | None = None
    error_message: str | None = None


class BackendError(RuntimeError):
    """Raised when a backend cannot execute a requested operation."""


__all__ = [
    "BackendError",
    "BackendInfo",
    "BackendType",
]
