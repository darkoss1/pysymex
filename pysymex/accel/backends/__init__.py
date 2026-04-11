"""Shared backend typing contracts for acceleration backends.

This module centralizes backend metadata and error types so all backend
implementations can share one strongly-typed interface.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class BackendType(str, Enum):
	"""Acceleration backend kinds."""

	GPU = "gpu"
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
