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

"""Tracer configuration schema."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from pysymex.config.defaults import (
    DEFAULT_TRACE_COMPRESSION_LEVEL,
    DEFAULT_TRACE_DELTA_BATCH_SIZE,
    DEFAULT_TRACE_ENABLED,
    DEFAULT_TRACE_KEYFRAME_ON_FORK,
    DEFAULT_TRACE_KEYFRAME_ON_ISSUE,
    DEFAULT_TRACE_KEYFRAME_ON_PRUNE,
    DEFAULT_TRACE_MAX_CONSTRAINT_DISPLAY,
    DEFAULT_TRACE_OUTPUT_DIR,
    DEFAULT_TRACE_VERBOSITY,
)
from pysymex.config.environment import read_trace_environment


class VerbosityLevel(StrEnum):
    """Controls how much data the tracer emits."""

    QUIET = "quiet"
    DELTA_ONLY = "delta_only"
    FULL = "full"


class TracerConfig(BaseModel):
    """Runtime configuration for ExecutionTracer."""

    model_config = ConfigDict(frozen=True)

    output_dir: str = DEFAULT_TRACE_OUTPUT_DIR
    verbosity: VerbosityLevel = VerbosityLevel(DEFAULT_TRACE_VERBOSITY)
    delta_batch_size: int = Field(default=DEFAULT_TRACE_DELTA_BATCH_SIZE, gt=0)
    keyframe_on_fork: bool = DEFAULT_TRACE_KEYFRAME_ON_FORK
    keyframe_on_prune: bool = DEFAULT_TRACE_KEYFRAME_ON_PRUNE
    keyframe_on_issue: bool = DEFAULT_TRACE_KEYFRAME_ON_ISSUE
    max_constraint_display: int = Field(default=DEFAULT_TRACE_MAX_CONSTRAINT_DISPLAY, gt=0)
    compression_level: int = Field(default=DEFAULT_TRACE_COMPRESSION_LEVEL, ge=0, le=9)
    enabled: bool = DEFAULT_TRACE_ENABLED
    """Tracing is **opt-in**.  Set ``enabled=True`` explicitly, or set the
    ``PY_SYMEX_TRACE=1`` environment variable and call :meth:`from_env`."""

    @classmethod
    def from_env(cls, **overrides: object) -> TracerConfig:
        """Construct a :class:`TracerConfig` whose ``enabled`` flag is driven
        by the ``PY_SYMEX_TRACE`` environment variable.

        The variable is considered *truthy* when its lowercased value is one
        of ``"1"``, ``"true"``, ``"yes"``, or ``"on"``.

        Any keyword arguments in *overrides* are forwarded verbatim to the
        constructor and take precedence over env-var resolution.

        Args:
            **overrides: Any :class:`TracerConfig` field values that should
                         override env-var-resolved defaults.

        Returns:
            A new :class:`TracerConfig` instance.

        Example::

            # Enable tracing with a custom output directory, driven by env:
            cfg = TracerConfig.from_env(output_dir="/tmp/my_traces")
        """
        trace_env = read_trace_environment()

        return cls(
            enabled=overrides.pop("enabled", trace_env.enabled),
            compression_level=overrides.pop("compression_level", trace_env.compression_level),
            **overrides,
        )


__all__ = ["TracerConfig", "VerbosityLevel"]
