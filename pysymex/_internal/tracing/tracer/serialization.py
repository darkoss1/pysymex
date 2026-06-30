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

"""Trace serialization helpers and writer protocol for execution tracing."""

from __future__ import annotations

import json
from itertools import islice
from time import perf_counter_ns
from typing import TYPE_CHECKING, Protocol

from pysymex._internal.logging.root import get_logger
from pysymex._internal.tracing.schemas.primitives import ConstraintEntry

if TYPE_CHECKING:
    from collections.abc import Iterable

    from pysymex._internal.tracing.z3.serializer import Z3Serializer

logger = get_logger(__name__)


class TraceWriter(Protocol):
    """Protocol for a file-like writer used by the execution tracer."""

    def write(self, s: str, /) -> int:
        """Write string to stream."""
        ...

    def flush(self) -> None:
        """Flush stream."""
        ...

    def close(self) -> None:
        """Close stream."""
        ...


class TraceSerialization:
    """Domain owner for tracer config coercion and Z3 excerpt serialization."""

    @staticmethod
    def scalar(value: object) -> str | int | float | bool | None:
        """Coerce arbitrary config values into schema-safe scalar values.

        ``SystemContextEvent.tracer_config`` accepts only scalar values. Nested
        structures (e.g. dict/list) and enums are serialised to stable JSON strings.
        """
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        try:
            return json.dumps(value, default=str, sort_keys=True)
        except Exception:
            logger.debug("Failed to JSON-serialize trace config value", exc_info=True)
            return str(value)

    @staticmethod
    def config_snapshot(
        snapshot: dict[str, object],
    ) -> dict[str, str | int | float | bool | None]:
        """Convert a raw config snapshot to ``SystemContextEvent`` scalar schema."""
        return {str(key): TraceSerialization.scalar(value) for key, value in snapshot.items()}

    @staticmethod
    def elapsed_ms(start_ns: int | None) -> float | None:
        """Return elapsed milliseconds since a monotonic start timestamp."""
        if start_ns is None:
            return None
        elapsed_ns = perf_counter_ns() - start_ns
        return round(max(elapsed_ns, 0) / 1_000_000.0, 3)

    @staticmethod
    def constraint_entries(
        serializer: Z3Serializer,
        constraints: Iterable[object],
        causality: str,
        *,
        limit: int,
    ) -> list[ConstraintEntry]:
        """Serialize path constraints into trace schema entries with a display limit."""
        bounded_constraints = islice(constraints, max(limit, 0))
        raw_entries = serializer.constraints_to_smtlib(bounded_constraints, causality)
        return [
            ConstraintEntry(smtlib=entry["smtlib"], causality=entry["causality"])
            for entry in raw_entries
        ]

    @staticmethod
    def model_excerpt(
        serializer: Z3Serializer,
        model: object,
        *,
        max_vars: int,
        failure_message: str,
    ) -> dict[str, str] | None:
        """Serialize a bounded Z3 model excerpt without letting tracing fail."""
        if model is None:
            return None
        try:
            return serializer.serialize_model(model, max_vars=max_vars)
        except Exception:
            logger.debug(failure_message, exc_info=True)
            return None
