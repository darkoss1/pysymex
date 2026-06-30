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

"""Environment-variable parsing for pysymex configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.config.defaults import (
    DEFAULT_ASYNC_SCANNER_PROCESS_POOL,
    DEFAULT_TRACE_COMPRESSION_LEVEL,
    DEFAULT_TRACE_ENABLED,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

TRUTHY_ENV_VALUES = frozenset(("1", "true", "yes", "on"))
FALSY_ENV_VALUES = frozenset(("0", "false", "no", "off"))


@dataclass(frozen=True, slots=True)
class TraceEnvironment:
    """Trace-related settings resolved from environment variables."""

    enabled: bool
    compression_level: int


def env_flag(value: str | None, *, default: bool = False) -> bool:
    """Resolve common truthy/falsy environment strings to a boolean."""
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in TRUTHY_ENV_VALUES:
        return True
    if normalized in FALSY_ENV_VALUES:
        return False
    return default


def env_int(value: str | None, *, default: int) -> int:
    """Parse a non-negative integer environment value or return ``default``."""
    if value is None:
        return default
    normalized = value.strip()
    if normalized.isdigit():
        return int(normalized)
    return default


def read_trace_environment(environ: Mapping[str, str] | None = None) -> TraceEnvironment:
    """Read tracing environment variables."""
    source = os.environ if environ is None else environ
    return TraceEnvironment(
        enabled=env_flag(source.get("PY_SYMEX_TRACE"), default=DEFAULT_TRACE_ENABLED),
        compression_level=env_int(
            source.get("PY_SYMEX_TRACE_COMPRESSION"),
            default=DEFAULT_TRACE_COMPRESSION_LEVEL,
        ),
    )


def async_scanner_process_pool_enabled(environ: Mapping[str, str] | None = None) -> bool:
    """Return whether the async scanner should use the process-pool worker path."""
    source = os.environ if environ is None else environ
    return env_flag(
        source.get("PYSYMEX_ASYNC_USE_PROCESS_POOL"),
        default=DEFAULT_ASYNC_SCANNER_PROCESS_POOL,
    )


def scanner_issue_dedup_enabled(environ: Mapping[str, str] | None = None) -> bool:
    """Return whether scanner issue de-duplication is enabled."""
    source = os.environ if environ is None else environ
    return not env_flag(source.get("PYSYMEX_DISABLE_ISSUE_DEDUP"), default=False)


def false_positive_filter_enabled(environ: Mapping[str, str] | None = None) -> bool:
    """Return whether detector false-positive filtering is enabled."""
    source = os.environ if environ is None else environ
    return not env_flag(source.get("PYSYMEX_DISABLE_FP_FILTER"), default=False)
