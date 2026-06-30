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

"""Shared constants and result types for Windows AppContainer isolation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from pysymex._internal.sandbox.types import ExecutionStatus

RUNTIME_EXCLUDED_DIR_NAMES: Final[frozenset[str]] = frozenset(
    ("__pycache__", "ensurepip", "idlelib", "site-packages", "test", "tkinter", "venv"),
)
RUNTIME_EXCLUDED_FILE_PREFIXES: Final[tuple[str, ...]] = ("_test", "test_")
RUNTIME_ALLOWED_NATIVE_EXTENSIONS: Final[frozenset[str]] = frozenset()
RUNTIME_CACHE_SCHEMA: Final[int] = 1
RUNTIME_CACHE_POLICY_VERSION: Final[str] = "filtered-cpython-v3-sha512-256"
RUNTIME_MANIFEST_FILENAME: Final[str] = ".pysymex-runtime-manifest.json"
RUNTIME_CACHE_DIRNAME: Final[str] = "pysymex-appcontainer-runtime"
ALL_APPLICATION_PACKAGES_SID: Final[str] = "S-1-15-2-1"
ALL_RESTRICTED_APPLICATION_PACKAGES_SID: Final[str] = "S-1-15-2-2"
LPAC_CAPABILITY_NAMES: Final[tuple[str, ...]] = ("registryRead",)
# Bounded output budget for the pysymex-generated setup self-check. It is
# independent of the caller's ``max_output_bytes`` so a tightened user limit
# cannot misclassify the self-check's own small diagnostic JSON as an
# output-limit violation, while still capping genuinely runaway output.
SELF_CHECK_OUTPUT_LIMIT: Final[int] = 64 * 1024


@dataclass(slots=True)
class NativeProcessResult:
    """Telemetry and output from running a native Windows process."""

    status: ExecutionStatus
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    wall_time_ms: float
    error_message: str | None = None
    blocked_operations: tuple[str, ...] = ()
