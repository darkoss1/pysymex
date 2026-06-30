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

"""Canonical configuration defaults used across pysymex."""

from __future__ import annotations

from typing import Final

__version__ = "0.1.1a2"
VERSION: Final = __version__

DEFAULT_ENGINE_SOLVER_TIMEOUT_MS: Final = 5000

DEFAULT_DETECT_OVERFLOW: Final = False

DEFAULT_LIMIT_MAX_MEMORY_MB: Final[int | None] = None
DEFAULT_LIMIT_MAX_CONSTRAINT_SIZE: Final[int | None] = None

DEFAULT_OUTPUT_FORMAT: Final = "text"
SCAN_OUTPUT_FORMAT_CHOICES: Final = ("text", "json", "sarif", "rich", "html", "markdown")
DEFAULT_SCAN_OUTPUT_FORMAT: Final = "text"
DEFAULT_SCAN_MAX_PATHS: Final[int | None] = None
DEFAULT_SCAN_MAX_DEPTH: Final[int | None] = None
DEFAULT_SCAN_TIMEOUT_SECONDS: Final[float | None] = None
DEFAULT_SCAN_WORKERS: Final = 0
DEFAULT_SCAN_MAX_ITERATIONS: Final[int | None] = None
DEFAULT_SCAN_SANDBOX: Final = True

DEFAULT_SCANNER_FILE_MAX_PATHS: Final[int | None] = None
DEFAULT_SCANNER_FILE_MAX_DEPTH: Final = DEFAULT_SCAN_MAX_DEPTH
DEFAULT_SCANNER_DIRECTORY_MAX_PATHS: Final[int | None] = None
DEFAULT_SCANNER_DIRECTORY_MAX_DEPTH: Final = DEFAULT_SCAN_MAX_DEPTH
DEFAULT_SCANNER_TIMEOUT_SECONDS: Final[float | None] = None
DEFAULT_SCANNER_DIRECTORY_TIMEOUT_SECONDS: Final[float | None] = None
DEFAULT_SCANNER_CLI_DIRECTORY: Final = "."
DEFAULT_SCANNER_CLI_RECURSIVE: Final = True
DEFAULT_SCANNER_CLI_WORKERS: Final = 0
DEFAULT_SCANNER_CLI_MAX_ITERATIONS: Final[int | None] = None

DEFAULT_ASYNC_SCANNER_PROCESS_POOL: Final = True

DEFAULT_ANALYZE_MAX_PATHS: Final[int | None] = None
DEFAULT_ANALYZE_TIMEOUT_SECONDS: Final[float | None] = None
DEFAULT_BENCHMARK_ITERATIONS: Final = 1

DEFAULT_VERIFIED_SOLVER_TIMEOUT_MS: Final = 250

DEFAULT_TRACE_OUTPUT_DIR: Final = ".pysymex/traces"
TRACE_VERBOSITY_CHOICES: Final = ("quiet", "delta_only", "full")
DEFAULT_TRACE_VERBOSITY: Final = "delta_only"
DEFAULT_TRACE_ENABLED: Final = False
DEFAULT_TRACE_DELTA_BATCH_SIZE: Final = 50
DEFAULT_TRACE_KEYFRAME_ON_FORK: Final = True
DEFAULT_TRACE_KEYFRAME_ON_PRUNE: Final = True
DEFAULT_TRACE_KEYFRAME_ON_ISSUE: Final = True
DEFAULT_TRACE_MAX_CONSTRAINT_DISPLAY: Final = 50
DEFAULT_TRACE_COMPRESSION_LEVEL: Final = 6

DEFAULT_PROFILE_OUTPUT_DIR: Final = ".pysymex/profiles"
DEFAULT_PROFILE_MODE: Final = "sample"
PROFILE_MODE_CHOICES: Final = ("sample", "cprofile")
DEFAULT_PROFILE_SAMPLE_INTERVAL_MS: Final = 5.0
