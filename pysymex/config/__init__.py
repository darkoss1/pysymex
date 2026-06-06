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

"""Public configuration API for pysymex."""

from __future__ import annotations

from pysymex.config.defaults import (
    CONFIG_FILE_NAMES,
    DEFAULT_ANALYZE_MAX_PATHS,
    DEFAULT_ANALYZE_TIMEOUT_SECONDS,
    DEFAULT_LIMIT_MAX_DEPTH,
    DEFAULT_LIMIT_MAX_ITERATIONS,
    DEFAULT_LIMIT_MAX_PATHS,
    DEFAULT_LIMIT_TIMEOUT_SECONDS,
    DEFAULT_SCAN_MAX_ITERATIONS,
    DEFAULT_SCAN_MAX_PATHS,
    DEFAULT_SCAN_MODE,
    DEFAULT_SCAN_OUTPUT_FORMAT,
    DEFAULT_SCAN_RANDOM_SEED,
    DEFAULT_SCAN_SANDBOX,
    DEFAULT_SCAN_TIMEOUT_SECONDS,
    DEFAULT_SCAN_WORKERS,
    DEFAULT_SCANNER_DIRECTORY_MAX_PATHS,
    DEFAULT_SCANNER_FILE_MAX_PATHS,
    DEFAULT_SCANNER_TIMEOUT_SECONDS,
    DEFAULT_TRACE_COMPRESSION_LEVEL,
    DEFAULT_TRACE_OUTPUT_DIR,
    DEFAULT_TRACE_VERBOSITY,
    DEFAULT_VERIFIED_INTEGER_BITS,
    DEFAULT_VERIFIED_SOLVER_TIMEOUT_MS,
    DEFAULT_VERIFIED_TERMINATION_TIMEOUT_MS,
    SCAN_MODE_CHOICES,
    SCAN_OUTPUT_FORMAT_CHOICES,
    TRACE_VERBOSITY_CHOICES,
    VERSION,
)
from pysymex.config.environment import (
    TraceEnvironment,
    async_scanner_process_pool_enabled,
    env_flag,
    env_int,
    false_positive_filter_enabled,
    read_trace_environment,
    scanner_issue_dedup_enabled,
)
from pysymex.config.helpers import (
    is_object_collection,
    is_object_dict,
    is_object_list,
    is_object_mapping,
    normalize_object_dict,
    normalize_string_list,
)
from pysymex.config.io import (
    CONFIG_FILES,
    apply_config,
    find_config_file,
    generate_default_config,
    init_config,
    load_config,
)

from pysymex.config.root import PysymexConfig
from pysymex.config.sections import (
    AnalysisConfig,
    AnalysisLimits,
    ConcurrencyConfig,
    DetectorConfig,
    OutputConfig,
    SolverConfig,
)

__all__ = [
    "CONFIG_FILE_NAMES",
    "CONFIG_FILES",
    "AnalysisConfig",
    "AnalysisLimits",
    "ConcurrencyConfig",
    "DEFAULT_ANALYZE_MAX_PATHS",
    "DEFAULT_ANALYZE_TIMEOUT_SECONDS",
    "DEFAULT_LIMIT_MAX_DEPTH",
    "DEFAULT_LIMIT_MAX_ITERATIONS",
    "DEFAULT_LIMIT_MAX_PATHS",
    "DEFAULT_LIMIT_TIMEOUT_SECONDS",
    "DEFAULT_SCAN_MAX_ITERATIONS",
    "DEFAULT_SCAN_MAX_PATHS",
    "DEFAULT_SCAN_MODE",
    "DEFAULT_SCAN_OUTPUT_FORMAT",
    "DEFAULT_SCAN_RANDOM_SEED",
    "DEFAULT_SCAN_SANDBOX",
    "DEFAULT_SCAN_TIMEOUT_SECONDS",
    "DEFAULT_SCAN_WORKERS",
    "DEFAULT_SCANNER_DIRECTORY_MAX_PATHS",
    "DEFAULT_SCANNER_FILE_MAX_PATHS",
    "DEFAULT_SCANNER_TIMEOUT_SECONDS",
    "DEFAULT_TRACE_COMPRESSION_LEVEL",
    "DEFAULT_TRACE_OUTPUT_DIR",
    "DEFAULT_TRACE_VERBOSITY",
    "DEFAULT_VERIFIED_INTEGER_BITS",
    "DEFAULT_VERIFIED_SOLVER_TIMEOUT_MS",
    "DEFAULT_VERIFIED_TERMINATION_TIMEOUT_MS",
    "DetectorConfig",
    "OutputConfig",
    "PysymexConfig",
    "SCAN_MODE_CHOICES",
    "SCAN_OUTPUT_FORMAT_CHOICES",
    "SolverConfig",
    "TRACE_VERBOSITY_CHOICES",
    "TraceEnvironment",
    "VERSION",
    "apply_config",
    "async_scanner_process_pool_enabled",
    "env_flag",
    "env_int",
    "false_positive_filter_enabled",
    "is_object_collection",
    "is_object_dict",
    "is_object_list",
    "normalize_object_dict",
    "normalize_string_list",
    "find_config_file",
    "generate_default_config",
    "init_config",
    "is_object_mapping",
    "load_config",
    "read_trace_environment",
    "scanner_issue_dedup_enabled",
]
