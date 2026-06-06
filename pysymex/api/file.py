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

"""File-loading path for public symbolic analysis."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path

from pysymex.api.conversions import to_bool, to_float, to_int
from pysymex.config import is_object_mapping
from pysymex.execution.results.result import ExecutionResult
from pysymex.logger import get_logger

logger = get_logger(__name__)


def analyze_file_from_path(
    analyze_func: Callable[..., ExecutionResult],
    filepath: str | Path,
    function_name: str,
    symbolic_args: Mapping[str, str] | None = None,
    **kwargs: object,
) -> ExecutionResult:
    """Analyse a function loaded from a Python file."""
    from pysymex.sandbox import (
        PathTraversalError,
        sanitize_function_name,
        validate_config,
        validate_path,
    )

    kwargs_mut = dict(kwargs)
    sandbox_requested = to_bool(kwargs_mut.pop("sandbox", True), True)
    if not sandbox_requested:
        raise ValueError("Disabling sandboxed target loading is unsupported")
    sandbox_config = kwargs_mut.pop("sandbox_config", None)
    sandbox_config_map: dict[str, object] | None = None
    if is_object_mapping(sandbox_config):
        normalized: dict[str, object] = {}
        for key, value in sandbox_config.items():
            normalized[str(key)] = value
        sandbox_config_map = normalized

    try:
        validated_path = validate_path(
            filepath,
            must_exist=True,
            must_be_file=True,
            allowed_extensions=[".py", ".pyw"],
        )
    except PathTraversalError as e:
        logger.warning("Rejected unsafe analysis path %s: %s", filepath, e)
        raise ValueError(f"Security error: {e}") from e

    try:
        safe_name = sanitize_function_name(function_name)
    except ValueError as e:
        logger.warning("Rejected invalid function name %r: %s", function_name, e)
        raise ValueError(f"Invalid function name: {e}") from e

    config_params = validate_config(
        max_paths=to_int(kwargs_mut.get("max_paths", 1000), 1000),
        max_depth=to_int(kwargs_mut.get("max_depth", 100), 100),
        max_iterations=to_int(kwargs_mut.get("max_iterations", 10000), 10000),
        timeout=to_float(kwargs_mut.get("timeout", 60.0), 60.0),
    )

    logger.verbose("Loading analysis target through sandbox: %s", validated_path)
    from pysymex.sandbox.bridge.module import extract_module

    module_blob = extract_module(
        validated_path.read_bytes(),
        str(validated_path),
        sandbox_config=sandbox_config_map,
    )
    func_obj = module_blob.get_function(safe_name)
    max_paths_cfg = to_int(config_params["max_paths"], 1000)
    max_depth_cfg = to_int(config_params["max_depth"], 100)
    max_iterations_cfg = to_int(config_params["max_iterations"], 10000)
    timeout_cfg = to_float(config_params["timeout"], 60.0)

    return analyze_func(
        func_obj,
        symbolic_args,
        max_paths=max_paths_cfg,
        max_depth=max_depth_cfg,
        max_iterations=max_iterations_cfg,
        timeout=timeout_cfg,
        verbose=to_bool(kwargs_mut.get("verbose", False), False),
        detect_division_by_zero=to_bool(kwargs_mut.get("detect_division_by_zero", True), True),
        detect_assertion_errors=to_bool(kwargs_mut.get("detect_assertion_errors", True), True),
        detect_index_errors=to_bool(kwargs_mut.get("detect_index_errors", True), True),
        detect_type_errors=to_bool(kwargs_mut.get("detect_type_errors", True), True),
        detect_overflow=to_bool(kwargs_mut.get("detect_overflow", False), False),
    )
