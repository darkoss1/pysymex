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

"""Function execution entrypoint orchestration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.detectors.query.storage import collect_detector_query_stats
from pysymex._internal.execution.engine.bytecode.metadata.preparation import (
    prepare_bytecode_execution,
)
from pysymex._internal.execution.engine.exploration import start_path_exploration
from pysymex._internal.execution.engine.finalization import finalize_execution_result
from pysymex._internal.execution.engine.lifecycle import reset_execution_run
from pysymex._internal.execution.engine.seeding import seed_function_execution_context
from pysymex._internal.execution.executors.executor.cache.keys import execution_result_cache_key
from pysymex._internal.execution.executors.executor.entrypoints.cache import clone_execution_result
from pysymex._internal.execution.initial.state.builders import create_function_initial_state
from pysymex._internal.execution.requests.types import ExecutionRequest
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.execution.executors.executor.entrypoints.types import (
        EntrypointInputs,
    )
    from pysymex._internal.execution.results.result import ExecutionResult

logger = get_logger(__name__)


def execute_function_entrypoint(
    inputs: EntrypointInputs,
    func: Callable[..., object],
    symbolic_args: dict[str, str] | None,
    initial_values: dict[str, object] | None,
) -> ExecutionResult:
    """Execute a Python function through the shared executor collaborators."""
    request = ExecutionRequest.from_inputs(func, symbolic_args, initial_values)
    cache_key = None
    if inputs.config.enable_caching and inputs.result_cache is not None:
        cache_key = execution_result_cache_key(
            func=request.func,
            symbolic_args_token=request.cache_symbolic_args_repr,
            initial_values=request.initial_values,
            config=inputs.config,
            active_detectors=inputs.active_detectors,
            executor_version=inputs.result_cache_version,
        )
        cached = inputs.result_cache.get(cache_key)
        if cached is not None:
            return clone_execution_result(cached)
    code = request.code
    reset_execution_run(
        solver=inputs.solver,
        session=inputs.session,
        infrastructure_degraded_passes=inputs.infrastructure_degraded_passes,
        state_merger=inputs.state_merger,
        resource_tracker=inputs.resource_tracker,
        interaction_graph=inputs.interaction_graph,
    )
    prepare_bytecode_execution(
        session=inputs.session,
        dispatcher=inputs.dispatcher,
        code=code,
        bytecode_source=request.func,
    )
    initial_state = create_function_initial_state(
        request.func,
        request.symbolic_arg_map(),
        request.initial_values,
        config=inputs.config,
        session=inputs.session,
    )

    initial_state = seed_function_execution_context(
        initial_state=initial_state,
        func=request.func,
        code=code,
    )
    start_path_exploration(
        session=inputs.session,
        config=inputs.config,
        interaction_graph=inputs.interaction_graph,
        state_merger=inputs.state_merger,
        initial_state=initial_state,
        code=code,
    )

    inputs.execute_loop()
    logger.debug("Executor issues count: %d", len(inputs.session.issues))
    result = finalize_execution_result(
        session=inputs.session,
        enable_fp_filtering=inputs.config.enable_fp_filtering,
        resource_tracker=inputs.resource_tracker,
        solver=inputs.solver,
        detector_query_stats=collect_detector_query_stats(inputs.session),
        state_merger=inputs.state_merger,
        function_name=request.function_name,
        source_file=code.co_filename,
        include_final_stack=True,
        include_final_exception=True,
    )
    if cache_key is not None and inputs.result_cache is not None:
        inputs.result_cache.put(cache_key, clone_execution_result(result))
    return result
