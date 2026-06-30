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

"""Compiled-code execution entrypoint orchestration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.detectors.query.storage import collect_detector_query_stats
from pysymex._internal.execution.engine.bytecode.metadata.preparation import (
    prepare_bytecode_execution,
)
from pysymex._internal.execution.engine.exploration import start_path_exploration
from pysymex._internal.execution.engine.finalization import finalize_execution_result
from pysymex._internal.execution.engine.lifecycle import reset_execution_run
from pysymex._internal.execution.initial.state.code.state import create_code_initial_state
from pysymex._internal.execution.requests.types import CodeExecutionRequest

if TYPE_CHECKING:
    import types

    from pysymex._internal.execution.executors.executor.entrypoints.types import (
        EntrypointInputs,
    )
    from pysymex._internal.execution.results.result import ExecutionResult


def execute_code_entrypoint(
    inputs: EntrypointInputs,
    code: types.CodeType,
    symbolic_vars: dict[str, str] | None,
    initial_globals: dict[str, object] | None,
    *,
    symbolic_vars_are_inferred: bool,
) -> ExecutionResult:
    """Execute a compiled code object through the shared executor collaborators."""
    request = CodeExecutionRequest.from_inputs(code, symbolic_vars, initial_globals)
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
        code=request.code,
        bytecode_source=request.code,
    )

    initial_state = create_code_initial_state(
        request.code,
        request.symbolic_vars,
        request.initial_globals,
        symbolic_vars_are_inferred=symbolic_vars_are_inferred,
    )
    start_path_exploration(
        session=inputs.session,
        config=inputs.config,
        interaction_graph=inputs.interaction_graph,
        state_merger=inputs.state_merger,
        initial_state=initial_state,
        code=request.code,
    )

    inputs.execute_loop()
    return finalize_execution_result(
        session=inputs.session,
        enable_fp_filtering=inputs.config.enable_fp_filtering,
        resource_tracker=inputs.resource_tracker,
        solver=inputs.solver,
        detector_query_stats=collect_detector_query_stats(inputs.session),
        state_merger=inputs.state_merger,
        function_name=request.code.co_name,
        source_file=request.code.co_filename,
        include_final_stack=False,
        include_final_exception=False,
    )
