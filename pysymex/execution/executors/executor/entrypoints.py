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

"""Scan entrypoints that drive public execution through executor mixins.

Owns ``execute_function`` and ``execute_code``: bytecode preparation, initial
``VMState`` construction through ``execution.initial_state``, worklist
exploration (``ExecutorLoopMixin``), and cache handoff around engine-owned
finalization.
"""

from __future__ import annotations

import types
from collections.abc import Callable
from dataclasses import replace
from typing import TYPE_CHECKING, cast

from pysymex.logger import get_logger
from pysymex.analysis.detectors import Issue
from pysymex.execution.detectors.query.cache import collect_detector_query_stats
from pysymex.execution.engine import (
    finalize_execution_result,
    prepare_bytecode_execution,
    reset_execution_run,
    run_optional_function_prepasses,
    seed_function_execution_context,
    start_path_exploration,
)
from pysymex.execution.executors.executor.types import ExecutorMixinContract
from pysymex.execution.initial_state.builders import (
    create_code_initial_state,
    create_function_initial_state,
)
from pysymex.execution.requests.types import CodeExecutionRequest, FunctionExecutionRequest
from pysymex.execution.results.result import ExecutionResult
from pysymex.execution.executors.executor.cache.keys import execution_result_cache_key

if TYPE_CHECKING:
    from pysymex.typing import StackValue

logger = get_logger(__name__)


def _clone_execution_result(result: ExecutionResult) -> ExecutionResult:
    """Return a container-isolated copy of a cached execution result."""
    return replace(
        result,
        issues=list(result.issues),
        coverage=set(result.coverage),
        final_globals=dict(result.final_globals),
        final_locals=dict(result.final_locals),
        final_stack=list(result.final_stack),
        branches=list(result.branches),
        solver_stats=dict(result.solver_stats),
        degraded_passes=list(result.degraded_passes),
    )


class ExecutorEntrypointMixin(ExecutorMixinContract):
    """High-level scan entrypoints and finalization handoff.

    Prepares bytecode metadata, seeds the worklist with an initial state,
    runs optional pre-passes (cross-function and type inference), drives
    ``execute_loop``, and delegates completed-run result assembly to
    :mod:`pysymex.execution.engine`.
    """

    def _execute_with_post_analysis(
        self,
        func: Callable[..., object],
        symbolic_args: dict[str, str] | None = None,
        initial_values: dict[str, object] | None = None,
        issue_collector: Callable[[], list[Issue]] | None = None,
    ) -> ExecutionResult:
        """Template method for subclasses to execute with post-analysis issue collection.

        Subclasses should override this to call their specific execute_function
        and then extend the result with collected issues.
        """
        result = self.execute_function(func, symbolic_args, initial_values)
        if issue_collector:
            issues = issue_collector()
            result.issues.extend(issues)
        return result

    def execute_function(
        self,
        func: Callable[..., object],
        symbolic_args: dict[str, str] | None = None,
        initial_values: dict[str, object] | None = None,
    ) -> ExecutionResult:
        """Symbolically execute a Python function.

        Compiles *func* to bytecode, creates symbolic arguments, and
        explores all feasible execution paths up to the configured
        resource limits.

        Args:
            func: The Python function to analyse.
            symbolic_args: Mapping of parameter names to type hints
                (e.g. ``{"x": "int", "s": "str"}``).  Parameters
                not listed default to ``"int"``.

        Returns:
            An :class:`ExecutionResult` summarising detected issues,
            path statistics, and bytecode coverage.

        **Execution Algorithm:**
        1. **Reset**: Clears caches and resets solvers for a clean slate.
        2. **Compile**: Retrieves cached bytecode instructions.
        3. **Initialize**: Creates a `VMState` with symbolic arguments based on hints.
        4. **Explore**: Enters the worklist-driven exploration loop until path limits or
           time budget is exhausted.
        5. **Finalize**: Filters symbolic findings and packages the final issue report.
        """
        request = FunctionExecutionRequest.from_inputs(func, symbolic_args, initial_values)
        cache_key = None
        if self.config.enable_caching and self._result_cache is not None:
            cache_key = execution_result_cache_key(
                func=request.func,
                symbolic_args_token=request.cache_symbolic_args_repr,
                initial_values=request.initial_values,
                config=self.config,
                active_detectors=self._active_detectors,
                executor_version=self._result_cache_version,
            )
            cached = self._result_cache.get(cache_key)
            if cached is not None:
                return _clone_execution_result(cached)
        code = request.code
        reset_execution_run(
            solver=self.solver,
            session=self.session,
            infrastructure_degraded_passes=self._infrastructure_degraded_passes,
            state_merger=self._state_merger,
            resource_tracker=self._resource_tracker,
            interaction_graph=self.interaction_graph,
        )
        prepare_bytecode_execution(
            session=self.session,
            dispatcher=self.dispatcher,
            code=code,
            bytecode_source=request.func,
        )
        initial_state = create_function_initial_state(
            request.func,
            request.symbolic_arg_map(),
            request.initial_values,
            config=self.config,
            session=self.session,
        )

        initial_state = seed_function_execution_context(
            initial_state=initial_state,
            func=request.func,
            code=code,
        )
        start_path_exploration(
            session=self.session,
            config=self.config,
            interaction_graph=self.interaction_graph,
            state_merger=self._state_merger,
            initial_state=initial_state,
            code=code,
        )

        prepass_result = run_optional_function_prepasses(
            session=self.session,
            code=code,
            cross_function=self._cross_function,
            enable_type_inference=self.config.enable_type_inference,
        )
        self._cross_function = prepass_result.cross_function
        if prepass_result.effect_summaries is not None:
            self._effect_summaries = prepass_result.effect_summaries
        if prepass_result.type_inference_ran:
            self._type_analyzer = prepass_result.type_analyzer
        self.execute_loop()
        logger.debug("Executor issues count: %d", len(self.session.issues))
        result = finalize_execution_result(
            session=self.session,
            enable_fp_filtering=self.config.enable_fp_filtering,
            resource_tracker=self._resource_tracker,
            solver=self.solver,
            detector_query_stats=collect_detector_query_stats(self.session),
            state_merger=self._state_merger,
            function_name=request.function_name,
            source_file=code.co_filename,
            include_final_stack=True,
            include_final_exception=True,
        )
        if cache_key is not None and self._result_cache is not None:
            self._result_cache.put(cache_key, _clone_execution_result(result))
        return result

    def execute_code(
        self,
        code: types.CodeType,
        symbolic_vars: dict[str, str] | None = None,
        initial_globals: dict[str, object] | None = None,
    ) -> ExecutionResult:
        """Symbolically execute a compiled code object (module or snippet).

        Unlike :meth:`execute_function`, this path does not bind closure cells
        or seed function-local module globals. Use it for ``exec``-style targets
        where parameters are named in ``symbolic_vars`` and optional concrete
        globals are supplied via ``initial_globals``.

        Args:
            code: Compiled bytecode to analyse.
            symbolic_vars: Mapping of local names to symbolic type hints
                (for example ``{"x": "int"}``). Unlisted parameters default
                based on ``co_varnames`` and ``co_flags``.
            initial_globals: Optional globals visible during execution.

        Returns:
            :class:`~pysymex.execution.results.result.ExecutionResult` without final
            stack or exception snapshots (unlike ``execute_function``).
        """
        request = CodeExecutionRequest.from_inputs(code, symbolic_vars, initial_globals)
        reset_execution_run(
            solver=self.solver,
            session=self.session,
            infrastructure_degraded_passes=self._infrastructure_degraded_passes,
            state_merger=self._state_merger,
            resource_tracker=self._resource_tracker,
            interaction_graph=self.interaction_graph,
        )
        prepare_bytecode_execution(
            session=self.session,
            dispatcher=self.dispatcher,
            code=request.code,
            bytecode_source=request.code,
        )

        initial_state = create_code_initial_state(
            request.code,
            request.symbolic_vars,
            cast("dict[str, StackValue] | None", request.initial_globals),
        )
        start_path_exploration(
            session=self.session,
            config=self.config,
            interaction_graph=self.interaction_graph,
            state_merger=self._state_merger,
            initial_state=initial_state,
            code=request.code,
        )

        self.execute_loop()
        return finalize_execution_result(
            session=self.session,
            enable_fp_filtering=self.config.enable_fp_filtering,
            resource_tracker=self._resource_tracker,
            solver=self.solver,
            detector_query_stats=collect_detector_query_stats(self.session),
            state_merger=self._state_merger,
            function_name=request.code.co_name,
            source_file=request.code.co_filename,
            include_final_stack=False,
            include_final_exception=False,
        )
