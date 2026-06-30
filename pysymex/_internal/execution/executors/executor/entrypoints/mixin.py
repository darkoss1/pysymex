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

"""Scan entrypoint method surface for public executor mixins."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.executors.executor.entrypoints.code import execute_code_entrypoint
from pysymex._internal.execution.executors.executor.entrypoints.function import (
    execute_function_entrypoint,
)
from pysymex._internal.execution.executors.executor.entrypoints.types import (
    EntrypointInputs,
)
from pysymex._internal.execution.executors.executor.types import ExecutorMixinContract

if TYPE_CHECKING:
    import types
    from collections.abc import Callable

    from pysymex._internal.execution.results.result import ExecutionResult


class ExecutorEntrypointMixin(ExecutorMixinContract):
    """High-level scan entrypoints and finalization handoff.

    Prepares bytecode metadata, seeds the worklist with an initial state,
    drives ``execute_loop``, and delegates completed-run result assembly to
    :mod:`pysymex._internal.execution.engine`.
    """

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

        """
        return execute_function_entrypoint(
            self._entrypoint_inputs(),
            func,
            symbolic_args,
            initial_values,
        )

    def execute_code(
        self,
        code: types.CodeType,
        symbolic_vars: dict[str, str] | None = None,
        initial_globals: dict[str, object] | None = None,
        *,
        symbolic_vars_are_inferred: bool = False,
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
            symbolic_vars_are_inferred: Whether ``symbolic_vars`` came from static
                inference rather than an explicit caller override. Inferred entries
                yield to real callable defaults in ``initial_globals``.

        Returns:
            :class:`~pysymex._internal.execution.results.result.ExecutionResult` without final
            stack or exception snapshots (unlike ``execute_function``).

        """
        return execute_code_entrypoint(
            self._entrypoint_inputs(),
            code,
            symbolic_vars,
            initial_globals,
            symbolic_vars_are_inferred=symbolic_vars_are_inferred,
        )

    def _entrypoint_inputs(self) -> EntrypointInputs:
        """Collect executor-owned collaborators for direct entrypoint owners."""
        return EntrypointInputs(
            config=self.config,
            solver=self.solver,
            session=self.session,
            dispatcher=self.dispatcher,
            interaction_graph=self.interaction_graph,
            infrastructure_degraded_passes=self._infrastructure_degraded_passes,
            state_merger=self._state_merger,
            resource_tracker=self._resource_tracker,
            result_cache=self._result_cache,
            result_cache_version=self._result_cache_version,
            active_detectors=self._active_detectors,
            execute_loop=self.execute_loop,
        )
