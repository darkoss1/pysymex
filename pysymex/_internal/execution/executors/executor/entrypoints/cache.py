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

"""Cached execution-result cloning for executor entrypoints."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex._internal.execution.results.result import ExecutionResult


def clone_execution_result(result: ExecutionResult) -> ExecutionResult:
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
