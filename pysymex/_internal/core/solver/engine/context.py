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

"""Active solver context for top-level query helpers."""

from __future__ import annotations

import contextvars
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex._internal.core.solver.engine.incremental import IncrementalSolver
    from pysymex._internal.typing.protocols import SolverProtocol

_active_solver_var: contextvars.ContextVar[SolverProtocol | None] = contextvars.ContextVar(
    "_active_solver_var",
    default=None,
)


class SolverContext:
    """Namespace for active solver context variables."""

    active = _active_solver_var


class _ThreadLocalSolver(threading.local):
    """Hold the reusable incremental solver instance for one worker thread."""

    def __init__(self) -> None:
        """Initialize a thread slot without constructing a solver."""
        self.solver: IncrementalSolver | None = None
        self.model_solver: IncrementalSolver | None = None


thread_local_solver = _ThreadLocalSolver()
