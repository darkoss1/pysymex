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

"""Execution-run lifecycle reset ownership."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from pysymex.core.types.containers.bytes import BYTES_CONST_CACHE
from pysymex.core.types.scalars.values import FROM_CONST_CACHE
from pysymex.core.types.scalars.values import STRING_CONST_CACHE
from pysymex.core.types.scalars.values import SYMBOLIC_CACHE
from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.execution.session.state import ExecutionSession
    from pysymex.typing import SolverProtocol

__all__ = ["reset_execution_run"]

logger = get_logger(__name__)


class Resettable(Protocol):
    """Protocol for execution infrastructure reset between analyzed code objects."""

    def reset(self) -> None:
        """Reset per-run mutable state while preserving configuration."""


def reset_execution_run(
    *,
    solver: SolverProtocol,
    session: ExecutionSession,
    infrastructure_degraded_passes: list[str],
    state_merger: Resettable | None,
    resource_tracker: Resettable | None,
    interaction_graph: Resettable,
) -> None:
    """Reset execution-run state without rebuilding persistent executor infrastructure.

    The double solver reset preserves the existing lifecycle behavior: the
    solver is cleared before session/sidecar reset and again after sidecars are
    reset so no stale path constraints survive a new analysis run.
    """
    solver.reset()
    session.reset_for_run(infrastructure_degraded_passes)
    if state_merger is not None:
        state_merger.reset()
    if resource_tracker is not None:
        resource_tracker.reset()

    solver.reset()
    interaction_graph.reset()
    _clear_symbolic_value_caches()
    _clear_modeled_class_registry()


def _clear_symbolic_value_caches() -> None:
    """Clear process-wide symbolic construction caches."""
    SYMBOLIC_CACHE.clear()
    FROM_CONST_CACHE.clear()
    STRING_CONST_CACHE.clear()
    BYTES_CONST_CACHE.clear()


def _clear_modeled_class_registry() -> None:
    """Clear modeled class registry if the object-model package is importable."""
    try:
        from pysymex.models.objects import class_registry

        class_registry.clear()
    except ImportError:
        logger.debug("Modeled class registry unavailable during executor reset")
