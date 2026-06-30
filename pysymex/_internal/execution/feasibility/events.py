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

"""Fallback and prune-hook events for execution path-feasibility checks."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import TYPE_CHECKING

from pysymex._internal.execution.fallback.types import (
    FallbackEvent,
    FallbackKind,
    RiskLevel,
    SoundnessTag,
)
from pysymex._internal.logging.root import get_logger

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.session.state.core import ExecutionSession

HookMap = Mapping[str, Sequence[Callable[..., object]]]
SOLVER_UNKNOWN_PATH_FEASIBILITY_DEGRADED_PASS = "solver_unknown_path_feasibility"

logger = get_logger(__name__)


def record_solver_unknown_path_feasibility(
    *,
    session: ExecutionSession,
    state: VMState,
    reason: str,
) -> None:
    """Record an inconclusive path-feasibility check without pruning the path."""
    session.record_fallback_event(
        FallbackEvent(
            kind=FallbackKind.UNKNOWN,
            label=SOLVER_UNKNOWN_PATH_FEASIBILITY_DEGRADED_PASS,
            owner="execution.feasibility",
            reason=reason,
            pc=state.pc,
            soundness=SoundnessTag.INCONCLUSIVE,
            false_positive_risk=RiskLevel.MEDIUM,
            false_negative_risk=RiskLevel.MEDIUM,
        ),
    )


def publish_prune_hooks(*, hook_owner: object, hooks: HookMap, state: VMState) -> None:
    """Notify prune hooks that path feasibility established UNSAT."""
    for hook in hooks.get("on_prune", ()):
        try:
            hook(hook_owner, state, "infeasible")
        except Exception:
            logger.exception("Plugin hook execution failed")
