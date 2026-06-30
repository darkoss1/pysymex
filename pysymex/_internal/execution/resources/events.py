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

"""Resource-limit fallback events and prune hook publication."""

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
    from pysymex._internal.limits.models import LimitExceeded

RESOURCE_LIMIT_PRUNE_REASON = "resource_limit"
HookMap = Mapping[str, Sequence[Callable[..., object]]]

logger = get_logger(__name__)


def resource_limit_degraded_pass(exc: LimitExceeded) -> str:
    """Return the stable degraded-pass label for a host resource limit."""
    return f"resource_limit_{exc.resource_type.name.lower()}"


def record_resource_limit_degradation(
    *,
    exc: LimitExceeded,
    session: ExecutionSession,
    state: VMState | None = None,
    reason: str = "resource limit reached",
) -> None:
    """Record a resource-limit degradation without path-prune accounting."""
    label = resource_limit_degraded_pass(exc)
    session.record_fallback_event(
        FallbackEvent(
            kind=FallbackKind.RESOURCE_LIMIT,
            label=label,
            owner="execution.resources",
            reason=reason,
            pc=state.pc if state is not None else None,
            soundness=SoundnessTag.INCONCLUSIVE,
            false_positive_risk=RiskLevel.LOW,
            false_negative_risk=RiskLevel.HIGH,
        )
    )


def record_resource_limit_prune(
    *,
    session: ExecutionSession,
    exc: LimitExceeded,
    hook_owner: object | None = None,
    hooks: HookMap | None = None,
    state: VMState | None = None,
) -> None:
    """Record a pruned path caused by a resource limit and optionally fire hooks."""
    session.paths_pruned += 1
    record_resource_limit_degradation(
        exc=exc,
        session=session,
        state=state,
        reason="path pruned by resource limit",
    )
    if hook_owner is None or hooks is None or state is None:
        return
    for hook in hooks.get("on_prune", ()):
        try:
            hook(hook_owner, state, RESOURCE_LIMIT_PRUNE_REASON)
        except Exception:
            logger.exception("Plugin hook execution failed")
