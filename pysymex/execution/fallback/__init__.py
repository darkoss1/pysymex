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

"""Execution fallback and unsupported-state classification helpers."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Final

from pysymex.logger import get_logger

from pysymex.core.state.record import VMState
from pysymex.core.state.types import VMStateError
from pysymex.execution.fallback.types import (
    FallbackEvent,
    FallbackKind,
    RiskLevel,
    SoundnessTag,
)

__all__ = [
    "FallbackEvent",
    "FallbackKind",
    "RiskLevel",
    "SoundnessTag",
    "UNSUPPORTED_VM_STATE_DEGRADED_PASS",
    "record_unsupported_vm_state",
]

if TYPE_CHECKING:
    from pysymex.execution.session.state import ExecutionSession

UNSUPPORTED_VM_STATE_DEGRADED_PASS: Final = "unsupported_vm_state"

logger = get_logger(__name__)


def record_unsupported_vm_state(
    *,
    session: ExecutionSession,
    state: VMState,
    exc: VMStateError,
    line_number: int | None,
    record_degraded_passes: Callable[[list[str]], None],
) -> None:
    """Record an unsupported VM state as an UNKNOWN issue and degraded pass."""
    from pysymex.analysis.detectors import Issue, IssueKind

    logger.warning("Unsupported VM state at PC %d: %s", state.pc, exc)
    issue = Issue(
        kind=IssueKind.UNKNOWN,
        message=f"Unsupported VM state: {exc}",
        constraints=list(state.path_constraints),
        pc=state.pc,
        line_number=line_number,
    )
    session.issues.append(issue)
    session.last_exception = issue
    session.paths_pruned += 1
    session.record_fallback_event(
        FallbackEvent(
            kind=FallbackKind.UNSUPPORTED,
            label=UNSUPPORTED_VM_STATE_DEGRADED_PASS,
            owner="execution.fallback",
            reason=str(exc),
            pc=state.pc,
            line_number=line_number,
            soundness=SoundnessTag.UNSUPPORTED,
            false_positive_risk=RiskLevel.LOW,
            false_negative_risk=RiskLevel.HIGH,
        )
    )
    record_degraded_passes([UNSUPPORTED_VM_STATE_DEGRADED_PASS])
