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

"""Issue classification and handler-catch probes for modeled exceptions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.exceptions.policy import (
    canonical_exception_type,
    issue_kind_for_exception,
)
from pysymex._internal.core.outcome import IssueKind

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.models.contracts.results import (
        PotentialException,
        RaisedExceptionEffect,
    )


def raised_model_exception_is_caught(
    state: VMState,
    ctx: OpcodeDispatcher,
    instr: dis.Instruction,
    effect: RaisedExceptionEffect,
) -> bool:
    """Return whether a definite model-raised exception is caught at the call site."""
    from pysymex._internal.execution.detectors.suppression.policy import (
        exception_handler_catches_issue,
    )

    issue_kind = IssueKind.__members__.get(effect["issue_kind"], IssueKind.RUNTIME_ERROR)
    probe_issue = Issue(
        kind=issue_kind,
        message=f"Path raises unhandled exception: {effect['exception_type']}",
        pc=state.pc,
    )
    return exception_handler_catches_issue(ctx, probe_issue, instr, state)


def modeled_exception_type(name: str) -> type[BaseException] | str:
    """Resolve builtin model exception names to concrete CPython exception classes."""
    resolved = canonical_exception_type(name)
    return resolved if isinstance(resolved, type) else name


def potential_exception_is_caught(
    state: VMState,
    ctx: OpcodeDispatcher,
    instr: dis.Instruction,
    effect: PotentialException,
) -> bool:
    """Return whether a conditional model exception is caught at the call site."""
    from pysymex._internal.execution.detectors.suppression.policy import (
        exception_handler_catches_issue,
    )

    issue_kind = issue_kind_for_exception(effect["type"])
    probe_issue = Issue(
        kind=issue_kind,
        message=f"Path raises unhandled exception: {effect['type']}",
        pc=state.pc,
    )
    return exception_handler_catches_issue(ctx, probe_issue, instr, state)
