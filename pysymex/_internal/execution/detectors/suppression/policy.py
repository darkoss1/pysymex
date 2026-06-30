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

"""Public detector issue suppression policy."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.detectors.publication.context.manager import (
    should_replace_dynamic_exit_issue,
)
from pysymex._internal.execution.detectors.suppression.handlers import (
    active_exception_handler_catches,
    exception_handler_catches,
)
from pysymex._internal.execution.detectors.suppression.names import exception_name_for_issue

if TYPE_CHECKING:
    import dis

    from pysymex._internal.analysis.detectors.detector.types import Issue
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def exception_handler_catches_issue(
    dispatcher: OpcodeDispatcher,
    issue: Issue,
    instr: dis.Instruction,
    state: VMState,
) -> bool:
    """Return whether bytecode exception tables would catch this issue type."""
    exception_name = exception_name_for_issue(issue, instr)
    if exception_name is None:
        return False
    from pysymex._internal.execution.opcodes.common.control.iteration.callable.sentinel import (
        handle_callable_sentinel_exception,
    )
    from pysymex._internal.execution.opcodes.common.control.iteration.sequence import (
        handle_getitem_exception,
        handle_next_exception,
    )

    if handle_getitem_exception(state, exception_name):
        return True
    if handle_next_exception(state, exception_name):
        return True
    if handle_callable_sentinel_exception(state, exception_name):
        return True
    if should_replace_dynamic_exit_issue(state):
        return active_exception_handler_catches(dispatcher, state, instr.offset, exception_name)
    return exception_handler_catches(dispatcher, state, instr.offset, exception_name)
