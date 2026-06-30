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

"""Callback contract for one-instruction execution pipeline steps."""

from __future__ import annotations

import dis
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.execution.session.state.core import ExecutionSession

HookMap = Mapping[str, Sequence[Callable[..., object]]]
BeforeDispatch = Callable[[dis.Instruction, VMState, list[dis.Instruction]], None]
CheckPathFeasibility = Callable[[VMState], bool]
CheckResourceLimits = Callable[[VMState], bool]
GetLineNumber = Callable[[int, list[dis.Instruction]], int | None]
HandleLoopLogic = Callable[[VMState, list[dis.Instruction]], bool]
MergeState = Callable[[VMState], VMState | None]
OnPathComplete = Callable[[VMState], None]
ProcessExecutionResult = Callable[[OpcodeResult, VMState, list[dis.Instruction]], None]
RunDetectors = Callable[[VMState, dis.Instruction, list[dis.Instruction]], None]
HasDetectors = Callable[[str], bool]


@dataclass(frozen=True, slots=True)
class StepExecutionContext:
    """Executor callbacks and mutable owners needed for one instruction step."""

    session: ExecutionSession
    dispatcher: OpcodeDispatcher
    hook_owner: object
    hooks: HookMap
    root_instructions: list[dis.Instruction]
    lazy_eval_threshold: int
    check_resource_limits: CheckResourceLimits
    merge_state: MergeState
    handle_loop_logic: HandleLoopLogic
    check_path_feasibility: CheckPathFeasibility
    before_dispatch: BeforeDispatch
    has_detectors: HasDetectors
    run_detectors: RunDetectors
    process_execution_result: ProcessExecutionResult
    on_path_complete: OnPathComplete
    get_line_number: GetLineNumber
