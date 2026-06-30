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

"""Call-frame construction for interprocedural callee entry."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    import dis

    from pysymex._internal.analysis.runtime.summaries.builder import SummaryBuilder
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import CallFrame, ProtocolCallCandidate
    from pysymex._internal.execution.calls.interprocedural.targets import InterproceduralTarget
    from pysymex._internal.typing.protocols import StackValue


def build_interprocedural_call_frame(
    *,
    state: VMState,
    target: InterproceduralTarget,
    caller_instruction: dis.Instruction | None,
    caller_instructions: list[dis.Instruction],
    summary_builder: SummaryBuilder | None,
    is_init: bool,
    init_instance: StackValue | None,
    protocol_method: str | None,
    resume_pc: int | None,
    protocol_retained_operand: StackValue | None,
    protocol_fallbacks: tuple[ProtocolCallCandidate, ...],
    has_contract_frame: bool,
    pos_arg_names: tuple[str, ...],
    caller_instructions_override: list[object] | None,
    caller_offset_override: int | None,
) -> CallFrame:
    """Build the caller frame retained while executing a nested callee."""
    from pysymex._internal.core.state.types import CallFrame

    return CallFrame(
        function_name=target.func_name,
        return_pc=state.pc + 1 if resume_pc is None else resume_pc,
        local_vars=state.local_vars,
        stack_depth=len(state.stack),
        caller_stack=tuple(state.stack),
        caller_instructions=(
            caller_instructions_override
            if caller_instructions_override is not None
            else cast("list[object]", list(caller_instructions))
        ),
        summary_builder=summary_builder,
        is_init_call=is_init,
        init_instance=init_instance,
        protocol_method=protocol_method,
        protocol_retained_operand=protocol_retained_operand,
        protocol_fallbacks=protocol_fallbacks,
        has_contract_frame=has_contract_frame,
        argument_aliases=tuple(
            (str(name), target.args[index])
            for index, name in enumerate(pos_arg_names)
            if index < len(target.args)
        ),
        caller_offset=(
            caller_offset_override
            if caller_offset_override is not None
            else caller_instruction.offset
            if caller_instruction is not None
            else None
        ),
        write_event_start_index=len(state.write_events),
        function_code=target.func_code,
    )
