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

"""Post-instruction delta event behavior."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, cast

from pydantic import BaseModel

from pysymex.logger import get_logger
from pysymex.tracing.schemas import (
    ConstraintEntry,
    StackDiff,
    StepDeltaEvent,
    TracerConfig,
    VarDiff,
    VerbosityLevel,
)
from pysymex.tracing.tracer.helpers import elapsed_ms_since
from pysymex.tracing.tracer.steps.source import instruction_source_line
from pysymex.tracing.z3.serializer import Z3Serializer

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState
    from pysymex.execution.executors.core import SymbolicExecutor


logger = get_logger(__name__)


class TracerStepMixin:
    """Post-step delta emission behavior."""

    if TYPE_CHECKING:
        config: TracerConfig
        _serializer: Z3Serializer
        _pre_step_started_ns: int | None
        _pre_step_snapshot: (
            tuple[
                list[StackValue],
                dict[str, StackValue],
                dict[str, StackValue],
                dict[int, StackValue],
                int,
            ]
            | None
        )

        def _next_seq(self) -> int:
            """Allocate and return the next event sequence number.

            Returns:
                The next sequential integer identifier.
            """
            ...

        def _get_source_line(self, filename: str | None, line_number: int | None) -> str | None:
            """Retrieve the source code text corresponding to a filename and line number.

            Args:
                filename: Path to the target source file, or None to use default.
                line_number: Line number to look up.

            Returns:
                The source code line as a stripped string, or None if not found.
            """
            ...

        def _write_event(self, event: BaseModel, *, force_flush: bool) -> None:
            """Write a telemetry event to the trace output buffer.

            Args:
                event: The event payload model to write.
                force_flush: Whether to flush the output file immediately.
            """
            ...

    def post_step(
        self,
        executor: SymbolicExecutor,
        state: VMState,
        instr: dis.Instruction,
    ) -> None:
        """Emit a :class:`~pysymex.tracing.schemas.StepDeltaEvent` after dispatch.

        Computes elapsed instruction dispatch time and the diff between the
        pre-step snapshot and the current state, then appends the delta to the buffer.

        Args:
            executor: The running executor.
            state:    VM state **after** the instruction was dispatched.
            instr:    The instruction that was just executed.
        """
        if not self.config.enabled:
            return
        if self.config.verbosity == VerbosityLevel.QUIET:
            return

        snap = self._pre_step_snapshot
        step_latency_ms = elapsed_ms_since(self._pre_step_started_ns)
        self._pre_step_started_ns = None
        stack_diff = StackDiff()
        var_diff = VarDiff()
        mem_diff: dict[str, str] = {}
        constraint_added: ConstraintEntry | None = None

        try:
            current_stack = list(state.stack)
            current_locals = dict(state.local_vars)
            current_memory = dict(state.memory)

            prev_constraint_count: int | None = None
            if snap is not None:
                prev_stack, prev_locals, _prev_globals, prev_memory, prev_constraint_count = snap

                prev_len = len(prev_stack)
                curr_len = len(current_stack)
                if curr_len < prev_len:
                    stack_diff = StackDiff(popped=prev_len - curr_len, pushed=[])
                elif curr_len > prev_len:
                    pushed_vals = [
                        self._serializer.serialize_stack_value(v) for v in current_stack[prev_len:]
                    ]
                    stack_diff = StackDiff(popped=0, pushed=pushed_vals)
                elif current_stack != prev_stack:
                    n_changed = sum(
                        1 for a, b in zip(prev_stack, current_stack, strict=False) if a is not b
                    )
                    if n_changed:
                        stack_diff = StackDiff(
                            popped=n_changed,
                            pushed=[
                                self._serializer.serialize_stack_value(v)
                                for v in current_stack[-n_changed:]
                            ],
                        )

                for k, v in current_locals.items():
                    if k not in prev_locals:
                        var_diff = VarDiff(
                            modified=var_diff.modified,
                            added={**var_diff.added, k: self._serializer.serialize_stack_value(v)},
                            removed=var_diff.removed,
                        )
                    elif prev_locals[k] is not v:
                        var_diff = VarDiff(
                            modified={
                                **var_diff.modified,
                                k: self._serializer.serialize_stack_value(v),
                            },
                            added=var_diff.added,
                            removed=var_diff.removed,
                        )
                removed = [k for k in prev_locals if k not in current_locals]
                if removed:
                    var_diff = VarDiff(
                        modified=var_diff.modified,
                        added=var_diff.added,
                        removed=removed,
                    )

                if self.config.verbosity == VerbosityLevel.FULL:
                    for addr, val in current_memory.items():
                        if addr not in prev_memory or prev_memory[addr] is not val:
                            mem_diff[str(addr)] = self._serializer.serialize_stack_value(val)

            current_constraints = state.path_constraints
            current_count = len(current_constraints)
            if (
                snap is not None
                and prev_constraint_count is not None
                and current_count > prev_constraint_count
            ):
                new_constraints: list[object] = []
                curr = current_constraints

                for _ in range(current_count - prev_constraint_count):
                    if curr is not None:
                        new_constraints.append(cast("object", curr.constraint))
                        curr = curr.parent
                    else:
                        break

                if new_constraints:
                    newest = new_constraints[0]
                    causality = f"{instr.opname} at PC={state.pc}"
                    constraint_added = ConstraintEntry(
                        smtlib=self._serializer.safe_sexpr(newest),
                        causality=causality,
                    )

        except Exception:
            logger.debug("Failed to build trace step delta", exc_info=True)

        source_line = instruction_source_line(instr)

        event = StepDeltaEvent(
            seq=self._next_seq(),
            path_id=getattr(state, "path_id", 0),
            pc=getattr(state, "pc", 0),
            offset=getattr(instr, "offset", 0),
            opcode=getattr(instr, "opname", "UNKNOWN"),
            step_latency_ms=step_latency_ms,
            source_line=source_line,
            source_text=self._get_source_line(None, source_line),
            stack_diff=stack_diff,
            var_diff=var_diff,
            mem_diff=mem_diff,
            constraint_added=constraint_added,
        )
        self._write_event(event, force_flush=False)


__all__ = ["TracerStepMixin"]
