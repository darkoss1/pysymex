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

"""Control-flow join detection and merge eligibility checks.

Identifies bytecode indices with multiple predecessors and decides whether two
``VMState`` payloads are similar enough to merge under the active
:class:`~pysymex._internal.execution.strategies.merger.types.MergePolicy`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import dis
    import types

    from pysymex._internal.core.state.record import VMState
from pysymex._internal.execution.strategies.merger.types import StateMergerMixinContract


class StateMergerJoinMixin(StateMergerMixinContract):
    """CFG join-point detection and policy-gated merge eligibility."""

    def detect_join_points(
        self,
        instructions: list[dis.Instruction],
        code: types.CodeType | None = None,
    ) -> set[int]:
        """Detect join points using instruction indices.

        A join point is any instruction index reached by more than one
        predecessor edge in the control-flow graph.
        """
        _ = code

        if not instructions:
            self.join_points = set()
            return self.join_points

        import dis

        predecessor_counts: dict[int, int] = {}
        backward_jump_targets: set[int] = set()
        offset_to_index: dict[int, int] = {
            instr.offset: idx for idx, instr in enumerate(instructions)
        }

        for idx, instr in enumerate(instructions):
            successors: set[int] = set()
            opname = instr.opname

            if instr.opcode in dis.hasjabs or instr.opcode in dis.hasjrel:
                jump_target = instr.argval
                if isinstance(jump_target, int) and jump_target in offset_to_index:
                    target_index = offset_to_index[jump_target]
                    successors.add(target_index)
                    if target_index <= idx:
                        backward_jump_targets.add(target_index)

            has_fallthrough = True
            if opname.startswith("RETURN") or opname in {"RAISE_VARARGS", "RERAISE"}:
                has_fallthrough = False
            if (
                opname.startswith("JUMP")
                and "IF" not in opname
                and opname
                not in {
                    "JUMP_IF_TRUE_OR_POP",
                    "JUMP_IF_FALSE_OR_POP",
                }
            ):
                has_fallthrough = False

            if has_fallthrough and idx + 1 < len(instructions):
                successors.add(idx + 1)

            for succ in successors:
                predecessor_counts[succ] = predecessor_counts.get(succ, 0) + 1

        self.join_points = {
            idx
            for idx, count in predecessor_counts.items()
            if count > 1 and idx not in backward_jump_targets
        }
        return self.join_points

    def is_join_point(self, pc: int) -> bool:
        """Check if a program counter is at a join point."""
        return pc in self.join_points

    def should_merge(self, state: VMState) -> bool:
        """Determine if the state should be considered for merging."""
        if self._disabled_for_execution:
            return False
        if state.deferred_detector_issues:
            return False
        if not self.is_join_point(state.pc):
            return False
        return not len(state.path_constraints) > self.max_constraints_for_merge

    def _structural_hash(self, state: VMState) -> int:
        """Compute a structural hash to fast-fail basic structure differences."""
        return hash(
            (
                len(state.stack),
                len(state.call_stack),
                frozenset(state.local_vars.keys()),
                tuple((b.block_type, b.handler_pc) for b in state.block_stack),
            ),
        )
