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

"""Program-counter, path-constraint, and branch-trace mutation helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.state.branches import BranchRecord
from pysymex._internal.core.state.mixin.types import VMStateMixinAttributes

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import LoopCounterKey


class VMStatePathMixin(VMStateMixinAttributes):
    """Mutate path metadata without deciding path feasibility."""

    def advance_pc(self, delta: int = 1) -> VMState:
        """Increment ``pc`` by *delta*. Returns ``self``."""
        self.pc += delta
        self._cached_hash = None
        return cast("VMState", self)

    def set_pc(self, target: int) -> VMState:
        """Set ``pc`` to *target*. Returns ``self``."""
        self.pc = target
        self._cached_hash = None
        return cast("VMState", self)

    def increment_loop_iteration(self, key: LoopCounterKey) -> int:
        """Increment loop iteration count for *key*. Returns new count.

        Invalidates hash to ensure loop detection logic sees the updated state.
        """
        current_count = self.loop_iterations.get(key)
        count = (current_count if current_count is not None else 0) + 1
        self.loop_iterations[key] = count
        self._cached_hash = None
        return count

    def add_constraint(self, constraint: z3.BoolRef) -> VMState:
        """Append a path constraint without querying satisfiability.

        Side Effects:
            Replaces the persistent constraint-chain head, increments the
            pending-constraint count for nontrivial constraints, and clears
            the cached structural hash.

        Notes:
            Feasibility checks and any resulting pruning occur in solver or
            exploration owners, not in this mutation helper.

        """
        if z3.is_true(constraint):
            return cast("VMState", self)
        self.path_constraints = self.path_constraints.append(constraint)
        self.pending_constraint_count += 1
        self._cached_hash = None
        return cast("VMState", self)

    def record_branch(self, condition: z3.BoolRef, taken: bool, pc: int) -> VMState:
        """Append a branch-trace record without adding a path constraint."""
        record = BranchRecord(pc=pc, condition=condition, taken=taken)
        self.branch_trace = self.branch_trace.append(record)
        return cast("VMState", self)

    def mark_visited(self) -> bool:
        """Record the current ``pc`` in the path's visitation log.

        This method records a repeated program counter; exploration policy
        remains responsible for interpreting revisits as loops or bounds.

        Returns:
            ``True`` if the current ``pc`` was already present in
            ``visited_pcs``.

        """
        if self.pc in self.visited_pcs:
            return True
        self.visited_pcs.add(self.pc)
        self._cached_hash = None
        return False

    def copy_constraints(self) -> list[z3.BoolRef]:
        """Get a copy of the current path constraints."""
        return self.path_constraints.to_list()

    def constraint_hash(self) -> int:
        """Return the persistent constraint chain's structural hash."""
        return self.path_constraints.hash_value()
