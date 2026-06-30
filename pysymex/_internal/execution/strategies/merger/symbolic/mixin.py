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

"""State-merger mixin for symbolic phi-node joins."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.execution.strategies.merger.symbolic.regions.frames import merge_call_stack
from pysymex._internal.execution.strategies.merger.symbolic.regions.memory import merge_memory
from pysymex._internal.execution.strategies.merger.symbolic.regions.variables import (
    merge_global_vars,
    merge_local_vars,
    merge_stack,
)
from pysymex._internal.execution.strategies.merger.types import StateMergerMixinContract

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState


class StateMergerSymbolicMixin(StateMergerMixinContract):
    """Perform symbolic merges of compatible states at join points."""

    def _merge_states_symbolically(self, state1: VMState, state2: VMState) -> VMState | None:
        """Merge states using strict Phi-nodes without Implies AST bloat."""
        condition = z3.Bool(f"phi_merge_p{state1.path_id}_p{state2.path_id}")
        if tuple(map(repr, state1.contract_frames)) != tuple(map(repr, state2.contract_frames)):
            return None

        merged = state1.fork()
        merged.path_constraints = state1.path_constraints
        values_equal = self.values_structurally_equal

        if not merge_local_vars(merged, state1, state2, condition, values_equal):
            return None
        if not merge_global_vars(merged, state1, state2, condition, values_equal):
            return None
        if not merge_stack(merged, state1, state2, condition, values_equal):
            return None
        if not merge_call_stack(merged, state1, state2, condition, values_equal):
            return None
        if not merge_memory(merged, state1, state2, condition, values_equal):
            return None
        return merged
