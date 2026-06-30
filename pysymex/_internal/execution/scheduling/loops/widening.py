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

"""Widening operators that accelerate convergence of loop abstract values."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import z3

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.scheduling.loops.types import LoopInfo
    from pysymex._internal.typing.protocols import StackValue


class LoopWidening:
    """Applies widening to accelerate loop analysis."""

    def should_widen(self, old_state: VMState, new_state: VMState, loop: LoopInfo) -> bool:
        """Return whether local-state widening can summarize the observed recurrence."""
        _ = loop
        if set(old_state.local_vars) != set(new_state.local_vars):
            return False
        return any(
            not _values_equal(old_state.local_vars[name], new_state.local_vars[name])
            for name in old_state.local_vars
        )

    def widen_state(self, old_state: VMState, new_state: VMState, loop: LoopInfo) -> VMState:
        """Apply widening to generalize loop state."""
        _ = loop
        widened = new_state.copy()
        self._widen_changed_locals(old_state, new_state, widened)
        return widened

    @staticmethod
    def _symbolic_stack_for_affinity(
        name: str,
        affinity: object,
    ) -> tuple[StackValue, z3.BoolRef]:
        from pysymex._internal.core.types.scalars.strings import SymbolicString
        from pysymex._internal.core.types.scalars.values import SymbolicValue

        if affinity == "int":
            return SymbolicValue.symbolic_int(f"{name}_widened")
        if affinity == "bool":
            return SymbolicValue.symbolic_bool(f"{name}_widened")
        if affinity == "str":
            return SymbolicString.symbolic(f"{name}_widened")
        return SymbolicValue.symbolic(f"{name}_widened")

    def _widen_changed_locals(
        self,
        old_state: VMState,
        new_state: VMState,
        widened: VMState,
    ) -> None:
        for name in set(old_state.local_vars.keys()) | set(new_state.local_vars.keys()):
            old_val = old_state.local_vars.get(name)
            new_val = new_state.local_vars.get(name)
            if _values_equal(old_val, new_val):
                continue
            if old_val is None or new_val is None or name not in new_state.local_vars:
                continue
            old_affinity = getattr(old_val, "affinity_type", None)
            new_affinity = getattr(new_val, "affinity_type", None)
            affinity = (
                old_affinity
                if old_affinity == new_affinity and old_affinity != "NoneType"
                else None
            )
            widened_sym, type_constraint = self._symbolic_stack_for_affinity(name, affinity)
            widened.local_vars[name] = widened_sym
            widened.path_constraints = widened.path_constraints.append(type_constraint)


def _values_equal(left: object, right: object) -> bool:
    """Return conservative structural equality for widening eligibility.

    Symbolic equality operators model target-program equality and may return a
    symbolic Boolean carrier rather than a Python bool.  Treating that carrier
    with ``bool(...)`` makes every such comparison truthy, which hides changed
    symbolic locals from the loop widener.
    """
    if left is right:
        return True

    from pysymex._internal.core.types.scalars.values import SymbolicValue

    if isinstance(left, SymbolicValue) and isinstance(right, SymbolicValue):
        import z3

        return (
            left.hash_value() == right.hash_value()
            and left.affinity_type == right.affinity_type
            and z3.eq(left.z3_int, right.z3_int)
            and z3.eq(left.is_int, right.is_int)
            and z3.eq(left.z3_bool, right.z3_bool)
            and z3.eq(left.is_bool, right.is_bool)
            and z3.eq(left.z3_float, right.z3_float)
            and z3.eq(left.is_float, right.is_float)
            and z3.eq(left.z3_str, right.z3_str)
            and z3.eq(left.is_str, right.is_str)
            and z3.eq(left.z3_addr, right.z3_addr)
            and z3.eq(left.is_obj, right.is_obj)
            and z3.eq(left.is_none, right.is_none)
            and z3.eq(left.is_list, right.is_list)
            and z3.eq(left.is_dict, right.is_dict)
        )

    try:
        equality = left == right
    except Exception:
        return False
    if isinstance(equality, SymbolicValue):
        return False
    if isinstance(equality, bool):
        return equality
    return False
