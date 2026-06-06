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

import z3

from pysymex.typing import StackValue
from pysymex.analysis.static.loops.types import LoopInfo

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.core.types.scalars.values import SymbolicValue


class LoopWidening:
    """Applies widening to accelerate loop analysis."""

    def __init__(self, widening_threshold: int = 3) -> None:
        self.widening_threshold = widening_threshold

    def should_widen(self, loop: LoopInfo, current_count: int) -> bool:
        """Check if widening should be applied for the path-sensitive loop count."""
        _ = loop
        return current_count >= self.widening_threshold

    def widen_state(self, old_state: VMState, new_state: VMState, loop: LoopInfo) -> VMState:
        """Apply widening to generalize loop state."""
        widened = new_state.copy()
        handled_vars: set[str] = set()
        for name, iv in loop.induction_vars.items():
            old_val = old_state.locals.get(name)
            new_val = new_state.locals.get(name)
            if old_val is not None and new_val is not None:
                widened_sym, type_constraint = self._symbolic_value_for_affinity(
                    name, getattr(new_val, "affinity_type", None)
                )
                widened.locals[name] = widened_sym
                widened.path_constraints = widened.path_constraints.append(type_constraint)
                handled_vars.add(name)
                if iv.direction >= 0:
                    widened.path_constraints = widened.path_constraints.append(
                        widened_sym.z3_int >= iv.initial
                    )
                else:
                    widened.path_constraints = widened.path_constraints.append(
                        widened_sym.z3_int <= iv.initial
                    )
                if loop.bound is not None:
                    final = iv.final_value(loop.bound.upper)
                    if iv.direction > 0:
                        widened.path_constraints = widened.path_constraints.append(
                            widened_sym.z3_int <= final
                        )
                    else:
                        widened.path_constraints = widened.path_constraints.append(
                            widened_sym.z3_int >= final
                        )
        self._widen_other_changed_locals(old_state, new_state, widened, handled_vars)
        return widened

    @staticmethod
    def _symbolic_value_for_affinity(
        name: str,
        affinity: object,
    ) -> tuple[SymbolicValue, z3.BoolRef]:
        from pysymex.core.types.scalars.values import SymbolicValue

        if affinity == "int":
            return SymbolicValue.symbolic_int(f"{name}_widened")
        if affinity == "bool":
            return SymbolicValue.symbolic_bool(f"{name}_widened")
        return SymbolicValue.symbolic(f"{name}_widened")

    @staticmethod
    def _symbolic_stack_for_affinity(
        name: str,
        affinity: object,
    ) -> tuple[StackValue, z3.BoolRef]:
        from pysymex.core.types.scalars.strings import SymbolicString
        from pysymex.core.types.scalars.values import SymbolicValue

        if affinity == "int":
            return SymbolicValue.symbolic_int(f"{name}_widened")
        if affinity == "bool":
            return SymbolicValue.symbolic_bool(f"{name}_widened")
        if affinity == "str":
            return SymbolicString.symbolic(f"{name}_widened")
        return SymbolicValue.symbolic(f"{name}_widened")

    def _widen_other_changed_locals(
        self,
        old_state: VMState,
        new_state: VMState,
        widened: VMState,
        handled_vars: set[str],
    ) -> None:
        for name in set(old_state.locals.keys()) | set(new_state.locals.keys()):
            if name in handled_vars:
                continue
            old_val = old_state.locals.get(name)
            new_val = new_state.locals.get(name)
            try:
                if old_val == new_val:
                    continue
            except Exception:
                if old_val is new_val:
                    continue
            if old_val is None or new_val is None or name not in new_state.locals:
                continue
            old_affinity = getattr(old_val, "affinity_type", None)
            new_affinity = getattr(new_val, "affinity_type", None)
            affinity = (
                old_affinity
                if old_affinity == new_affinity and old_affinity != "NoneType"
                else None
            )
            widened_sym, type_constraint = self._symbolic_stack_for_affinity(name, affinity)
            widened.locals[name] = widened_sym
            widened.path_constraints = widened.path_constraints.append(type_constraint)


__all__ = ["LoopWidening"]
