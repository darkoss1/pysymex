# pysymex: Python Symbolic Execution & Formal Verification
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

"""Lowering for call opcodes.

The lowerer resolves CPython call-stack layouts and emits callable-null checks.
"""

from __future__ import annotations

import types
from dataclasses import dataclass
from typing import TYPE_CHECKING

import z3

from pysymex.core.types import (
    SymbolicNone,
    SymbolicObject,
    SymbolicValue,
)
from pysymex.core.constants import Z3_TRUE

if TYPE_CHECKING:
    from pysymex._typing import StackValue


@dataclass(frozen=True)
class CallLayout:
    """Represents the resolved components of a function call."""

    func_obj: StackValue
    args: list[StackValue]
    kwargs: dict[str, StackValue]
    is_heuristic_callable: bool


class CallLowerer:
    """Resolve Python call targets and argument layout."""

    def __init__(self, pc: int):
        self.pc = pc

    def resolve_layout(
        self,
        top_value: StackValue,
        receiver_or_null: StackValue,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
    ) -> CallLayout:
        """Resolve the (func, self, args) layout from the stack components."""

        func_obj = top_value
        final_args = list(args)

        if not isinstance(receiver_or_null, SymbolicNone) and receiver_or_null is not None:
            final_args.insert(0, receiver_or_null)

        is_heuristic = self.is_likely_callable(func_obj)

        return CallLayout(
            func_obj=func_obj, args=final_args, kwargs=kwargs, is_heuristic_callable=is_heuristic
        )

    def is_likely_callable(self, obj: object) -> bool:
        if callable(obj):
            return True
        if isinstance(obj, (SymbolicObject, SymbolicValue)):
            enhanced = getattr(obj, "_enhanced_object", None)
            if getattr(obj, "affinity_type", None) == "type" or isinstance(
                enhanced, types.CodeType
            ):
                return True
            name = getattr(obj, "_name", "") or getattr(obj, "name", "")
            if (
                name.startswith("import_")
                or name.endswith(".close")
                or any(part.isupper() for part in name.split("."))
                or getattr(obj, "model_name", None)
            ):
                return True
        return False

    def emit_none_check(self, func_obj: StackValue) -> z3.BoolRef:
        """Return condition for whether the callable is None/NULL."""
        if isinstance(func_obj, (SymbolicNone, SymbolicValue)):
            return Z3_TRUE if isinstance(func_obj, SymbolicNone) else func_obj.is_none
        return z3.BoolVal(func_obj is None)
