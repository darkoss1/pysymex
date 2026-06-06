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

"""Deque model for collections."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.core.identity.addressing import next_address
from pysymex.core.solver.constraints.hashing import get_int_val
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


def _deque_storage(arg: object, state: VMState) -> SymbolicList | None:
    if isinstance(arg, SymbolicList):
        return arg
    if isinstance(arg, SymbolicObject):
        stored = state.load_heap(arg.address)
        if isinstance(stored, SymbolicList):
            return stored
    return None


class DequeConstructorModel(FunctionModel):
    """Model for collections.deque() as heap-backed sequence storage."""

    name = "deque"
    qualname = "collections.deque"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        source = _deque_storage(args[0], state) if args else None
        constraints: list[z3.BoolRef] = []
        if source is None and args:
            storage, constraint = SymbolicList.symbolic(f"deque_{state.pc}")
            constraints.append(constraint)
        elif source is None:
            storage = SymbolicList.empty(f"deque_{state.pc}")
        else:
            storage = source.copy()
        setattr(storage, "_type", "deque")
        address = next_address()
        handle = SymbolicObject(f"deque_{address}", address, get_int_val(address), {address})
        state.store_heap(address, storage)
        return ModelResult(value=handle, constraints=constraints)


class DequePopleftModel(FunctionModel):
    """Model deque.popleft() with CPython-compatible empty-deque failure."""

    name = "popleft"
    qualname = "deque.popleft"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        storage = _deque_storage(args[0], state) if args else None
        result, result_constraint = SymbolicValue.symbolic(f"deque_popleft_{state.pc}")
        constraints: list[z3.BoolRef] = [result_constraint]
        side_effects: dict[str, object] = {}
        if storage is not None:
            index = SymbolicValue.from_const(0)
            result = storage[index]
            updated = storage.__delitem__(index)
            setattr(updated, "_type", "deque")
            constraints.append(storage.z3_len > 0)
            side_effects["potential_exception"] = {
                "type": "IndexError",
                "message": "pop from an empty deque",
                "condition": storage.z3_len == 0,
            }
            side_effects["list_mutation"] = {
                "operation": "popleft",
                "original_list": storage,
                "updated_list": updated,
            }
        return ModelResult(value=result, constraints=constraints, side_effects=side_effects)


class DequeModel:
    """Model for collections.deque.

    Double-ended queue with O(1) append/pop on both ends.
    Uses high-fidelity SymbolicList extensions for prepend and rotate.
    """

    @staticmethod
    def model_init(
        state: VMState,
        iterable: SymbolicList | None = None,
        maxlen: int | None = None,
    ) -> SymbolicList:
        """Model deque() initialization."""
        _ = maxlen
        if iterable is not None:
            return iterable
        return SymbolicList.empty("deque")

    @staticmethod
    def apply(
        args: list[object],
        kwargs: dict[str, object],
        state: VMState,
    ) -> ModelResult:
        """Dispatch deque method calls to high-fidelity SymbolicList methods."""
        from pysymex.core.types.base import SymbolicNoneType as SymbolicNone

        lst = args[0] if args and isinstance(args[0], SymbolicList) else None
        side_effects: dict[str, object] = {}

        if lst is not None:
            method_name = kwargs.get("_method_name", "")
            if method_name == "append" and len(args) > 1:
                val = args[1]
                sym_val = val if isinstance(val, SymbolicValue) else SymbolicValue.from_const(val)
                new_list = lst.append(sym_val)
                side_effects["list_mutation"] = {"operation": "append", "updated_list": new_list}
            elif method_name == "appendleft" and len(args) > 1:
                val = args[1]
                sym_val = val if isinstance(val, SymbolicValue) else SymbolicValue.from_const(val)
                new_list = lst.prepend(sym_val)
                side_effects["list_mutation"] = {
                    "operation": "appendleft",
                    "updated_list": new_list,
                }
            elif method_name == "rotate":
                n_arg = args[1] if len(args) > 1 else 1
                n_val: int | z3.ArithRef
                if isinstance(n_arg, int):
                    n_val = n_arg
                elif hasattr(n_arg, "z3_int"):
                    n_val = getattr(n_arg, "z3_int")
                elif isinstance(n_arg, z3.ArithRef):
                    n_val = n_arg
                else:
                    n_val = 1
                new_list = lst.rotate(n_val)
                side_effects["list_mutation"] = {"operation": "rotate", "updated_list": new_list}

        return ModelResult(value=SymbolicNone(), side_effects=side_effects)

    @staticmethod
    def model_pop(deque: SymbolicList) -> SymbolicValue:
        """Model deque.pop(). Removes and returns from right end."""
        from pysymex.core.types.scalars.values import SymbolicValue

        result, _ = SymbolicValue.symbolic("deque_pop_result")
        return result

    @staticmethod
    def model_popleft(deque: SymbolicList) -> SymbolicValue:
        """Model deque.popleft(). Removes and returns from left end."""
        from pysymex.core.types.scalars.values import SymbolicValue

        result, _ = SymbolicValue.symbolic("deque_popleft_result")
        return result

    @staticmethod
    def model_extend(deque: SymbolicList, iterable: SymbolicList) -> None:
        """Model deque.extend(iterable). Extends right side."""
        pass

    @staticmethod
    def model_extendleft(deque: SymbolicList, iterable: SymbolicList) -> None:
        """Model deque.extendleft(iterable). Extends left side."""
        pass

    @staticmethod
    def model_clear(deque: SymbolicList) -> None:
        """Model deque.clear(). Removes all elements."""
        pass


DEQUE_MODELS: list[FunctionModel] = [DequeConstructorModel(), DequePopleftModel()]


__all__ = ["DEQUE_MODELS", "DequeConstructorModel", "DequeModel", "DequePopleftModel"]
