# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

import os
import sys
import types

import z3

cwd = os.getcwd()
pysymex = types.ModuleType("pysymex")
sys.modules["pysymex"] = pysymex
pysymex.__path__ = [cwd]

if cwd in sys.path:
    sys.path.remove(cwd)
if "" in sys.path:
    sys.path.remove("")

from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from pysymex._typing import StackValue

from pysymex.core.memory.collections.lists import SymbolicListOps
from pysymex.core.objects import OBJECT_CLASS
from pysymex.core.optimization import StateMerger
from pysymex.core.state import create_initial_state
from pysymex.core.types.scalars import SymbolicValue
from pysymex.core.types.containers import SymbolicList


def test_collection_isolation() -> None:
    """Test that mutating a concrete collection in one branch doesn't affect others."""
    state = create_initial_state()
    lst: list[StackValue] = [1, 2]
    state.local_vars["l"] = lst

    state_a = state.fork()
    state_b = state.fork()

    l_val = state_a.local_vars["l"]
    assert isinstance(l_val, list)
    res = SymbolicListOps.append(cast("list[object]", l_val), 3)
    state_a.local_vars["l"] = cast("StackValue", res.modified_collection)

    print(f"Branch A list: {state_a.local_vars['l']}")
    print(f"Branch B list: {state_b.local_vars['l']}")

    l_a = state_a.local_vars["l"]
    l_b = state_b.local_vars["l"]
    assert isinstance(l_a, list)
    assert isinstance(l_b, list)
    assert 3 in l_a
    assert 3 not in l_b, "Leak! Branch B sees mutation from Branch A"


def test_state_merging_soundness() -> None:
    """Test that merging preserves stack and memory using conditional merge."""
    state = create_initial_state()
    merger = StateMerger()

    state_a = state.fork()
    state_a.push(SymbolicValue.from_const(10))
    state_a = state_a.add_constraint(z3.Bool("cond"))

    state_b = state.fork()
    state_b.push(SymbolicValue.from_const(20))
    state_b = state_b.add_constraint(z3.Not(z3.Bool("cond")))

    merged = merger.merge_states(state_a, state_b)
    assert merged is not None
    assert len(merged.stack) == 1

    merged_val = merged.stack[0]
    print(f"Merged stack value: {merged_val}")

    solver = z3.Solver()
    solver.add(merged.copy_constraints())

    assert isinstance(merged_val, SymbolicValue)

    solver.push()
    solver.add(z3.Bool("cond"))
    assert solver.check() == z3.sat
    model = solver.model()

    assert model.evaluate(merged_val.z3_int).as_long() == 10
    solver.pop()

    solver.push()
    solver.add(z3.Not(z3.Bool("cond")))
    assert solver.check() == z3.sat
    model = solver.model()
    assert model.evaluate(merged_val.z3_int).as_long() == 20
    solver.pop()


def test_object_identity_persistence() -> None:
    """Test that object state is shared across forks and maintains identity."""
    state = create_initial_state()

    obj1 = state.object_state.create_object(OBJECT_CLASS, "my_obj")

    state_a = state.fork()

    obj2 = state_a.object_state.create_object(OBJECT_CLASS, "another_obj")

    assert state_a.object_state.get_object(obj1.id) is not None
    assert state_a.object_state.get_object(obj2.id) is not None

    state_b = state.fork()
    assert state_b.object_state.get_object(obj1.id) is not None
    assert state_b.object_state.get_object(obj2.id) is None


def test_multiplexed_value_merge() -> None:
    """Test that z3_len is merged in conditional_merge."""
    v1 = SymbolicList.from_const([1, 2, 3])
    v2 = SymbolicList.from_const([1])

    cond = z3.Bool("c")
    merged = v1.conditional_merge(v2, cond)

    assert isinstance(merged, SymbolicList)
    assert merged.z3_len is not None

    solver = z3.Solver()
    solver.push()
    solver.add(cond)
    assert solver.check() == z3.sat
    assert solver.model().evaluate(merged.z3_len).as_long() == 3
    solver.pop()

    solver.push()
    solver.add(z3.Not(cond))
    assert solver.check() == z3.sat
    assert solver.model().evaluate(merged.z3_len).as_long() == 1
    solver.pop()


if __name__ == "__main__":
    print("Running Core Soundness Tests...")
    test_collection_isolation()
    print("PASS: Collection Isolation")
    test_state_merging_soundness()
    print("PASS: State Merging Soundness")
    test_object_identity_persistence()
    print("PASS: Object Identity Persistence")
    test_multiplexed_value_merge()
    print("PASS: Multiplexed Value Merge")
    print("\nALL CORE SOUNDNESS TESTS PASSED")

