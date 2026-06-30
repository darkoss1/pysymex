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

"""Well-founded dynamic ranking proofs for automatic loop exploration."""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar

import z3

from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.scheduling.loop.bounds.finite import exact_int_value

if TYPE_CHECKING:
    import dis
    from collections.abc import Iterable

    from pysymex._internal.core.memory.cow.dicts import CowDict
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.scheduling.loops.types import LoopInfo
    from pysymex._internal.typing.protocols import StackValue

StoreKey = TypeVar("StoreKey")


def finite_container_descent_remaining_steps(
    previous: VMState,
    current: VMState,
) -> int | None:
    """Return a remaining rank when a concrete-backed list strictly shrank.

    The proof is re-established on every header visit. A natural-number length
    cannot decrease forever; if mutation stops decreasing it, the next visit
    falls through to recurrence, widening, or explicit unsupported handling.
    """
    remaining = _finite_container_descent_in_store(
        previous.local_vars,
        current.local_vars,
        previous.path_constraints,
        current.path_constraints,
    )
    if remaining is not None:
        return remaining
    remaining = _finite_container_descent_in_store(
        previous.global_vars,
        current.global_vars,
        previous.path_constraints,
        current.path_constraints,
    )
    if remaining is not None:
        return remaining
    return _finite_container_descent_in_store(
        previous.memory,
        current.memory,
        previous.path_constraints,
        current.path_constraints,
    )


def _finite_container_descent_in_store(
    old_store: CowDict[StoreKey, StackValue],
    new_store: CowDict[StoreKey, StackValue],
    old_constraints: Iterable[z3.BoolRef],
    new_constraints: Iterable[z3.BoolRef],
) -> int | None:
    """Return the first proven list-length descent in one state store."""
    for key in set(old_store) & set(new_store):
        old_length = _symbolic_list_length(old_store[key], old_constraints)
        new_length = _symbolic_list_length(new_store[key], new_constraints)
        if old_length is not None and new_length is not None and 0 <= new_length < old_length:
            return new_length
    return None


def guarded_affine_remaining_steps(
    previous: VMState,
    current: VMState,
    instructions: list[dis.Instruction],
    loop: LoopInfo,
) -> int | None:
    """Return a finite rank for an observed monotone local and literal guard."""
    guards = _literal_exit_guards(instructions, loop)
    for name in set(previous.local_vars) & set(current.local_vars):
        old_value = _exact_integer(previous.local_vars[name], previous.path_constraints)
        new_value = _exact_integer(current.local_vars[name], current.path_constraints)
        if old_value is None or new_value is None or old_value == new_value:
            continue
        for guard_name, relation, bound in guards:
            if guard_name != name:
                continue
            remaining = _guard_rank(old_value, new_value, relation, bound)
            if remaining is not None:
                return remaining
    return None


def _symbolic_list_length(
    value: object,
    constraints: Iterable[z3.BoolRef],
) -> int | None:
    if not isinstance(value, SymbolicList):
        return None
    if value.concrete_items is not None:
        return len(value.concrete_items)
    return exact_int_value(value.z3_len, constraints)


def _exact_integer(value: object, constraints: Iterable[z3.BoolRef]) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if not isinstance(value, SymbolicValue):
        return None
    if not z3.is_true(simplify_expr(value.is_int)):
        return None
    return exact_int_value(value.z3_int, constraints)


def _literal_exit_guards(
    instructions: list[dis.Instruction],
    loop: LoopInfo,
) -> list[tuple[str, str, int]]:
    guards: list[tuple[str, str, int]] = []
    loop_offsets = loop.body_pcs | {loop.header_pc, loop.back_edge_pc}
    for index in range(len(instructions) - 3):
        left, right, compare, jump = instructions[index : index + 4]
        if compare.offset not in loop_offsets or not jump.opname.startswith("POP_JUMP"):
            continue
        exits_on_false = "IF_FALSE" in jump.opname and jump.argval in loop.exit_pcs
        continues_on_true = "IF_TRUE" in jump.opname and jump.argval in loop_offsets
        if not exits_on_false and not continues_on_true:
            continue
        relation = compare.argval if isinstance(compare.argval, str) else compare.argrepr
        if compare.opname != "COMPARE_OP" or relation not in {"<", "<=", ">", ">="}:
            continue
        if left.opname == "LOAD_FAST" and right.opname == "LOAD_CONST":
            name = left.argval
            bound = right.argval
        elif left.opname == "LOAD_CONST" and right.opname == "LOAD_FAST":
            name = right.argval
            bound = left.argval
            relation = _reverse_relation(relation)
        else:
            continue
        if isinstance(name, str) and isinstance(bound, int) and not isinstance(bound, bool):
            guards.append((name, relation, bound))
    return guards


def _reverse_relation(relation: str) -> str:
    return {"<": ">", "<=": ">=", ">": "<", ">=": "<="}[relation]


def _guard_rank(old_value: int, new_value: int, relation: str, bound: int) -> int | None:
    if relation == "<" and new_value > old_value and new_value < bound:
        return bound - new_value
    if relation == "<=" and new_value > old_value and new_value <= bound:
        return bound - new_value + 1
    if relation == ">" and new_value < old_value and new_value > bound:
        return new_value - bound
    if relation == ">=" and new_value < old_value and new_value >= bound:
        return new_value - bound + 1
    return None
