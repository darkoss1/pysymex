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

"""Modeled generator-expression truth conditions for ``all`` and ``any``."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, Literal, cast

import z3

from pysymex._internal.core.cache.code.instructions import get_instructions
from pysymex._internal.core.constants import Z3_FALSE, Z3_ONE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.base import SymbolicType
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.results import ModelResult

from .exceptions import modeled_generator_call_exceptions
from .sources import generator_code, generator_items

if TYPE_CHECKING:
    import dis
    import types

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.types.containers.generators import ModeledGenerator

_SUPPORTED_COMPARE_OPS: Final = frozenset(("==", "!=", ">", ">=", "<", "<="))


def modeled_generator_truth(
    *,
    name: str,
    generator: ModeledGenerator,
    state: VMState,
    aggregate: Literal["all", "any"],
) -> ModelResult | None:
    """Model simple generator-expression yields for ``all`` and ``any``."""
    code = generator_code(generator)
    if code is None:
        return None
    comparison = _simple_compare_const(code)
    direct_truth = comparison is None and _simple_direct_truth_yield(code)
    if comparison is None and not direct_truth:
        return modeled_generator_call_exceptions(name=name, generator=generator, state=state)
    items = generator_items(generator, state)
    if items is None:
        return None

    conditions: list[z3.BoolRef] = []
    for item in items:
        if comparison is None:
            condition = _truth_condition_for_item(item)
        else:
            op_name, constant = comparison
            condition = _compare_item_to_constant(item, op_name, constant)
        if condition is None:
            return None
        conditions.append(condition)

    if not conditions:
        return ModelResult(value=SymbolicValue.from_const(aggregate == "all"))

    result, constraints = ModelResult.symbolic_bool(f"{name}_{state.pc}")
    aggregate_condition = z3.And(*conditions) if aggregate == "all" else z3.Or(*conditions)
    constraints.append(result.z3_bool == aggregate_condition)
    return ModelResult(value=result, constraints=constraints)


def _simple_compare_const(code: types.CodeType) -> tuple[str, object] | None:
    """Recognize generator bodies shaped like ``item == const`` or ``item != const``."""
    instructions = list(get_instructions(code))
    for index, instruction in enumerate(instructions):
        if instruction.opname != "COMPARE_OP" or index == 0:
            continue
        previous = instructions[index - 1]
        if previous.opname != "LOAD_CONST":
            continue
        op_name = _compare_op_name(instruction)
        if op_name not in _SUPPORTED_COMPARE_OPS:
            return None
        return op_name, previous.argval
    return None


def _compare_op_name(instruction: dis.Instruction) -> str:
    """Normalize CPython version-specific comparison names."""
    op_name = str(instruction.argrepr or instruction.argval)
    if op_name.startswith("bool(") and op_name.endswith(")"):
        return op_name[5:-1]
    return op_name


def _simple_direct_truth_yield(code: types.CodeType) -> bool:
    """Return whether a generator body yields the loop item directly."""
    instructions = list(get_instructions(code))
    for index, instruction in enumerate(instructions):
        if instruction.opname != "YIELD_VALUE" or index == 0:
            continue
        previous = instructions[index - 1]
        return previous.opname in {"LOAD_FAST", "STORE_FAST_LOAD_FAST"}
    return False


def _compare_arith(
    left: z3.ArithRef,
    op_name: str,
    right: z3.ArithRef,
) -> z3.BoolRef:
    """Return an arithmetic comparison expression for a supported generator op."""
    if op_name == "==":
        return left == right
    if op_name == "!=":
        return left != right
    if op_name == ">":
        return left > right
    if op_name == ">=":
        return left >= right
    if op_name == "<":
        return left < right
    if op_name == "<=":
        return left <= right
    msg = f"unsupported comparison op: {op_name}"
    raise ValueError(msg)


def _compare_ints(left: int, op_name: str, right: int) -> bool:
    """Return a Python int/bool comparison for a supported generator op."""
    if op_name == "==":
        return left == right
    if op_name == "!=":
        return left != right
    if op_name == ">":
        return left > right
    if op_name == ">=":
        return left >= right
    if op_name == "<":
        return left < right
    if op_name == "<=":
        return left <= right
    msg = f"unsupported comparison op: {op_name}"
    raise ValueError(msg)


def _symbolic_numeric_compare(
    item: SymbolicValue,
    op_name: str,
    constant: int,
) -> z3.BoolRef:
    """Compare symbolic int/bool payloads using CPython's bool-is-int relation."""
    right = ConstraintValues.int(constant)
    if z3.is_true(item.is_bool):
        bool_expr = z3.If(item.z3_bool, Z3_ONE, Z3_ZERO)
        return _compare_arith(bool_expr, op_name, right)
    if z3.is_true(item.is_int) and z3.is_false(item.is_bool):
        return _compare_arith(item.z3_int, op_name, right)
    if z3.is_false(item.is_int) and z3.is_false(item.is_bool):
        return Z3_FALSE

    numeric_expr = z3.If(
        item.is_bool,
        z3.If(item.z3_bool, Z3_ONE, Z3_ZERO),
        item.z3_int,
    )
    return z3.And(
        z3.Or(item.is_int, item.is_bool),
        _compare_arith(numeric_expr, op_name, right),
    )


def _compare_concrete_item(item: object, op_name: str, constant: object) -> z3.BoolRef | None:
    """Return a concrete comparison result, or ``None`` for unsupported type pairs."""
    if isinstance(item, int) and isinstance(constant, int):
        return Z3_TRUE if _compare_ints(int(item), op_name, int(constant)) else Z3_FALSE
    if op_name == "==":
        return Z3_TRUE if item == constant else Z3_FALSE
    if op_name == "!=":
        return Z3_TRUE if item != constant else Z3_FALSE
    return None


def _compare_item_to_constant(item: object, op_name: str, constant: object) -> z3.BoolRef | None:
    """Build the yielded boolean for a supported simple generator comparison."""
    if isinstance(constant, SymbolicValue):
        constant = constant.value

    if isinstance(item, SymbolicValue):
        if constant is None:
            if op_name not in {"==", "!="}:
                return None
            condition = item.is_none
        elif isinstance(constant, int):
            return _symbolic_numeric_compare(item, op_name, int(constant))
        elif isinstance(constant, str):
            if op_name not in {"==", "!="}:
                return None
            condition = z3.And(item.is_str, item.z3_str == ConstraintValues.string(constant))
        else:
            return None
        return z3.Not(condition) if op_name == "!=" else condition

    return _compare_concrete_item(item, op_name, constant)


def _truth_condition_for_item(item: object) -> z3.BoolRef | None:
    """Build the yielded boolean for a direct truth-yielded generator item."""
    if isinstance(item, SymbolicType):
        return item.could_be_truthy()
    if item is None:
        return Z3_FALSE
    if isinstance(item, bool):
        return Z3_TRUE if item else Z3_FALSE
    if isinstance(item, (int, float)):
        return Z3_TRUE if item != 0 else Z3_FALSE
    if isinstance(item, (str, bytes)):
        return Z3_TRUE if item else Z3_FALSE
    if isinstance(item, tuple):
        return Z3_TRUE if cast("tuple[object, ...]", item) else Z3_FALSE
    if isinstance(item, list):
        return Z3_TRUE if cast("list[object]", item) else Z3_FALSE
    if isinstance(item, dict):
        return Z3_TRUE if cast("dict[object, object]", item) else Z3_FALSE
    if isinstance(item, set):
        return Z3_TRUE if cast("set[object]", item) else Z3_FALSE
    if isinstance(item, frozenset):
        return Z3_TRUE if cast("frozenset[object]", item) else Z3_FALSE
    return None
