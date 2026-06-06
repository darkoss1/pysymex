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

"""Truth aggregation builtin models."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

from pysymex.core.solver.constraints.literals import exact_bool_literal
from pysymex.core.types.base import SymbolicType
from pysymex.core.types.containers.sequences import SymbolicIterator
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.opcodes.common.generators import ModeledGenerator
from pysymex.models.typed_results import (
    model_bool_result,
    symbolic_bool_result,
)
from ..base import FunctionModel, ModelResult, SideEffectValue
from ..core.helpers import (
    symbolic_list_len_is_zero as _symbolic_list_len_is_zero,
    type_error_side_effect,
)
from ..core.iterator_items import (
    concrete_iterable_items as _shared_concrete_iterable_items,
    iterator_mutation_side_effect,
    remaining_concrete_iterator_items,
)
from .generator.truth import modeled_generator_truth as _modeled_generator_truth
from .helpers import (
    known_iter_type_error as _known_iter_type_error,
    resolve_heap_object as _resolve_heap_object,
)


def _truth_arity_error(name: str, args: list[StackValue], state: VMState) -> ModelResult:
    return model_bool_result(
        f"{name}_{state.pc}",
        side_effects=type_error_side_effect(
            f"builtins.{name}",
            f"{name}() takes exactly one argument ({len(args)} given)",
        ),
    )


class AllModel(FunctionModel):
    """Model for all()."""

    name = "all"
    qualname = "builtins.all"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _truth_arity_error("all", args, state)
        val = _resolve_heap_object(args[0], state)
        if isinstance(val, ModeledGenerator):
            modeled = _modeled_generator_truth(
                name="all", generator=val, state=state, aggregate="all"
            )
            if modeled is not None:
                return modeled
        exact_items = _shared_concrete_iterable_items(val, state)
        if exact_items is not None:
            return _truth_aggregate_result(
                "all",
                exact_items,
                state,
                _truth_iterator_side_effect("all", val, state),
            )
        if isinstance(val, SymbolicList):
            if _symbolic_list_len_is_zero(val):
                return ModelResult(value=SymbolicValue.from_const(True))
            if val.concrete_items is not None:
                val = val.concrete_items
            else:
                return model_bool_result(f"all_{state.pc}")
        if isinstance(val, (list, tuple)):
            if not val:
                return ModelResult(value=SymbolicValue.from_const(True))
            val_seq: list[object] | tuple[object, ...] = cast(
                "list[object] | tuple[object, ...]", val
            )
            if all(isinstance(x, SymbolicValue) for x in val_seq):
                sv_list: list[SymbolicValue] = cast("list[SymbolicValue]", list(val_seq))
                conditions: list[z3.BoolRef] = [x.could_be_truthy() for x in sv_list]
                result, constraints = symbolic_bool_result(f"all_{state.pc}")
                constraints.append(result.z3_bool == z3.And(*conditions))
                return ModelResult(
                    value=result,
                    constraints=constraints,
                )
            return ModelResult(value=SymbolicValue.from_const(all(val_seq)))
        if isinstance(val, (str, bytes)):
            return ModelResult(value=SymbolicValue.from_const(all(val)))
        if isinstance(val, dict):
            return ModelResult(
                value=SymbolicValue.from_const(all(cast("dict[object, object]", val)))
            )
        if isinstance(val, (set, frozenset)):
            return ModelResult(
                value=SymbolicValue.from_const(all(cast("set[object] | frozenset[object]", val)))
            )
        if isinstance(val, SymbolicString) and z3.is_string_value(val.z3_str):
            return ModelResult(value=SymbolicValue.from_const(all(val.z3_str.as_string())))
        if _known_iter_type_error(val):
            return model_bool_result(
                f"all_{state.pc}",
                side_effects=type_error_side_effect(
                    "builtins.all", "all() argument is not iterable"
                ),
            )
        return model_bool_result(f"all_{state.pc}")


class AnyModel(FunctionModel):
    """Model for any()."""

    name = "any"
    qualname = "builtins.any"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _truth_arity_error("any", args, state)
        val = _resolve_heap_object(args[0], state)
        if isinstance(val, ModeledGenerator):
            modeled = _modeled_generator_truth(
                name="any", generator=val, state=state, aggregate="any"
            )
            if modeled is not None:
                return modeled
        exact_items = _shared_concrete_iterable_items(val, state)
        if exact_items is not None:
            return _truth_aggregate_result(
                "any",
                exact_items,
                state,
                _truth_iterator_side_effect("any", val, state),
            )
        if isinstance(val, SymbolicList):
            if _symbolic_list_len_is_zero(val):
                return ModelResult(value=SymbolicValue.from_const(False))
            if val.concrete_items is not None:
                val = val.concrete_items
            else:
                return model_bool_result(f"any_{state.pc}")
        if isinstance(val, (list, tuple)):
            if not val:
                return ModelResult(value=SymbolicValue.from_const(False))
            val_seq: list[object] | tuple[object, ...] = cast(
                "list[object] | tuple[object, ...]", val
            )
            if all(isinstance(x, SymbolicValue) for x in val_seq):
                sv_list: list[SymbolicValue] = cast("list[SymbolicValue]", list(val_seq))
                conditions: list[z3.BoolRef] = [x.could_be_truthy() for x in sv_list]
                result, constraints = symbolic_bool_result(f"any_{state.pc}")
                constraints.append(result.z3_bool == z3.Or(*conditions))
                return ModelResult(
                    value=result,
                    constraints=constraints,
                )
            return ModelResult(value=SymbolicValue.from_const(any(val_seq)))
        if isinstance(val, (str, bytes)):
            return ModelResult(value=SymbolicValue.from_const(any(val)))
        if isinstance(val, dict):
            return ModelResult(
                value=SymbolicValue.from_const(any(cast("dict[object, object]", val)))
            )
        if isinstance(val, (set, frozenset)):
            return ModelResult(
                value=SymbolicValue.from_const(any(cast("set[object] | frozenset[object]", val)))
            )
        if isinstance(val, SymbolicString) and z3.is_string_value(val.z3_str):
            return ModelResult(value=SymbolicValue.from_const(any(val.z3_str.as_string())))
        if _known_iter_type_error(val):
            return model_bool_result(
                f"any_{state.pc}",
                side_effects=type_error_side_effect(
                    "builtins.any", "any() argument is not iterable"
                ),
            )
        return model_bool_result(f"any_{state.pc}")


def _truth_aggregate_result(
    name: str,
    values: list[StackValue],
    state: VMState,
    side_effects: dict[str, SideEffectValue] | None = None,
) -> ModelResult:
    if not values:
        return ModelResult(
            value=SymbolicValue.from_const(name == "all"),
            side_effects=side_effects or {},
        )
    if all(isinstance(value, SymbolicValue) for value in values):
        symbolic_values = cast("list[SymbolicValue]", values)
        conditions = [value.could_be_truthy() for value in symbolic_values]
        result, constraints = symbolic_bool_result(f"{name}_{state.pc}")
        if name == "all":
            constraints.append(result.z3_bool == z3.And(*conditions))
        else:
            constraints.append(result.z3_bool == z3.Or(*conditions))
        return ModelResult(value=result, constraints=constraints, side_effects=side_effects or {})
    if name == "all":
        return ModelResult(
            value=SymbolicValue.from_const(all(values)),
            side_effects=side_effects or {},
        )
    return ModelResult(value=SymbolicValue.from_const(any(values)), side_effects=side_effects or {})


def _truth_iterator_side_effect(
    name: str,
    value: object,
    state: VMState,
) -> dict[str, SideEffectValue] | None:
    if not isinstance(value, SymbolicIterator) or value.is_generator:
        return None
    remaining_items = remaining_concrete_iterator_items(value, state)
    if remaining_items is None:
        return None
    consumed = _truth_consumed_items(name, remaining_items)
    if consumed is None:
        return None
    consumed_count, exhausted = consumed
    updated_iterator = value
    for _ in range(consumed_count):
        updated_iterator = updated_iterator.advance()
    if exhausted:
        updated_iterator = updated_iterator.exhaust()
    return cast(
        "dict[str, SideEffectValue]",
        iterator_mutation_side_effect(value, updated_iterator),
    )


def _truth_consumed_items(
    name: str,
    values: list[StackValue],
) -> tuple[int, bool] | None:
    if name == "any":
        return _any_consumed_items(values)
    return _all_consumed_items(values)


def _any_consumed_items(values: list[StackValue]) -> tuple[int, bool] | None:
    for index, value in enumerate(values, start=1):
        truth = _definite_truth_value(value)
        if truth is None:
            return None
        if truth:
            return index, False
    return len(values), True


def _all_consumed_items(values: list[StackValue]) -> tuple[int, bool] | None:
    for index, value in enumerate(values, start=1):
        truth = _definite_truth_value(value)
        if truth is None:
            return None
        if not truth:
            return index, False
    return len(values), True


def _definite_truth_value(value: object) -> bool | None:
    if isinstance(value, (SymbolicValue, SymbolicType)):
        return exact_bool_literal(z3.simplify(value.could_be_truthy()))
    if isinstance(value, (bool, int, float, str, bytes, bytearray)):
        return bool(value)
    if isinstance(value, list):
        return bool(cast("list[object]", value))
    if isinstance(value, tuple):
        return bool(cast("tuple[object, ...]", value))
    if isinstance(value, dict):
        return bool(cast("dict[object, object]", value))
    if isinstance(value, (set, frozenset)):
        return bool(cast("set[object] | frozenset[object]", value))
    return None
