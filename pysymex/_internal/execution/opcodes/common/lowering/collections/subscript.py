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

"""Subscript lowering for symbolic collection containers."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.opcodes.common.lowering.collections.coercion import (
    CollectionCoercionMixin,
)
from pysymex._internal.execution.opcodes.common.lowering.subscripts import (
    concrete_int_index,
    lower_concrete_subscript,
    to_stack_value,
)
from pysymex._internal.execution.opcodes.common.lowering.types import (
    UNSUPPORTED_SUBSCRIPT_ABSTRACTION,
    LoweredValue,
)

if TYPE_CHECKING:
    from pysymex._internal.typing.protocols import StackValue


class SubscriptLoweringMixin(CollectionCoercionMixin):
    """Lower subscript operations for concrete-backed and symbolic collections."""

    def lower_subscript(self, container: object, index: StackValue) -> LoweredValue:
        """Lower a subscript operation while preserving concrete CPython cases."""
        concrete = lower_concrete_subscript(self.pc, container, index)
        if concrete is not None:
            return concrete

        if isinstance(container, SymbolicList):
            concrete_items = container.concrete_items
            concrete_index = concrete_int_index(index)
            if concrete_items is not None and concrete_index is not None:
                try:
                    return LoweredValue(to_stack_value(concrete_items[concrete_index]))
                except IndexError:
                    result, constraint = SymbolicValue.symbolic(f"subscr_error_{self.pc}")
                    return LoweredValue(
                        result,
                        constraints=[constraint],
                        exception_condition=Z3_TRUE,
                    )

            s_idx = self._coerce_index(index)
            if s_idx is not None:
                bounds_check = z3.And(
                    s_idx.z3_int >= -container.z3_len,
                    s_idx.z3_int < container.z3_len,
                )
                return LoweredValue(container[s_idx], exception_condition=z3.Not(bounds_check))

        if isinstance(container, SymbolicTuple):
            concrete_index = concrete_int_index(index)
            if concrete_index is not None:
                try:
                    return LoweredValue(to_stack_value(container[concrete_index]))
                except IndexError:
                    result, constraint = SymbolicValue.symbolic(f"subscr_error_{self.pc}")
                    return LoweredValue(
                        result,
                        constraints=[constraint],
                        exception_condition=Z3_TRUE,
                    )

            s_idx = self._coerce_index(index)
            if s_idx is not None:
                return LoweredValue(
                    to_stack_value(container[s_idx]),
                    exception_condition=z3.Not(container.in_bounds(s_idx)),
                )

        if isinstance(container, SymbolicDict):
            concrete_presence = container.concrete_key_presence_condition(index)
            if concrete_presence is not None:
                has_value, concrete_value = container.concrete_value_for_key(index)
                if has_value:
                    return LoweredValue(to_stack_value(concrete_value))
                if getattr(container, "_has_default_factory", False):
                    default_key = self._coerce_key(index)
                    if default_key is not None:
                        default_value, _presence = container[default_key]
                        return LoweredValue(default_value)
                conditional_value = self._conditional_retained_dict_value(container, index)
                if conditional_value is not None:
                    return LoweredValue(
                        conditional_value,
                        exception_condition=z3.Not(concrete_presence),
                    )
                concrete_items_obj = getattr(container, "_concrete_items", None)
                if isinstance(concrete_items_obj, dict):
                    concrete_items = cast("dict[object, object]", concrete_items_obj)
                    if len(concrete_items) == 1:
                        concrete_value = next(iter(concrete_items.values()))
                        return LoweredValue(
                            to_stack_value(concrete_value),
                            exception_condition=z3.Not(concrete_presence),
                        )
                result, constraint = SymbolicValue.symbolic(f"{container.name}[{self.pc}]")
                return LoweredValue(
                    result,
                    constraints=[constraint],
                    exception_condition=z3.Not(concrete_presence),
                )

            s_key = self._coerce_key(index)
            if s_key is not None:
                result, presence_check = container[s_key]
                if getattr(container, "_value_type", None) == "list[str]":
                    value, constraints = self._symbolic_string_list_value(container, s_key)
                    return LoweredValue(
                        value,
                        constraints=constraints,
                        exception_condition=z3.Not(presence_check),
                    )
                if getattr(container, "_value_type", None) == "dict":
                    result, constraint = self._nested_symbolic_dict(container, s_key)
                    return LoweredValue(
                        result,
                        constraints=[constraint],
                        exception_condition=z3.Not(presence_check),
                    )
                return LoweredValue(result, exception_condition=z3.Not(presence_check))

        if isinstance(container, SymbolicString):
            s_idx = self._coerce_index(index)
            if s_idx is not None:
                bounds_check = z3.And(
                    s_idx.z3_int >= -container.z3_len,
                    s_idx.z3_int < container.z3_len,
                )
                real_idx = z3.If(s_idx.z3_int < 0, s_idx.z3_int + container.z3_len, s_idx.z3_int)
                char_str = container.substring(
                    self._to_int_val(f"idx_{self.pc}", real_idx),
                    self._to_int_val(f"idx_plus_1_{self.pc}", real_idx + 1),
                )
                return LoweredValue(char_str, exception_condition=z3.Not(bounds_check))

        result, constraint = SymbolicValue.symbolic(f"subscr_havoc_{self.pc}")
        return LoweredValue(
            result,
            constraints=[constraint],
            degraded_passes=[UNSUPPORTED_SUBSCRIPT_ABSTRACTION],
        )

    def _nested_symbolic_dict(
        self,
        container: SymbolicDict,
        key: SymbolicString,
    ) -> tuple[SymbolicDict, z3.BoolRef]:
        """Allocate a fresh symbolic nested dict for a missing key lookup."""
        nested, constraint = SymbolicDict.symbolic(f"{container.name}[{key.name}]")
        return nested, constraint

    def _symbolic_string_list_value(
        self,
        container: SymbolicDict,
        key: SymbolicString,
    ) -> tuple[SymbolicList, list[z3.BoolRef]]:
        """Allocate a non-empty list[str] value for typed symbolic dictionaries."""
        item, constraint = SymbolicString.symbolic(f"{container.name}[{key.name}][0]_{self.pc}")
        return SymbolicList.from_const([item]), [constraint]

    def _conditional_retained_dict_value(
        self,
        container: SymbolicDict,
        key: object,
    ) -> StackValue | None:
        """Return an exact finite-domain lookup value for retained dictionary items."""
        value_conditions = container.concrete_value_conditions_for_key(key)
        if not value_conditions:
            return None
        value_conditions_list = list(value_conditions)
        string_value = self._conditional_retained_dict_string(
            container,
            key,
            value_conditions_list,
        )
        if string_value is not None:
            return string_value
        return self._conditional_retained_dict_integer(container, key, value_conditions_list)

    def _conditional_retained_dict_integer(
        self,
        container: SymbolicDict,
        key: object,
        value_conditions: list[tuple[z3.BoolRef, object]],
    ) -> SymbolicValue | None:
        """Return a conditional int carrier for int/bool retained dictionary values."""
        last_value = self._int_like_retained_value(value_conditions[-1][1])
        if last_value is None:
            return None

        result_expr = last_value.z3_int
        for condition, value in reversed(value_conditions[:-1]):
            value_symbolic = self._int_like_retained_value(value)
            if value_symbolic is None:
                return None
            result_expr = z3.If(condition, value_symbolic.z3_int, result_expr)

        return SymbolicValue(
            _name=f"{container.name}[{getattr(key, 'name', key)!s}]",
            z3_int=simplify_expr(result_expr),
            is_int=Z3_TRUE,
            z3_bool=Z3_FALSE,
            is_bool=Z3_FALSE,
            is_str=Z3_FALSE,
            is_none=Z3_FALSE,
            affinity_type="int",
        )

    def _conditional_retained_dict_string(
        self,
        container: SymbolicDict,
        key: object,
        value_conditions: list[tuple[z3.BoolRef, object]],
    ) -> SymbolicString | None:
        """Return a conditional string carrier for retained dictionary values."""
        last_str, last_len = self._string_retained_value_channels(value_conditions[-1][1])
        if last_str is None or last_len is None:
            return None

        result_str = last_str
        result_len = last_len
        for condition, value in reversed(value_conditions[:-1]):
            value_str, value_len = self._string_retained_value_channels(value)
            if value_str is None or value_len is None:
                return None
            result_str = z3.If(condition, value_str, result_str)
            result_len = z3.If(condition, value_len, result_len)

        return SymbolicString(
            _z3_str=simplify_expr(result_str),
            _z3_len=simplify_expr(result_len),
            _name=f"{container.name}[{getattr(key, 'name', key)!s}]",
        )

    def _int_like_retained_value(self, value: object) -> SymbolicValue | None:
        """Return an integer-channel value for retained int/bool payloads."""
        symbolic = SymbolicValue.from_const(value)
        if symbolic.affinity_type in {"int", "bool"}:
            return symbolic
        return None

    def _string_retained_value_channels(
        self,
        value: object,
    ) -> tuple[z3.SeqRef | None, z3.ArithRef | None]:
        """Return string and length channels for retained string payloads."""
        if isinstance(value, str):
            return ConstraintValues.string(value), ConstraintValues.int(len(value))
        if isinstance(value, SymbolicString):
            return value.z3_str, value.z3_len
        if isinstance(value, SymbolicValue) and z3.is_true(simplify_expr(value.is_str)):
            return value.z3_str, z3.Length(value.z3_str)
        return None, None
