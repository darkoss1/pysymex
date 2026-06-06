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

"""max() builtin model."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, cast

import z3

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.base import SymbolicType
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.typed_results import (
    symbolic_int_result,
)

from ..base import FunctionModel, ModelResult
from .helpers import (
    resolve_heap_object as _resolve_heap_object,
    safe_max_concrete as _safe_max_concrete,
    symbolic_list_len_is_zero as _symbolic_list_len_is_zero,
    type_error_side_effect as _type_error_side_effect,
    value_error_side_effect as _value_error_side_effect,
)
from .extrema_precision import (
    concrete_sequence_items as _concrete_sequence_items,
    iterator_exhaustion_side_effect as _iterator_exhaustion_side_effect,
    model_result_with_side_effects as _model_result_with_side_effects,
    symbolic_extreme_result as _symbolic_extreme_result,
)


class MaxModel(FunctionModel):
    """Model for max()."""

    name = "max"
    qualname = "builtins.max"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply max() model."""
        if not args:
            result, constraint = SymbolicValue.symbolic(f"max_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=_type_error_side_effect(
                    "builtins.max", "max expected at least 1 argument, got 0"
                ),
            )
        if set(kwargs) - {"key", "default"} or (len(args) > 1 and "default" in kwargs):
            result, constraint = SymbolicValue.symbolic(f"max_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=_type_error_side_effect(
                    "builtins.max", "max() received invalid keyword arguments"
                ),
            )

        first_arg = _resolve_heap_object(args[0], state) if len(args) == 1 else args[0]
        has_default = "default" in kwargs
        has_nontrivial_key = "key" in kwargs and kwargs["key"] is not None

        if (
            len(args) == 1
            and isinstance(first_arg, SymbolicList)
            and _symbolic_list_len_is_zero(first_arg)
        ):
            if has_default:
                return ModelResult(value=kwargs["default"])
            result, constraint = SymbolicValue.symbolic(f"max_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=_value_error_side_effect(
                    "builtins.max", "max() arg is an empty sequence"
                ),
            )
        sequence = _concrete_sequence_items(first_arg, state) if len(args) == 1 else None
        if sequence is not None:
            seq = sequence
            iterator_side_effects = (
                _iterator_exhaustion_side_effect(first_arg, state)
                if not has_nontrivial_key
                else None
            )
            if not seq:
                if has_default:
                    return ModelResult(
                        value=kwargs["default"],
                        side_effects=iterator_side_effects or {},
                    )
                result, constraint = SymbolicValue.symbolic(f"max_{state.pc}")
                return _model_result_with_side_effects(
                    ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects=_value_error_side_effect(
                            "builtins.max", "max() arg is an empty sequence"
                        ),
                    ),
                    iterator_side_effects,
                )
            if has_nontrivial_key:
                result, constraint = SymbolicValue.symbolic(f"max_{state.pc}")
                return ModelResult(value=result, constraints=[constraint])
            symbolic_max = _symbolic_extreme_result(seq, f"max_{state.pc}", "max")
            if symbolic_max is not None:
                return _model_result_with_side_effects(symbolic_max, iterator_side_effects)
            if all(not isinstance(x, (SymbolicValue, SymbolicType)) for x in seq):
                concrete_max = _safe_max_concrete(cast("Sequence[StackValue]", seq))
                if concrete_max is not None:
                    return ModelResult(
                        value=concrete_max,
                        side_effects=iterator_side_effects or {},
                    )
            result, constraint = SymbolicValue.symbolic(f"max_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=iterator_side_effects or {},
            )

        if len(args) >= 2:
            if has_nontrivial_key:
                result, constraint = SymbolicValue.symbolic(f"max_{state.pc}")
                return ModelResult(value=result, constraints=[constraint])
            if all(not isinstance(x, (SymbolicValue, SymbolicType)) for x in args):
                concrete_max = _safe_max_concrete(cast("Sequence[StackValue]", args))
                if concrete_max is not None:
                    return ModelResult(value=concrete_max)

            sym_args = [
                arg if isinstance(arg, SymbolicValue) else SymbolicValue.from_const(arg)
                for arg in args
            ]

            result, constraints = symbolic_int_result(f"max_{state.pc}")
            expr = sym_args[0].z3_int
            for i in range(1, len(sym_args)):
                expr = z3.If(sym_args[i].z3_int > expr, sym_args[i].z3_int, expr)

            constraints.append(result.z3_int == expr)
            return ModelResult(
                value=result,
                constraints=constraints,
            )

        result, constraint = SymbolicValue.symbolic(f"max_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])
