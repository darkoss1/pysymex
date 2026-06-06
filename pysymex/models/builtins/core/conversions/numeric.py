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

"""float(), complex(), and slice() builtin models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import z3

from pysymex.core.constants import Z3_ZERO
from pysymex.core.solver.constraints.hashing import get_int_val

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue

from ...base import FunctionModel, ModelResult
from ..helpers import type_error_side_effect, value_error_side_effect


class FloatModel(FunctionModel):
    """Model for float()."""

    name = "float"
    qualname = "builtins.float"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) > 1 or kwargs:
            result, constraint = SymbolicValue.symbolic(f"float_invalid_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.float", "float() accepts at most one argument"
                ),
            )
        if not args:
            return ModelResult(value=SymbolicValue.from_const(0.0))
        val = args[0]
        if isinstance(val, SymbolicString) and z3.is_string_value(val.z3_str):
            literal = val.z3_str.as_string()
            try:
                from pysymex.core.types.advanced_float import AdvancedSymbolicFloat

                return ModelResult(value=AdvancedSymbolicFloat(value=float(literal)))
            except ValueError as exc:
                from pysymex.core.types.advanced_float import AdvancedSymbolicFloat

                return ModelResult(
                    value=AdvancedSymbolicFloat(f"float_{state.pc}"),
                    side_effects=value_error_side_effect("float", str(exc)),
                )
        if isinstance(val, SymbolicString):
            from pysymex.core.types.advanced_float import AdvancedSymbolicFloat

            return ModelResult(
                value=AdvancedSymbolicFloat(f"float_{state.pc}"),
                side_effects={
                    "potential_exception": {
                        "type": "ValueError",
                        "message": "could not convert string to float",
                        "condition": z3.Bool(f"float_parse_error_{state.pc}"),
                    }
                },
            )
        if isinstance(val, SymbolicValue):
            if val.type_tag == "float":
                return ModelResult(value=val)
            elif val.type_tag == "int" or z3.is_true(val.is_int):
                from pysymex.core.types.advanced_float import AdvancedSymbolicFloat
                from pysymex.config.floats import get_fp_sort

                result = AdvancedSymbolicFloat(f"float_{state.pc}")
                rm = result.config.get_rounding_mode()
                sort = get_fp_sort(result.config.precision)
                fp_val = z3.fpToFP(rm, z3.ToReal(val.z3_int), sort)
                return ModelResult(
                    value=result,
                    constraints=[z3.fpEQ(result.z3_expr, fp_val)],
                )
        if isinstance(val, (int, float)):
            from pysymex.core.types.advanced_float import AdvancedSymbolicFloat

            return ModelResult(value=AdvancedSymbolicFloat(value=float(val)))
        if isinstance(val, (str, bytes, bytearray)):
            try:
                from pysymex.core.types.advanced_float import AdvancedSymbolicFloat

                return ModelResult(value=AdvancedSymbolicFloat(value=float(val)))
            except ValueError as exc:
                from pysymex.core.types.advanced_float import AdvancedSymbolicFloat

                return ModelResult(
                    value=AdvancedSymbolicFloat(f"float_{state.pc}"),
                    side_effects=value_error_side_effect("float", str(exc)),
                )
        from pysymex.core.types.advanced_float import AdvancedSymbolicFloat

        if val is None or isinstance(val, (list, tuple, dict, set)):
            return ModelResult(
                value=AdvancedSymbolicFloat(f"float_{state.pc}"),
                side_effects=type_error_side_effect(
                    "builtins.float", "float() requires a string or real number"
                ),
            )
        result = AdvancedSymbolicFloat(f"float_{state.pc}")
        return ModelResult(value=result)


class ComplexModel(FunctionModel):
    """Model for complex()."""

    name = "complex"
    qualname = "builtins.complex"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if (
            len(args) > 2
            or set(kwargs) - {"real", "imag"}
            or (args and "real" in kwargs)
            or (len(args) > 1 and "imag" in kwargs)
        ):
            result, constraint = SymbolicValue.symbolic(f"complex_invalid_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.complex", "complex() received invalid arguments"
                ),
            )
        real: StackValue = args[0] if args else kwargs.get("real", 0)
        has_imag = len(args) > 1 or "imag" in kwargs
        imag: StackValue | None = args[1] if len(args) > 1 else kwargs.get("imag")
        if not has_imag and isinstance(real, (int, float, bool, str)):
            try:
                return ModelResult(value=SymbolicValue.from_const(complex(real)))
            except ValueError as exc:
                result, constraint = SymbolicValue.symbolic(f"complex_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=value_error_side_effect("builtins.complex", str(exc)),
                )
        if (
            has_imag
            and isinstance(real, (int, float, bool))
            and isinstance(imag, (int, float, bool))
        ):
            return ModelResult(value=SymbolicValue.from_const(complex(real, imag)))
        if (
            real is None
            or isinstance(real, (bytes, bytearray, list, tuple, dict, set))
            or (
                has_imag
                and (
                    imag is None
                    or isinstance(imag, (str, bytes, bytearray, list, tuple, dict, set))
                    or isinstance(real, str)
                )
            )
        ):
            result, constraint = SymbolicValue.symbolic(f"complex_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.complex", "complex() arguments must be numeric or one string"
                ),
            )
        result, constraint = SymbolicValue.symbolic(f"complex_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


@dataclass(frozen=True, slots=True)
class SliceIndicesCallable:
    """Callable adapter for ``slice(None, stop).indices(length)``."""

    stop: SymbolicValue

    def __call__(self, length: object) -> object:
        _ = length
        result, _constraint = SymbolicValue.symbolic("slice_indices_result")
        return result

    def for_nonnegative_length(self, length: int | z3.ArithRef) -> tuple[StackValue, ...]:
        length_expr = get_int_val(length) if isinstance(length, int) else length
        shifted_stop = self.stop.z3_int + length_expr
        normalized_stop = z3.If(
            self.stop.z3_int < 0,
            z3.If(shifted_stop < 0, Z3_ZERO, shifted_stop),
            z3.If(self.stop.z3_int > length_expr, length_expr, self.stop.z3_int),
        )
        stop_value = SymbolicValue.from_z3(normalized_stop, name="slice_indices_stop")
        stop_value.model_name = "slice.indices.stop"
        return (0, stop_value, 1)


@dataclass(frozen=True, slots=True)
class PositiveStopSlice:
    """Carrier for the supported default-start, default-step slice shape."""

    indices: SliceIndicesCallable

    def __call__(self, *args: object, **kwargs: object) -> object:
        _ = (args, kwargs)
        result, _constraint = SymbolicValue.symbolic("slice_result")
        return result


class SliceModel(FunctionModel):
    """Model for slice()."""

    name = "slice"
    qualname = "builtins.slice"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {1, 2, 3} or kwargs:
            result, constraint = SymbolicValue.symbolic(f"slice_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.slice",
                    f"slice() received invalid positional argument count: {len(args)}",
                ),
            )
        stop = args[1] if len(args) == 2 else None
        if (
            len(args) == 2
            and not kwargs
            and isinstance(args[0], (type(None), SymbolicNone))
            and isinstance(stop, SymbolicValue)
            and stop.affinity_type == "int"
        ):
            return ModelResult(value=PositiveStopSlice(SliceIndicesCallable(stop)))
        if all(arg is None or isinstance(arg, int) for arg in args):
            return ModelResult(value=SymbolicValue.from_const(slice(*args)))
        result, constraint = SymbolicValue.symbolic(f"slice_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])
