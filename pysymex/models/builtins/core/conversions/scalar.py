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

"""Scalar conversion builtin models."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.core.constants import Z3_ONE, Z3_ZERO
from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.typed_results import (
    symbolic_int_result,
)

from ...base import FunctionModel, ModelResult
from ..helpers import type_error_side_effect, value_error_side_effect
from .boolean import BoolModel as BoolModel

logger = get_logger(__name__)


def _arity_type_error(name: str, state: VMState) -> ModelResult:
    result, constraint = SymbolicValue.symbolic(f"{name}_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects=type_error_side_effect(
            f"builtins.{name}", f"{name}() received too many arguments"
        ),
    )


def _literal_text(value: StackValue | None) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, SymbolicString) and z3.is_string_value(value.z3_str):
        return value.z3_str.as_string()
    return None


def _literal_integer(value: StackValue | None) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, SymbolicValue) and isinstance(value.value, int):
        return value.value
    return None


def _definite_invalid_base(value: StackValue | None, *, provided: bool) -> bool:
    if not provided:
        return False
    if value is None or isinstance(value, (float, str, bytes, bytearray, list, tuple, dict, set)):
        return True
    return isinstance(value, SymbolicValue) and isinstance(
        value.value, (float, str, bytes, bytearray, list, tuple, dict, set)
    )


class IntModel(FunctionModel):
    """Model for int()."""

    name = "int"
    qualname = "builtins.int"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply int() model."""
        if (
            len(args) > 2
            or set(kwargs) - {"base"}
            or (len(args) > 1 and "base" in kwargs)
            or (not args and "base" in kwargs)
        ):
            return _arity_type_error("int", state)
        if not args:
            return ModelResult(value=0)
        x = args[0]
        has_base = len(args) > 1 or "base" in kwargs
        base = args[1] if len(args) > 1 else kwargs.get("base")
        literal_base = _literal_integer(base)
        if isinstance(x, SymbolicString):
            if z3.is_string_value(x.z3_str):
                literal = x.z3_str.as_string()
                if _definite_invalid_base(base, provided=has_base):
                    result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects=type_error_side_effect(
                            "builtins.int", "int() base must be an integer"
                        ),
                    )
                try:
                    if literal_base is not None:
                        return ModelResult(value=int(literal, literal_base))
                    if not has_base:
                        return ModelResult(value=int(literal))
                except ValueError as exc:
                    result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects=value_error_side_effect("int", str(exc)),
                    )
                result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")
                return ModelResult(value=result, constraints=[constraint])
            if base is not None and (not isinstance(base, int) or base != 10):
                result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")
                return ModelResult(value=result, constraints=[constraint])
            result, constraints = symbolic_int_result(f"int_{x.name}")
            converted = z3.StrToInt(x.z3_str)
            constraints.append(result.z3_int == converted)
            return ModelResult(
                value=result,
                constraints=constraints,
                side_effects={
                    "potential_exception": {
                        "type": "ValueError",
                        "message": "invalid literal for int() with base 10",
                        "condition": converted == -1,
                    }
                },
            )
        if isinstance(x, SymbolicValue):
            if isinstance(x.value, str):
                if _definite_invalid_base(base, provided=has_base):
                    result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects=type_error_side_effect(
                            "builtins.int", "int() base must be an integer"
                        ),
                    )
                try:
                    if literal_base is not None:
                        return ModelResult(value=int(x.value, literal_base))
                    if not has_base:
                        return ModelResult(value=int(x.value))
                except ValueError as exc:
                    result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects=value_error_side_effect("int", str(exc)),
                    )
                result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")
                return ModelResult(value=result, constraints=[constraint])
            if base is not None:
                result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")
                return ModelResult(value=result, constraints=[constraint])
            result, constraints = symbolic_int_result(f"int_{x.name}")
            constraints.append(result.z3_int == x.z3_int)
            return ModelResult(
                value=result,
                constraints=constraints,
            )
        if isinstance(x, (int, bool, float, str, bytes)):
            try:
                if literal_base is not None and isinstance(x, (str, bytes)):
                    return ModelResult(value=int(x, literal_base))
                if (
                    has_base
                    and isinstance(x, (str, bytes))
                    and not _definite_invalid_base(base, provided=True)
                ):
                    result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")
                    return ModelResult(value=result, constraints=[constraint])
                if has_base:
                    result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects=type_error_side_effect(
                            "builtins.int", "int() cannot convert non-string with explicit base"
                        ),
                    )
                return ModelResult(value=int(x))
            except ValueError as exc:
                result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=value_error_side_effect("int", str(exc)),
                )
            except TypeError as exc:
                logger.debug(
                    "int() concrete conversion failed; using symbolic value", exc_info=True
                )
                result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=type_error_side_effect("int", str(exc)),
                )
        if x is None or isinstance(x, (list, tuple, dict, set)):
            result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.int", "int() requires a string, bytes-like object, or real number"
                ),
            )
        result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class StrModel(FunctionModel):
    """Model for str()."""

    name = "str"
    qualname = "builtins.str"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply str() model."""
        parameters = ("object", "encoding", "errors")
        if (
            len(args) > len(parameters)
            or set(kwargs) - set(parameters)
            or any(name in kwargs for name in parameters[: len(args)])
        ):
            return _arity_type_error("str", state)
        if not args and "object" not in kwargs:
            return ModelResult(value="")
        x = args[0] if args else kwargs["object"]
        encoding = args[1] if len(args) > 1 else kwargs.get("encoding")
        errors = args[2] if len(args) > 2 else kwargs.get("errors")
        has_codec = len(args) > 1 or "encoding" in kwargs or len(args) > 2 or "errors" in kwargs
        if has_codec:
            if isinstance(x, (bytes, bytearray)):
                if encoding is not None and not isinstance(encoding, (str, SymbolicString)):
                    result, constraint = SymbolicString.symbolic(f"str_{state.pc}")
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects=type_error_side_effect(
                            "builtins.str", "str() encoding must be a string"
                        ),
                    )
                if errors is not None and not isinstance(errors, (str, SymbolicString)):
                    result, constraint = SymbolicString.symbolic(f"str_{state.pc}")
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects=type_error_side_effect(
                            "builtins.str", "str() errors must be a string"
                        ),
                    )
                literal_encoding = _literal_text(encoding)
                literal_errors = _literal_text(errors)
                if (
                    isinstance(encoding, SymbolicString)
                    and literal_encoding is None
                    or isinstance(errors, SymbolicString)
                    and literal_errors is None
                ):
                    result, constraint = SymbolicString.symbolic(f"str_{state.pc}")
                    return ModelResult(value=result, constraints=[constraint])
                return ModelResult(
                    value=str(x, literal_encoding or "utf-8", literal_errors or "strict")
                )
            if not isinstance(x, SymbolicValue):
                result, constraint = SymbolicString.symbolic(f"str_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=type_error_side_effect(
                        "builtins.str", "decoding to str requires a bytes-like object"
                    ),
                )
            result, constraint = SymbolicString.symbolic(f"str_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        if isinstance(x, SymbolicValue):
            z3_expr = z3.If(
                x.is_int,
                x.z3_int,
                z3.If(x.is_bool, z3.If(x.z3_bool, Z3_ONE, Z3_ZERO), Z3_ZERO),
            )
            z3_str_expr = z3.If(
                z3_expr < 0, z3.Concat("-", z3.IntToStr(-z3_expr)), z3.IntToStr(z3_expr)
            )

            result, constraint = SymbolicString.symbolic(f"str_{x.name}")
            return ModelResult(
                value=result,
                constraints=[
                    constraint,
                    result.z3_str == z3_str_expr,
                ],
            )
        try:
            return ModelResult(value=str(x))
        except (TypeError, RecursionError):
            result, constraint = SymbolicString.symbolic(f"str_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
