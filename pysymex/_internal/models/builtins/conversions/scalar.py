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

from pysymex._internal.core.constants import Z3_ONE, Z3_ZERO
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.logging.root import get_logger
from pysymex._internal.models.contracts.results import SideEffects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

logger = get_logger(__name__)
_MAX_PATH_FORCED_INT_STRING_LENGTH = 32


def _arity_type_error(name: str, state: VMState) -> ModelResult:
    result, constraint = SymbolicValue.symbolic(f"{name}_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects=SideEffects.type_error(
            f"builtins.{name}",
            f"{name}() received too many arguments",
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
    if value is None or isinstance(
        value,
        (float, str, bytes, bytearray, list, tuple, dict, set, frozenset),
    ):
        return True
    return isinstance(value, SymbolicValue) and isinstance(
        value.value,
        (float, str, bytes, bytearray, list, tuple, dict, set, frozenset),
    )


def _int_from_literal_result(
    literal: str,
    base: StackValue | None,
    *,
    has_base: bool,
    literal_base: int | None,
    state: VMState,
) -> ModelResult:
    if _definite_invalid_base(base, provided=has_base):
        result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            side_effects=SideEffects.type_error(
                "builtins.int",
                "int() base must be an integer",
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
            side_effects=SideEffects.value_error("int", str(exc)),
        )
    result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")
    return ModelResult(value=result, constraints=[constraint])


def _path_forced_string_literal(value: SymbolicString, state: VMState) -> str | None:
    expression = value.z3_str
    direct = _string_expr_literal(expression)
    if direct is not None:
        return direct

    constraints = state.path_constraints.to_list()
    direct = _forced_string_expr_literal(expression, constraints)
    if direct is not None:
        return direct

    length = _forced_int_literal(value.z3_len, constraints)
    if length is None:
        length = _forced_int_literal(z3.Length(expression), constraints)
    if length is None or length < 0 or length > _MAX_PATH_FORCED_INT_STRING_LENGTH:
        return None

    characters: list[str] = []
    for index in range(length):
        char_expr = z3.SubString(expression, index, 1)
        char = _forced_string_expr_literal(char_expr, constraints)
        if char is None or len(char) != 1:
            return None
        characters.append(char)
    return "".join(characters)


def _forced_string_expr_literal(
    expression: z3.SeqRef,
    constraints: list[z3.BoolRef],
) -> str | None:
    for constraint in constraints:
        pair = _equality_operands(constraint)
        if pair is None:
            continue
        left, right = pair
        if isinstance(left, z3.SeqRef) and _same_z3_expr(left, expression):
            literal = _string_expr_literal(right)
            if literal is not None:
                return literal
        if isinstance(right, z3.SeqRef) and _same_z3_expr(right, expression):
            literal = _string_expr_literal(left)
            if literal is not None:
                return literal
    return None


def _forced_int_literal(
    expression: z3.ArithRef,
    constraints: list[z3.BoolRef],
) -> int | None:
    direct = _int_expr_literal(expression)
    if direct is not None:
        return direct

    aliases: list[z3.ArithRef] = [simplify_expr(expression)]
    for _ in range(4):
        changed = False
        for constraint in constraints:
            pair = _equality_operands(constraint)
            if pair is None:
                continue
            left, right = pair
            if _matches_any(left, aliases):
                literal = _int_expr_literal(right)
                if literal is not None:
                    return literal
                changed = _append_int_alias(aliases, right) or changed
            if _matches_any(right, aliases):
                literal = _int_expr_literal(left)
                if literal is not None:
                    return literal
                changed = _append_int_alias(aliases, left) or changed
        if not changed:
            break
    return None


def _equality_operands(constraint: z3.BoolRef) -> tuple[z3.ExprRef, z3.ExprRef] | None:
    try:
        simplified = simplify_expr(constraint)
        if not z3.is_eq(simplified):
            return None
        left, right = simplified.children()
    except (ValueError, z3.Z3Exception):
        return None
    return left, right


def _matches_any(candidate: z3.ExprRef, aliases: list[z3.ArithRef]) -> bool:
    return any(_same_z3_expr(candidate, alias) for alias in aliases)


def _append_int_alias(aliases: list[z3.ArithRef], candidate: z3.ExprRef) -> bool:
    simplified = simplify_expr(candidate)
    if not isinstance(simplified, z3.ArithRef) or not z3.is_int(simplified):
        return False
    if _int_expr_literal(simplified) is not None or _matches_any(simplified, aliases):
        return False
    aliases.append(simplified)
    return True


def _same_z3_expr(left: z3.ExprRef, right: z3.ExprRef) -> bool:
    try:
        return z3.eq(simplify_expr(left), simplify_expr(right))
    except z3.Z3Exception:
        return False


def _string_expr_literal(value: z3.ExprRef) -> str | None:
    if not z3.is_string_value(value):
        return None
    try:
        return value.as_string()
    except z3.Z3Exception:
        return None


def _int_expr_literal(value: z3.ExprRef) -> int | None:
    simplified = simplify_expr(value)
    if not z3.is_int_value(simplified):
        return None
    try:
        return simplified.as_long()
    except z3.Z3Exception:
        return None


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
                return _int_from_literal_result(
                    literal,
                    base,
                    has_base=has_base,
                    literal_base=literal_base,
                    state=state,
                )
            forced_literal = _path_forced_string_literal(x, state)
            if forced_literal is not None:
                return _int_from_literal_result(
                    forced_literal,
                    base,
                    has_base=has_base,
                    literal_base=literal_base,
                    state=state,
                )
            if base is not None and (not isinstance(base, int) or base != 10):
                result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")
                return ModelResult(value=result, constraints=[constraint])
            result, constraints = ModelResult.symbolic_int(f"int_{x.name}")
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
                    },
                },
            )
        if isinstance(x, SymbolicValue):
            if isinstance(x.value, str):
                return _int_from_literal_result(
                    x.value,
                    base,
                    has_base=has_base,
                    literal_base=literal_base,
                    state=state,
                )
            if base is not None:
                result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")
                return ModelResult(value=result, constraints=[constraint])
            result, constraints = ModelResult.symbolic_int(f"int_{x.name}")
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
                        side_effects=SideEffects.type_error(
                            "builtins.int",
                            "int() cannot convert non-string with explicit base",
                        ),
                    )
                return ModelResult(value=int(x))
            except ValueError as exc:
                result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=SideEffects.value_error("int", str(exc)),
                )
            except TypeError as exc:
                logger.debug(
                    "int() concrete conversion failed; using symbolic value",
                    exc_info=True,
                )
                result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=SideEffects.type_error("int", str(exc)),
                )
        if x is None or isinstance(x, (list, tuple, dict, set, frozenset)):
            result, constraint = SymbolicValue.symbolic(f"int_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.int",
                    "int() requires a string, bytes-like object, or real number",
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
                        side_effects=SideEffects.type_error(
                            "builtins.str",
                            "str() encoding must be a string",
                        ),
                    )
                if errors is not None and not isinstance(errors, (str, SymbolicString)):
                    result, constraint = SymbolicString.symbolic(f"str_{state.pc}")
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects=SideEffects.type_error(
                            "builtins.str",
                            "str() errors must be a string",
                        ),
                    )
                literal_encoding = _literal_text(encoding)
                literal_errors = _literal_text(errors)
                if (isinstance(encoding, SymbolicString) and literal_encoding is None) or (
                    isinstance(errors, SymbolicString) and literal_errors is None
                ):
                    result, constraint = SymbolicString.symbolic(f"str_{state.pc}")
                    return ModelResult(value=result, constraints=[constraint])
                return ModelResult(
                    value=str(x, literal_encoding or "utf-8", literal_errors or "strict"),
                )
            if not isinstance(x, SymbolicValue):
                result, constraint = SymbolicString.symbolic(f"str_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=SideEffects.type_error(
                        "builtins.str",
                        "decoding to str requires a bytes-like object",
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
                z3_expr < 0,
                z3.Concat("-", z3.IntToStr(-z3_expr)),
                z3.IntToStr(z3_expr),
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
