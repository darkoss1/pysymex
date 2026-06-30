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

"""Async, identity, hash, callable, and representation builtin models."""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeGuard

import z3

from pysymex._internal.models.contracts.results import SideEffects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelDegradation, ModelResult


def _arity_type_error(name: str, args: list[StackValue], state: VMState) -> ModelResult:
    result, constraint = SymbolicValue.symbolic(f"{name}_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects=SideEffects.type_error(
            f"builtins.{name}",
            f"{name}() received invalid positional argument count: {len(args)}",
        ),
    )


def _definite_non_async_protocol(value: StackValue) -> bool:
    return value is None or isinstance(
        value,
        (int, float, bool, str, bytes, list, tuple, dict, set, SymbolicString),
    )


def _is_exact_hash_container(
    value: object,
) -> TypeGuard[tuple[object, ...] | frozenset[object]]:
    """Narrow exact builtin tuple and frozenset values without subclasses."""
    return type(value) in (tuple, frozenset)


def _safe_builtin_hash_value(value: object) -> bool:
    """Return whether hashing *value* cannot invoke a user-defined protocol."""
    if value is None or type(value) in (bool, int, float, str, bytes):
        return True
    if _is_exact_hash_container(value):
        return all(_safe_builtin_hash_value(item) for item in value)
    return False


def _definitely_unhashable_builtin(value: object) -> bool:
    """Return whether a builtin container tree definitely cannot be hashed."""
    if type(value) in (list, dict, set, bytearray):
        return True
    if _is_exact_hash_container(value):
        return any(_definitely_unhashable_builtin(item) for item in value)
    return False


class AiterModel(FunctionModel):
    """Model for aiter() - async iterator."""

    name = "aiter"
    qualname = "builtins.aiter"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _arity_type_error("aiter", args, state)
        if _definite_non_async_protocol(args[0]):
            result, constraint = SymbolicValue.symbolic(f"aiter_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.aiter",
                    "aiter() argument is not an async iterable",
                ),
            )
        result, constraint = SymbolicValue.symbolic(f"aiter_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            degradations=(
                ModelDegradation(
                    kind="unsupported",
                    label="builtin_aiter_protocol_unsupported",
                    owner="pysymex._internal.models.builtins.reflection.identity.AiterModel",
                    reason="custom __aiter__ protocol behavior is not executed",
                ),
            ),
        )


class AnextModel(FunctionModel):
    """Model for anext() - async next."""

    name = "anext"
    qualname = "builtins.anext"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {1, 2} or kwargs:
            return _arity_type_error("anext", args, state)
        if _definite_non_async_protocol(args[0]):
            result, constraint = SymbolicValue.symbolic(f"anext_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.anext",
                    "anext() argument is not an async iterator",
                ),
            )
        result, constraint = SymbolicValue.symbolic(f"anext_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            degradations=(
                ModelDegradation(
                    kind="unsupported",
                    label="builtin_anext_protocol_unsupported",
                    owner="pysymex._internal.models.builtins.reflection.identity.AnextModel",
                    reason=(
                        "custom __anext__, awaitable, default, and StopAsyncIteration behavior "
                        "is not executed"
                    ),
                ),
            ),
        )


class IdModel(FunctionModel):
    """Model for id() preserving symbolic object identity relations."""

    name = "id"
    qualname = "builtins.id"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _arity_type_error("id", args, state)
        obj = args[0]
        if not isinstance(obj, SymbolicValue):
            return ModelResult(value=SymbolicValue.from_const(id(obj)))
        result, constraints = ModelResult.symbolic_int(f"id_{state.pc}")
        constraints.extend((result.z3_int == obj.z3_addr, result.z3_int >= 0))
        return ModelResult(
            value=result,
            constraints=constraints,
        )


class HashModel(FunctionModel):
    """Model for hash()."""

    name = "hash"
    qualname = "builtins.hash"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _arity_type_error("hash", args, state)
        obj: StackValue = args[0]
        if _safe_builtin_hash_value(obj):
            return ModelResult(value=SymbolicValue.from_const(hash(obj)))
        if _definitely_unhashable_builtin(obj):
            result, constraint = SymbolicValue.symbolic_int(f"hash_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.hash",
                    "hash() argument is unhashable",
                ),
            )
        result, constraint = SymbolicValue.symbolic_int(f"hash_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            degradations=(
                ModelDegradation(
                    kind="unsupported",
                    label="builtin_hash_protocol_unsupported",
                    owner="pysymex._internal.models.builtins.reflection.identity.HashModel",
                    reason="custom __hash__ protocol behavior is not executed",
                ),
            ),
        )


class CallableModel(FunctionModel):
    """Model for callable()."""

    name = "callable"
    qualname = "builtins.callable"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _arity_type_error("callable", args, state)
        obj: StackValue = args[0]
        if not isinstance(obj, SymbolicValue):
            return ModelResult(value=SymbolicValue.from_const(callable(obj)))
        result, constraint = SymbolicValue.symbolic_bool(f"callable_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class ReprModel(FunctionModel):
    """Model for repr()."""

    name = "repr"
    qualname = "builtins.repr"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return _arity_type_error("repr", args, state)
        obj: StackValue = args[0]
        if isinstance(obj, SymbolicString):
            if z3.is_string_value(obj.z3_str):
                return ModelResult(value=SymbolicString.from_const(repr(obj.z3_str.as_string())))
            result, constraint = SymbolicString.symbolic(f"repr_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        if not isinstance(obj, SymbolicValue):
            return ModelResult(value=SymbolicString.from_const(repr(obj)))
        result, constraint = SymbolicString.symbolic(f"repr_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class FormatModel(FunctionModel):
    """Model for format()."""

    name = "format"
    qualname = "builtins.format"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {1, 2} or kwargs:
            return _arity_type_error("format", args, state)
        obj: StackValue = args[0]
        spec: StackValue = args[1] if len(args) > 1 else ""
        if spec is None or isinstance(
            spec,
            (int, float, bool, bytes, bytearray, list, tuple, dict, set, frozenset),
        ):
            result, constraint = SymbolicString.symbolic(f"format_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.format",
                    "format() argument 2 must be a string",
                ),
            )
        if isinstance(obj, SymbolicString):
            if isinstance(spec, str) and z3.is_string_value(obj.z3_str):
                try:
                    return ModelResult(
                        value=SymbolicString.from_const(format(obj.z3_str.as_string(), spec)),
                    )
                except ValueError as exc:
                    result, constraint = SymbolicString.symbolic(f"format_{state.pc}")
                    return ModelResult(
                        value=result,
                        constraints=[constraint],
                        side_effects=SideEffects.value_error("builtins.format", str(exc)),
                    )
            result, constraint = SymbolicString.symbolic(f"format_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        if not isinstance(obj, SymbolicValue) and isinstance(spec, str):
            try:
                return ModelResult(value=SymbolicString.from_const(format(obj, spec)))
            except ValueError as exc:
                result, constraint = SymbolicString.symbolic(f"format_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=SideEffects.value_error("builtins.format", str(exc)),
                )
            except TypeError as exc:
                result, constraint = SymbolicString.symbolic(f"format_{state.pc}")
                return ModelResult(
                    value=result,
                    constraints=[constraint],
                    side_effects=SideEffects.type_error("builtins.format", str(exc)),
                )
        result, constraint = SymbolicString.symbolic(f"format_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])
