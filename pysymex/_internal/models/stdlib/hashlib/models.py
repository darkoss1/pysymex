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

"""Models for the hashlib standard-library module."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult, SideEffects
from pysymex._internal.models.stdlib.coercion import (
    const_bytes,
    const_string,
    symbolic_object,
)
from pysymex._internal.models.stdlib.hash import (
    DigestMethodModel,
    HashCopyModel,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class HashlibConstructorModel(FunctionModel):
    """Model for hashlib constructors returning opaque hash objects."""

    aliases: tuple[str, ...]

    def __init__(self, algorithm: str, digest_size: int) -> None:
        self.name = algorithm
        self.qualname = f"hashlib.{algorithm}"
        self.aliases = (f"hashlib.{algorithm.lower()}",)
        self._algorithm = algorithm
        self._digest_size = digest_size

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        data = const_bytes(args[0]) if args else b""
        if data is not None and not kwargs:
            try:
                concrete = getattr(hashlib, self._algorithm)(data)
                value, constraint = symbolic_object(
                    f"hashlib_{self._algorithm}_{state.pc}",
                    f"hashlib.{self._algorithm}",
                )
                value.digest_size = concrete.digest_size
                return ModelResult(value=value, constraints=[constraint])
            except (TypeError, ValueError):
                pass
        value, constraint = symbolic_object(
            f"hashlib_{self._algorithm}_{state.pc}",
            f"hashlib.{self._algorithm}",
        )
        value.digest_size = self._digest_size
        return ModelResult(value=value, constraints=[constraint])


class HashlibNewModel(FunctionModel):
    """Model for hashlib.new()."""

    name = "new"
    qualname = "hashlib.new"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        algorithm = const_string(args[0]) if args else None
        data = const_bytes(args[1]) if len(args) > 1 else b""
        if algorithm is not None and data is not None:
            try:
                return ModelResult(value=SymbolicValue.from_const(hashlib.new(algorithm, data)))
            except (TypeError, ValueError):
                pass
        value, constraint = symbolic_object(f"hashlib_new_{state.pc}", "hashlib.HASH")
        return ModelResult(value=value, constraints=[constraint])


class HashUpdateModel(FunctionModel):
    """Validate hash updates and record receiver mutation explicitly."""

    aliases: tuple[str, ...] = ()

    def __init__(self, owner: str) -> None:
        self.name = f"{owner.replace('.', '_')}_update"
        self.qualname = f"{owner}.update"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del state
        data_index = 1 if len(args) == 2 else 0
        if kwargs or len(args) not in {1, 2} or const_bytes(args[data_index]) is None:
            return ModelResult.none(
                SideEffects.type_error(self.qualname, "update() requires a bytes-like object"),
            )
        return ModelResult.none({"mutates_arg": 0})


_HASH_METHOD_MODELS: list[FunctionModel] = [
    method_model
    for algorithm, digest_size in (
        ("hashlib.md5", 16),
        ("hashlib.sha1", 20),
        ("hashlib.sha224", 28),
        ("hashlib.sha256", 32),
        ("hashlib.sha384", 48),
        ("hashlib.sha512", 64),
        ("hashlib.blake2b", 64),
        ("hashlib.blake2s", 32),
    )
    for method_model in (
        DigestMethodModel(algorithm, "digest", digest_size),
        DigestMethodModel(algorithm, "hexdigest", digest_size),
        HashUpdateModel(algorithm),
        HashCopyModel(algorithm),
    )
]

hashlib_models: list[FunctionModel] = [
    HashlibNewModel(),
    HashlibConstructorModel("md5", 16),
    HashlibConstructorModel("sha1", 20),
    HashlibConstructorModel("sha224", 28),
    HashlibConstructorModel("sha256", 32),
    HashlibConstructorModel("sha384", 48),
    HashlibConstructorModel("sha512", 64),
    HashlibConstructorModel("blake2b", 64),
    HashlibConstructorModel("blake2s", 32),
    *_HASH_METHOD_MODELS,
]
