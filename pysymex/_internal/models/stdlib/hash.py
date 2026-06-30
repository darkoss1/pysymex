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

"""Standard library hash and digest model classes."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

import z3

from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult
from pysymex._internal.models.stdlib.coercion import symbolic_object

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class DigestMethodModel(FunctionModel):
    """Model digest/hexdigest methods for hash-like objects."""

    aliases: tuple[str, ...]

    def __init__(
        self,
        owner_type: str,
        method: Literal["digest", "hexdigest"],
        digest_size: int,
        *,
        aliases: tuple[str, ...] = (),
    ) -> None:
        self.name = f"{owner_type.replace('.', '_')}_{method}"
        self.qualname = f"{owner_type}.{method}"
        self.aliases = aliases
        self._method = method
        self._digest_size = digest_size

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del args, kwargs
        if self._method == "digest":
            value = SymbolicBytes.symbolic(f"{self.name}_{state.pc}")
            value.z3_len = z3.IntVal(self._digest_size)
            return ModelResult(value=value)
        value, constraint = SymbolicString.symbolic(f"{self.name}_{state.pc}")
        return ModelResult(
            value=value,
            constraints=[constraint, value.z3_len == self._digest_size * 2],
        )


class HashCopyModel(FunctionModel):
    """Model copy() for hash/HMAC objects by returning same-type opaque carrier."""

    aliases: tuple[str, ...]

    def __init__(self, owner_type: str) -> None:
        self.name = f"{owner_type.replace('.', '_')}_copy"
        self.qualname = f"{owner_type}.copy"
        self.aliases = ()

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del args, kwargs
        value, constraint = symbolic_object(f"{self.name}_{state.pc}", self.qualname[:-5])
        return ModelResult(value=value, constraints=[constraint])
