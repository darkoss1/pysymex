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

"""Models for the base64 standard-library module."""

from __future__ import annotations

import base64
import binascii
from typing import TYPE_CHECKING

from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult
from pysymex._internal.models.stdlib.coercion import const_bytes

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class Base64TransformModel(FunctionModel):
    """Model for common base64 byte transforms."""

    aliases: tuple[str, ...]

    def __init__(
        self,
        qualname: str,
        transform: Callable[[bytes], bytes],
        *,
        aliases: tuple[str, ...] = (),
    ) -> None:
        self.qualname = qualname
        self.name = qualname.rsplit(".", 1)[-1]
        self.aliases = aliases
        self._transform = transform

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        if args:
            data = const_bytes(args[0])
            if data is not None:
                try:
                    return ModelResult(value=SymbolicBytes.concrete(self._transform(data)))
                except binascii.Error:
                    pass
        value = SymbolicBytes.symbolic(f"{self.name}_{state.pc}")
        return ModelResult(value=value)


base64_models: list[FunctionModel] = [
    Base64TransformModel(
        "base64.b64encode",
        base64.b64encode,
        aliases=("base64.urlsafe_b64encode",),
    ),
    Base64TransformModel(
        "base64.b64decode",
        base64.b64decode,
        aliases=("base64.urlsafe_b64decode",),
    ),
    Base64TransformModel("base64.b32encode", base64.b32encode),
    Base64TransformModel("base64.b32decode", base64.b32decode),
    Base64TransformModel("base64.b16encode", base64.b16encode),
    Base64TransformModel("base64.b16decode", base64.b16decode),
]
