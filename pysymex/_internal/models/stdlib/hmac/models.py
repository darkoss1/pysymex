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

"""Models for the hmac standard-library module."""

from __future__ import annotations

import hmac
from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.strings import SymbolicString
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


class HmacNewModel(FunctionModel):
    """Model for hmac.new()."""

    name = "new"
    qualname = "hmac.new"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del args, kwargs
        value, constraint = symbolic_object(f"hmac_{state.pc}", "hmac.HMAC")
        return ModelResult(value=value, constraints=[constraint])


class HmacUpdateModel(FunctionModel):
    name = "hmac_HMAC_update"
    qualname = "hmac.HMAC.update"

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


class HmacCompareDigestModel(FunctionModel):
    """Preserve exact constant-time comparison results for concrete values."""

    name = "compare_digest"
    qualname = "hmac.compare_digest"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if kwargs or len(args) != 2:
            value, constraint = SymbolicValue.symbolic_bool(f"compare_digest_{state.pc}")
            return ModelResult(
                value=value,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    self.qualname,
                    "compare_digest() takes two arguments",
                ),
            )
        left = const_bytes(args[0]) or const_string(args[0])
        right = const_bytes(args[1]) or const_string(args[1])
        if isinstance(left, bytes) and isinstance(right, bytes):
            return ModelResult(value=hmac.compare_digest(left, right))
        if isinstance(left, str) and isinstance(right, str):
            return ModelResult(value=hmac.compare_digest(left, right))
        if isinstance(args[0], SymbolicString) or isinstance(args[1], SymbolicString):
            value, constraint = SymbolicValue.symbolic_bool(f"compare_digest_{state.pc}")
            return ModelResult(value=value, constraints=[constraint])
        value, constraint = SymbolicValue.symbolic_bool(f"compare_digest_{state.pc}")
        return ModelResult(value=value, constraints=[constraint])


hmac_models: list[FunctionModel] = [
    HmacNewModel(),
    DigestMethodModel("hmac.HMAC", "digest", 32),
    DigestMethodModel("hmac.HMAC", "hexdigest", 32),
    HmacUpdateModel(),
    HashCopyModel("hmac.HMAC"),
    HmacCompareDigestModel(),
]
