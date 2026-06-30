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

"""Models for the secrets standard-library module."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult
from pysymex._internal.models.stdlib.coercion import const_int

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class SecretsRandbelowModel(FunctionModel):
    """Model for secrets.randbelow()."""

    name = "randbelow"
    qualname = "secrets.randbelow"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        upper = const_int(args[0]) if args else None
        value, constraint = SymbolicValue.symbolic_int(f"randbelow_{state.pc}")
        constraints: list[z3.BoolRef] = [constraint, value.z3_int >= 0]
        if upper is not None and upper > 0:
            constraints.append(value.z3_int < upper)
            value.max_val = upper - 1
        value.min_val = 0
        return ModelResult(value=value, constraints=constraints)


class SecretsChoiceModel(FunctionModel):
    """Model for secrets.choice()."""

    name = "choice"
    qualname = "secrets.choice"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        if args and isinstance(args[0], Sequence) and args[0]:
            # Exact choice is intentionally not selected; every item is possible.
            value, constraint = SymbolicValue.symbolic(f"secrets_choice_{state.pc}")
            return ModelResult(value=value, constraints=[constraint])
        value, constraint = SymbolicValue.symbolic(f"secrets_choice_{state.pc}")
        return ModelResult(value=value, constraints=[constraint])


class SecretsTokenBytesModel(FunctionModel):
    """Model for secrets.token_bytes()."""

    name = "token_bytes"
    qualname = "secrets.token_bytes"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        value = SymbolicBytes.symbolic(f"token_bytes_{state.pc}")
        n = const_int(args[0]) if args else None
        if n is not None and n >= 0:
            value.z3_len = z3.IntVal(n)
        return ModelResult(value=value)


class SecretsTokenStringModel(FunctionModel):
    """Model for token_hex()/token_urlsafe()."""

    aliases = ("secrets.token_urlsafe",)
    name = "token_hex"
    qualname = "secrets.token_hex"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        value, constraint = SymbolicString.symbolic(f"token_{state.pc}")
        n = const_int(args[0]) if args else None
        constraints = [constraint]
        if n is not None and n >= 0:
            constraints.append(value.z3_len >= n)
        return ModelResult(value=value, constraints=constraints)


secrets_models: list[FunctionModel] = [
    SecretsRandbelowModel(),
    SecretsChoiceModel(),
    SecretsTokenBytesModel(),
    SecretsTokenStringModel(),
]
