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

"""Models for the fnmatch standard-library module."""

from __future__ import annotations

import fnmatch
from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult
from pysymex._internal.models.stdlib.coercion import const_string

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class FnmatchModel(FunctionModel):
    """Model for fnmatch.fnmatch()/fnmatchcase()."""

    aliases = ("fnmatch.fnmatchcase",)
    name = "fnmatch"
    qualname = "fnmatch.fnmatch"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        if len(args) >= 2:
            name = const_string(args[0])
            pattern = const_string(args[1])
            if name is not None and pattern is not None:
                return ModelResult(value=SymbolicValue.from_const(fnmatch.fnmatch(name, pattern)))
        value, constraint = SymbolicValue.symbolic_bool(f"fnmatch_{state.pc}")
        return ModelResult(value=value, constraints=[constraint])


fnmatch_models: list[FunctionModel] = [FnmatchModel()]
