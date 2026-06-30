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

"""Models for the glob standard-library module."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class GlobModel(FunctionModel):
    """Model for glob.glob()/iglob()."""

    aliases = ("glob.iglob",)
    name = "glob"
    qualname = "glob.glob"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del args, kwargs
        value, constraint = SymbolicList.symbolic(f"glob_{state.pc}", element_type="str")
        return ModelResult(value=value, constraints=[constraint], side_effects={"filesystem": True})


glob_models: list[FunctionModel] = [GlobModel()]
