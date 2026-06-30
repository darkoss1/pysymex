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

"""Models for the pprint standard-library module."""

from __future__ import annotations

import pprint
from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class PPrintPformatModel(FunctionModel):
    """Model for pprint.pformat()."""

    name = "pformat"
    qualname = "pprint.pformat"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        if args:
            try:
                return ModelResult(value=SymbolicString.from_const(pprint.pformat(args[0])))
            except (RecursionError, TypeError, ValueError):
                pass
        result, constraint = SymbolicString.symbolic(f"pprint_pformat_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


pprint_models: list[FunctionModel] = [PPrintPformatModel()]
