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

"""Models for the importlib standard-library module."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult
from pysymex._internal.models.stdlib.coercion import const_string, symbolic_object

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class ImportModuleModel(FunctionModel):
    """Model for importlib.import_module()."""

    name = "import_module"
    qualname = "importlib.import_module"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        module_name = const_string(args[0]) if args else None
        if module_name is not None and module_name in {"math", "json", "re", "os", "sys"}:
            try:
                return ModelResult(
                    value=SymbolicValue.from_const(importlib.import_module(module_name)),
                )
            except (ImportError, TypeError):
                pass
        value, constraint = symbolic_object(f"import_module_{state.pc}", "module")
        return ModelResult(value=value, constraints=[constraint], side_effects={"import": True})


importlib_models: list[FunctionModel] = [ImportModuleModel()]
