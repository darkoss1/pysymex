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

"""Import-time namespace model for :mod:`os`."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.modules import ModuleModel, new_module_object

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.types.containers.objects import SymbolicObject
    from pysymex._internal.typing.protocols import StackValue


class OsModuleModel(ModuleModel):
    """Materialize environment and path namespaces owned by ``os``."""

    name = "os"

    def materialize(self, state: VMState) -> tuple[SymbolicObject, VMState]:
        module = new_module_object(self.name)
        path_module = new_module_object("os.path")
        state = state.store_heap(path_module.address, {"__module_name__": "os.path"})
        getcwd = SymbolicValue.from_const(os.getcwd)
        getcwd.model_name = "os.getcwd"
        data: dict[str, StackValue] = {
            "__module_name__": self.name,
            "environ": SymbolicDict(
                "os.environ",
                z3.Array("os.environ_arr", z3.StringSort(), z3.IntSort()),
                z3.Array("os.environ_keys", z3.StringSort(), z3.BoolSort()),
                z3.Int("os.environ_len"),
            ),
            "getcwd": getcwd,
            "path": path_module,
        }
        return module, state.store_heap(module.address, data)
