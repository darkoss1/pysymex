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

"""Import-time namespace model for :mod:`sys`."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.models.modules import ModuleModel, new_module_object

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.types.containers.objects import SymbolicObject
    from pysymex._internal.typing.protocols import StackValue


class SysModuleModel(ModuleModel):
    """Materialize process inputs owned by the symbolic ``sys`` module."""

    name = "sys"

    def materialize(self, state: VMState) -> tuple[SymbolicObject, VMState]:
        module = new_module_object(self.name)
        implementation = new_module_object("sys.implementation")
        state = state.store_heap(
            implementation.address,
            {
                "name": sys.implementation.name,
                "cache_tag": sys.implementation.cache_tag,
                "version": tuple(sys.implementation.version),
                "hexversion": sys.implementation.hexversion,
            },
        )
        data: dict[str, StackValue] = {
            "__module_name__": self.name,
            "argv": SymbolicList(
                "sys.argv",
                z3.Array("sys.argv_arr", z3.IntSort(), z3.IntSort()),
                z3.Int("sys.argv_len"),
                "str",
            ),
            "path": SymbolicList(
                "sys.path",
                z3.Array("sys.path_arr", z3.IntSort(), z3.IntSort()),
                z3.Int("sys.path_len"),
                "str",
            ),
            "modules": SymbolicDict(
                "sys.modules",
                z3.Array("sys.modules_arr", z3.StringSort(), z3.IntSort()),
                z3.Array("sys.modules_keys", z3.StringSort(), z3.BoolSort()),
                z3.Int("sys.modules_len"),
            ),
            "path_importer_cache": SymbolicDict(
                "sys.path_importer_cache",
                z3.Array("sys.path_importer_cache_arr", z3.StringSort(), z3.IntSort()),
                z3.Array("sys.path_importer_cache_keys", z3.StringSort(), z3.BoolSort()),
                z3.Int("sys.path_importer_cache_len"),
            ),
            "platform": sys.platform,
            "byteorder": sys.byteorder,
            "maxsize": sys.maxsize,
            "version": sys.version,
            "version_info": tuple(sys.version_info),
            "hexversion": sys.hexversion,
            "api_version": sys.api_version,
            "prefix": sys.prefix,
            "base_prefix": sys.base_prefix,
            "exec_prefix": sys.exec_prefix,
            "base_exec_prefix": sys.base_exec_prefix,
            "executable": sys.executable,
            "dont_write_bytecode": sys.dont_write_bytecode,
            "implementation": implementation,
        }
        return module, state.store_heap(module.address, data)
