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

"""Assembly of standard-library module namespace models."""

from __future__ import annotations

import contextlib
import functools
import logging
from typing import TYPE_CHECKING

from pysymex._internal.models.modules import ModuleModel, new_module_object
from pysymex._internal.models.stdlib.os.module import OsModuleModel
from pysymex._internal.models.stdlib.sys.module import SysModuleModel

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.types.containers.objects import SymbolicObject
    from pysymex._internal.typing.protocols import StackValue


class StaticModuleModel(ModuleModel):
    """Module model backed by an immutable attribute map."""

    def __init__(self, name: str, attributes: dict[str, StackValue]) -> None:
        self.name = name
        self._attributes = attributes

    def materialize(self, state: VMState) -> tuple[SymbolicObject, VMState]:
        module = new_module_object(self.name)
        data: dict[str, StackValue] = {"__module_name__": self.name, **self._attributes}
        return module, state.store_heap(module.address, data)


def stdlib_module_models() -> tuple[ModuleModel, ...]:
    """Return all stdlib modules with specialized import-time state."""
    return (
        SysModuleModel(),
        OsModuleModel(),
        StaticModuleModel("contextlib", {"suppress": contextlib.suppress}),
        StaticModuleModel("typing", {"TYPE_CHECKING": False}),
        StaticModuleModel(
            "functools",
            {
                "lru_cache": functools.lru_cache,
                "partial": functools.partial,
                "reduce": functools.reduce,
                "wraps": functools.wraps,
            },
        ),
        StaticModuleModel(
            "logging",
            {
                "CRITICAL": logging.CRITICAL,
                "FATAL": logging.FATAL,
                "ERROR": logging.ERROR,
                "WARNING": logging.WARNING,
                "WARN": logging.WARNING,
                "INFO": logging.INFO,
                "DEBUG": logging.DEBUG,
                "NOTSET": logging.NOTSET,
            },
        ),
    )
