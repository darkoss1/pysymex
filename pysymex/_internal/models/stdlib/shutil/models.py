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

"""Models for the shutil standard-library module."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult, SideEffects
from pysymex._internal.models.stdlib.coercion import symbolic_int_range

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class ReturnPathModel(FunctionModel):
    """Model for path-returning filesystem helpers."""

    aliases: tuple[str, ...]

    def __init__(self, qualname: str, *, aliases: tuple[str, ...] = ()) -> None:
        self.qualname = qualname
        self.name = qualname.rsplit(".", 1)[-1]
        self.aliases = aliases

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        if self.name in {"copy", "copy2", "copyfile", "move"} and len(args) >= 2:
            dst = args[1]
            if isinstance(dst, (str, SymbolicString)):
                return ModelResult(value=dst, side_effects={"filesystem": True})
        value, constraint = SymbolicString.symbolic(f"{self.name}_{state.pc}")
        return ModelResult(value=value, constraints=[constraint], side_effects={"filesystem": True})


class ShutilDiskUsageModel(FunctionModel):
    """Model for shutil.disk_usage()."""

    name = "disk_usage"
    qualname = "shutil.disk_usage"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del args, kwargs
        total = symbolic_int_range(f"disk_total_{state.pc}", 0, None)
        used = symbolic_int_range(f"disk_used_{state.pc}", 0, None)
        free = symbolic_int_range(f"disk_free_{state.pc}", 0, None)
        return ModelResult(
            value=(total.value, used.value, free.value),
            constraints=[*total.constraints, *used.constraints, *free.constraints],
            side_effects={"filesystem": True},
        )


class ShutilRmtreeModel(FunctionModel):
    """Model recursive deletion as an explicit filesystem mutation."""

    name = "rmtree"
    qualname = "shutil.rmtree"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del state
        if not args and "path" not in kwargs:
            return ModelResult.none(SideEffects.type_error(self.qualname, "rmtree() missing path"))
        return ModelResult.none({"filesystem": True})


class ShutilCopytreeModel(ReturnPathModel):
    """Return the destination path written by ``copytree``."""

    def __init__(self) -> None:
        super().__init__("shutil.copytree")

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        destination = args[1] if len(args) > 1 else kwargs.get("dst")
        if isinstance(destination, (str, SymbolicString)):
            return ModelResult(value=destination, side_effects={"filesystem": True})
        return super().apply(args, kwargs, state)


shutil_models: list[FunctionModel] = [
    ReturnPathModel("shutil.copy", aliases=("shutil.copy2", "shutil.copyfile", "shutil.move")),
    ShutilRmtreeModel(),
    ShutilCopytreeModel(),
    ShutilDiskUsageModel(),
]
