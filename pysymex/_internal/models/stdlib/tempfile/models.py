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

"""Semantic models for temporary-file creation APIs."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelDegradation, ModelResult
from pysymex._internal.models.stdlib.coercion import symbolic_int_range, symbolic_object
from pysymex._internal.models.stdlib.shutil.models import ReturnPathModel

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class TempDirectoryBytesModel(FunctionModel):
    name = "gettempdirb"
    qualname = "tempfile.gettempdirb"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del args, kwargs
        return ModelResult(value=SymbolicBytes.symbolic(f"tempdir_{state.pc}"))


class MakeTempFileModel(FunctionModel):
    name = "mkstemp"
    qualname = "tempfile.mkstemp"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del args, kwargs
        descriptor = symbolic_int_range(f"temp_fd_{state.pc}", 0, None)
        path = ReturnPathModel("tempfile.mkstemp_path").apply([], {}, state)
        return ModelResult(
            value=(descriptor.value, path.value),
            constraints=[*descriptor.constraints, *path.constraints],
            side_effects={"filesystem": True},
        )


class TemporaryResourceModel(FunctionModel):
    """Create a typed temporary resource while keeping host I/O external."""

    aliases: tuple[str, ...] = ()

    def __init__(self, name: str, type_name: str, effect: Literal["io", "filesystem"]) -> None:
        self.name = name
        self.qualname = f"tempfile.{name}"
        self._type_name = type_name
        self._effect = effect

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del args, kwargs
        value, constraint = symbolic_object(f"{self.name}_{state.pc}", self._type_name)
        return ModelResult(
            value=value,
            constraints=[constraint],
            side_effects={self._effect: True},
            degradations=[
                ModelDegradation(
                    kind="precision_loss",
                    label=self.qualname,
                    owner=type(self).__name__,
                    reason="temporary resource lifecycle is external to symbolic state",
                ),
            ],
        )


tempfile_models: list[FunctionModel] = [
    ReturnPathModel("tempfile.gettempdir"),
    TempDirectoryBytesModel(),
    ReturnPathModel("tempfile.mkdtemp"),
    MakeTempFileModel(),
    TemporaryResourceModel("NamedTemporaryFile", "tempfile.NamedTemporaryFile", "filesystem"),
    TemporaryResourceModel("TemporaryDirectory", "tempfile.TemporaryDirectory", "filesystem"),
    TemporaryResourceModel("SpooledTemporaryFile", "tempfile.SpooledTemporaryFile", "io"),
]
