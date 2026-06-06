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

"""pathlib status query models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.models.builtins import FunctionModel, ModelResult
from pysymex.models.typed_results import model_bool_result

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


class PathExistsModel(FunctionModel):
    """Model for Path.exists()."""

    name = "exists"
    qualname = "pathlib.Path.exists"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the Path.exists()."""
        return model_bool_result(f"path_exists_{state.pc}", side_effects={"io": True})


class PathIsFileModel(FunctionModel):
    """Model for Path.is_file()."""

    name = "is_file"
    qualname = "pathlib.Path.is_file"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the Path.is_file()."""
        return model_bool_result(f"path_is_file_{state.pc}", side_effects={"io": True})


class PathIsDirModel(FunctionModel):
    """Model for Path.is_dir()."""

    name = "is_dir"
    qualname = "pathlib.Path.is_dir"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the Path.is_dir()."""
        return model_bool_result(f"path_is_dir_{state.pc}", side_effects={"io": True})


__all__ = ["PathExistsModel", "PathIsFileModel", "PathIsDirModel"]
