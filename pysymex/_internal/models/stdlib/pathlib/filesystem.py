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

"""pathlib filesystem operation models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class PathResolveModel(FunctionModel):
    """Model for Path.resolve()."""

    name = "resolve"
    qualname = "pathlib.Path.resolve"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply the Path.resolve()."""
        result, constraint = SymbolicString.symbolic(f"path_resolved_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint, result.z3_len >= 1],
            side_effects={"io": True},
        )


class PathMkdirModel(FunctionModel):
    """Model for Path.mkdir()."""

    name = "mkdir"
    qualname = "pathlib.Path.mkdir"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply the Path.mkdir()."""
        return ModelResult(
            value=SymbolicNoneType("none"),
            side_effects={"io": True, "creates_dir": True},
        )


class PathUnlinkModel(FunctionModel):
    """Model for Path.unlink()."""

    name = "unlink"
    qualname = "pathlib.Path.unlink"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply the Path.unlink()."""
        return ModelResult(
            value=SymbolicNoneType("none"),
            side_effects={"io": True, "deletes_file": True},
        )


class PathGlobModel(FunctionModel):
    """Model for Path.glob()."""

    name = "glob"
    qualname = "pathlib.Path.glob"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply the Path.glob()."""
        from pysymex._internal.core.types.containers.lists import SymbolicList

        result, constraint = SymbolicList.symbolic(f"glob_results_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint, result.z3_len >= 0],
            side_effects={"io": True},
        )


class PathRglobModel(FunctionModel):
    """Model for Path.rglob() (recursive glob)."""

    name = "rglob"
    qualname = "pathlib.Path.rglob"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply the Path.rglob() (recursive glob)."""
        from pysymex._internal.core.types.containers.lists import SymbolicList

        result, constraint = SymbolicList.symbolic(f"rglob_results_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint, result.z3_len >= 0],
            side_effects={"io": True},
        )
