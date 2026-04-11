# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""
Pathlib Models for pysymex.

Provides symbolic models for pathlib.Path operations:
- Path construction and basic attributes
- Existence checks (exists, is_file, is_dir)
- Path manipulation (joinpath, parent, name, suffix, stem)
- File I/O (read_text, write_text) with side-effect tracking
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.core.types.scalars import (
    SymbolicNone,
    SymbolicString,
    SymbolicValue,
)
from pysymex.models.builtins import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState


class PathModel(FunctionModel):
    """Model for pathlib.Path() constructor."""

    name = "Path"
    qualname = "pathlib.Path"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the pathlib.Path() constructor."""
        if args and isinstance(args[0], str):
            result = SymbolicString.from_const(args[0])
            return ModelResult(value=result)
        if args and isinstance(args[0], SymbolicString):
            return ModelResult(value=args[0])
        result, constraint = SymbolicString.symbolic(f"path_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class PurePathModel(FunctionModel):
    """Model for pathlib.PurePath() constructor."""

    name = "PurePath"
    qualname = "pathlib.PurePath"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the pathlib.PurePath() constructor."""
        if args and isinstance(args[0], str):
            result = SymbolicString.from_const(args[0])
            return ModelResult(value=result)
        result, constraint = SymbolicString.symbolic(f"purepath_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class PathExistsModel(FunctionModel):
    """Model for Path.exists()."""

    name = "exists"
    qualname = "pathlib.Path.exists"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the Path.exists()."""
        result, constraint = SymbolicValue.symbolic(f"path_exists_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint, result.is_bool],
            side_effects={"io": True},
        )


class PathIsFileModel(FunctionModel):
    """Model for Path.is_file()."""

    name = "is_file"
    qualname = "pathlib.Path.is_file"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the Path.is_file()."""
        result, constraint = SymbolicValue.symbolic(f"path_is_file_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint, result.is_bool],
            side_effects={"io": True},
        )


class PathIsDirModel(FunctionModel):
    """Model for Path.is_dir()."""

    name = "is_dir"
    qualname = "pathlib.Path.is_dir"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the Path.is_dir()."""
        result, constraint = SymbolicValue.symbolic(f"path_is_dir_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint, result.is_bool],
            side_effects={"io": True},
        )


class PathIsAbsoluteModel(FunctionModel):
    """Model for Path.is_absolute()."""

    name = "is_absolute"
    qualname = "pathlib.Path.is_absolute"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the Path.is_absolute()."""
        result, constraint = SymbolicValue.symbolic(f"path_is_absolute_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class PathNameModel(FunctionModel):
    """Model for Path.name property (final component)."""

    name = "name"
    qualname = "pathlib.Path.name"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the Path.name property (final component)."""
        result, constraint = SymbolicString.symbolic(f"path_name_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class PathStemModel(FunctionModel):
    """Model for Path.stem property (name without suffix)."""

    name = "stem"
    qualname = "pathlib.Path.stem"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the Path.stem property (name without suffix)."""
        result, constraint = SymbolicString.symbolic(f"path_stem_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class PathSuffixModel(FunctionModel):
    """Model for Path.suffix property (file extension)."""

    name = "suffix"
    qualname = "pathlib.Path.suffix"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the Path.suffix property (file extension)."""
        result, constraint = SymbolicString.symbolic(f"path_suffix_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class PathParentModel(FunctionModel):
    """Model for Path.parent property."""

    name = "parent"
    qualname = "pathlib.Path.parent"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the Path.parent property."""
        result, constraint = SymbolicString.symbolic(f"path_parent_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class PathJoinpathModel(FunctionModel):
    """Model for Path.joinpath()."""

    name = "joinpath"
    qualname = "pathlib.Path.joinpath"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the Path.joinpath()."""
        result, constraint = SymbolicString.symbolic(f"path_joined_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 1])


class PathTruedivModel(FunctionModel):
    """Model for Path.__truediv__ (the / operator)."""

    name = "__truediv__"
    qualname = "pathlib.Path.__truediv__"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the Path.__truediv__ (the / operator)."""
        result, constraint = SymbolicString.symbolic(f"path_div_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 1])


class PathReadTextModel(FunctionModel):
    """Model for Path.read_text()."""

    name = "read_text"
    qualname = "pathlib.Path.read_text"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the Path.read_text()."""
        result, constraint = SymbolicString.symbolic(f"file_content_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint, result.z3_len >= 0],
            side_effects={"io": True},
        )


class PathReadBytesModel(FunctionModel):
    """Model for Path.read_bytes()."""

    name = "read_bytes"
    qualname = "pathlib.Path.read_bytes"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the Path.read_bytes()."""
        result, constraint = SymbolicValue.symbolic(f"file_bytes_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            side_effects={"io": True},
        )


class PathWriteTextModel(FunctionModel):
    """Model for Path.write_text()."""

    name = "write_text"
    qualname = "pathlib.Path.write_text"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the Path.write_text()."""
        result, constraint = SymbolicValue.symbolic(f"bytes_written_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint, result.is_int, result.z3_int >= 0],
            side_effects={"io": True, "writes_file": True},
        )


class PathWriteBytesModel(FunctionModel):
    """Model for Path.write_bytes()."""

    name = "write_bytes"
    qualname = "pathlib.Path.write_bytes"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the Path.write_bytes()."""
        result, constraint = SymbolicValue.symbolic(f"bytes_written_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint, result.is_int, result.z3_int >= 0],
            side_effects={"io": True, "writes_file": True},
        )


class PathResolveModel(FunctionModel):
    """Model for Path.resolve()."""

    name = "resolve"
    qualname = "pathlib.Path.resolve"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
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
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the Path.mkdir()."""
        return ModelResult(
            value=SymbolicNone("none"),
            side_effects={"io": True, "creates_dir": True},
        )


class PathUnlinkModel(FunctionModel):
    """Model for Path.unlink()."""

    name = "unlink"
    qualname = "pathlib.Path.unlink"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the Path.unlink()."""
        return ModelResult(
            value=SymbolicNone("none"),
            side_effects={"io": True, "deletes_file": True},
        )


class PathGlobModel(FunctionModel):
    """Model for Path.glob()."""

    name = "glob"
    qualname = "pathlib.Path.glob"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the Path.glob()."""
        from pysymex.core.types.scalars import SymbolicList

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
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the Path.rglob() (recursive glob)."""
        from pysymex.core.types.scalars import SymbolicList

        result, constraint = SymbolicList.symbolic(f"rglob_results_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint, result.z3_len >= 0],
            side_effects={"io": True},
        )


PATHLIB_MODELS = [
    PathModel(),
    PurePathModel(),
    PathExistsModel(),
    PathIsFileModel(),
    PathIsDirModel(),
    PathIsAbsoluteModel(),
    PathNameModel(),
    PathStemModel(),
    PathSuffixModel(),
    PathParentModel(),
    PathJoinpathModel(),
    PathTruedivModel(),
    PathReadTextModel(),
    PathReadBytesModel(),
    PathWriteTextModel(),
    PathWriteBytesModel(),
    PathResolveModel(),
    PathMkdirModel(),
    PathUnlinkModel(),
    PathGlobModel(),
    PathRglobModel(),
]
