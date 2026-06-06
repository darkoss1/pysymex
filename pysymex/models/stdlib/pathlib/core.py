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

"""Path construction and manipulation models."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins import FunctionModel, ModelResult
from pysymex.models.typed_results import model_bool_result

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


PATH_STRING_PREFIXES = ("path_", "purepath_", "pureposixpath_")
PATH_STRING_STRING_PROPERTIES = frozenset({"name", "parent", "stem", "suffix"})
PATH_STRING_SEQUENCE_PROPERTIES = frozenset({"suffixes"})
PATH_STRING_ATTRIBUTE_NAMES = PATH_STRING_STRING_PROPERTIES | PATH_STRING_SEQUENCE_PROPERTIES


def _path_string_from_arg(arg: StackValue, name: str) -> SymbolicString | None:
    if isinstance(arg, str):
        concrete = SymbolicString.from_const(arg)
        return SymbolicString(_z3_str=concrete.z3_str, _z3_len=concrete.z3_len, _name=name)
    if isinstance(arg, SymbolicString):
        return SymbolicString(_z3_str=arg.z3_str, _z3_len=arg.z3_len, _name=name)
    if isinstance(arg, SymbolicValue) and arg.affinity_type == "str":
        return SymbolicString(
            _z3_str=arg.z3_str,
            _z3_len=z3.Length(arg.z3_str),
            _name=name,
            _unified=arg,
        )
    return None


class PathModel(FunctionModel):
    """Model for pathlib.Path() constructor."""

    name = "Path"
    qualname = "pathlib.Path"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the pathlib.Path() constructor."""
        if args:
            result = _path_string_from_arg(args[0], f"path_{state.pc}")
            if result is not None:
                return ModelResult(value=result)
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
        if args:
            result = _path_string_from_arg(args[0], f"purepath_{state.pc}")
            if result is not None:
                return ModelResult(value=result)
        result, constraint = SymbolicString.symbolic(f"purepath_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class PurePosixPathModel(PurePathModel):
    """Model for pathlib.PurePosixPath() constructor."""

    name = "PurePosixPath"
    qualname = "pathlib.PurePosixPath"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the pathlib.PurePosixPath() constructor."""
        if args:
            result = _path_string_from_arg(args[0], f"pureposixpath_{state.pc}")
            if result is not None:
                return ModelResult(value=result)
        result, constraint = SymbolicString.symbolic(f"pureposixpath_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class PathIsAbsoluteModel(FunctionModel):
    """Model for Path.is_absolute()."""

    name = "is_absolute"
    qualname = "pathlib.Path.is_absolute"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the Path.is_absolute()."""
        return model_bool_result(f"path_is_absolute_{state.pc}")


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


__all__ = [
    "PathIsAbsoluteModel",
    "PathJoinpathModel",
    "PathModel",
    "PathNameModel",
    "PathParentModel",
    "PathStemModel",
    "PathSuffixModel",
    "PathTruedivModel",
    "PurePosixPathModel",
    "PurePathModel",
]
