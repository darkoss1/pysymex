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

"""Symbolic models for os.path."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class OsPathExistsModel(FunctionModel):
    """Model for os.path.exists()."""

    name = "exists"
    qualname = "os.path.exists"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic_bool(f"exists_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OsPathIsfileModel(FunctionModel):
    """Model for os.path.isfile()."""

    name = "isfile"
    qualname = "os.path.isfile"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic_bool(f"isfile_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OsPathIsdirModel(FunctionModel):
    """Model for os.path.isdir()."""

    name = "isdir"
    qualname = "os.path.isdir"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic_bool(f"isdir_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OsPathJoinModel(FunctionModel):
    """Model for os.path.join()."""

    name = "join"
    qualname = "os.path.join"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if all(isinstance(a, str) for a in args):
            import os.path

            return ModelResult(
                value=SymbolicString.from_const(os.path.join(*cast("list[str]", args))),
            )
        result, constraint = SymbolicString.symbolic(f"pathjoin_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OsPathDirnameModel(FunctionModel):
    """Model for os.path.dirname()."""

    name = "dirname"
    qualname = "os.path.dirname"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if args and isinstance(args[0], str):
            import os.path

            return ModelResult(value=SymbolicString.from_const(os.path.dirname(args[0])))
        result, constraint = SymbolicString.symbolic(f"dirname_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OsPathBasenameModel(FunctionModel):
    """Model for os.path.basename()."""

    name = "basename"
    qualname = "os.path.basename"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if args and isinstance(args[0], str):
            import os.path

            return ModelResult(value=SymbolicString.from_const(os.path.basename(args[0])))
        result, constraint = SymbolicString.symbolic(f"basename_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class OsPathSplitModel(FunctionModel):
    """Model for os.path.split()."""

    name = "split"
    qualname = "os.path.split"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if args and isinstance(args[0], str):
            import os.path

            head, tail = os.path.split(args[0])
            return ModelResult(
                value=(
                    SymbolicString.from_const(head),
                    SymbolicString.from_const(tail),
                ),
            )
        head, c1 = SymbolicString.symbolic(f"split_head_{state.pc}")
        tail, c2 = SymbolicString.symbolic(f"split_tail_{state.pc}")
        return ModelResult(value=(head, tail), constraints=[c1, c2])


class OsPathAbspathModel(FunctionModel):
    """Model for os.path.abspath()."""

    name = "abspath"
    qualname = "os.path.abspath"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"abspath_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 1])


ospath_models = [
    OsPathExistsModel(),
    OsPathIsfileModel(),
    OsPathIsdirModel(),
    OsPathJoinModel(),
    OsPathDirnameModel(),
    OsPathBasenameModel(),
    OsPathSplitModel(),
    OsPathAbspathModel(),
]
