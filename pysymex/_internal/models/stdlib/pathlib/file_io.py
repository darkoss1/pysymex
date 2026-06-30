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

"""pathlib read/write models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class PathReadTextModel(FunctionModel):
    """Model for Path.read_text()."""

    name = "read_text"
    qualname = "pathlib.Path.read_text"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
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
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
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
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply the Path.write_text()."""
        result, constraints = ModelResult.symbolic_int(f"bytes_written_{state.pc}")
        constraints.append(result.z3_int >= 0)
        return ModelResult(
            value=result,
            constraints=constraints,
            side_effects={"io": True, "writes_file": True},
        )


class PathWriteBytesModel(FunctionModel):
    """Model for Path.write_bytes()."""

    name = "write_bytes"
    qualname = "pathlib.Path.write_bytes"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply the Path.write_bytes()."""
        result, constraints = ModelResult.symbolic_int(f"bytes_written_{state.pc}")
        constraints.append(result.z3_int >= 0)
        return ModelResult(
            value=result,
            constraints=constraints,
            side_effects={"io": True, "writes_file": True},
        )
