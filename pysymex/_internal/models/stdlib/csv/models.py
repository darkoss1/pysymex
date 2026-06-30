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

"""Models for the csv standard-library module."""

from __future__ import annotations

import csv
from collections.abc import Sequence
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult, SideEffects
from pysymex._internal.models.stdlib.coercion import symbolic_int_range, symbolic_object

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class CsvReaderModel(FunctionModel):
    """Model for csv reader factories."""

    aliases = ("csv.DictReader",)
    name = "reader"
    qualname = "csv.reader"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if args and isinstance(args[0], Sequence) and not isinstance(args[0], (str, bytes)):
            rows: list[StackValue] = []
            try:
                if not kwargs:
                    for row in csv.reader(cast("Sequence[str]", args[0])):
                        rows.append(SymbolicList.from_const(row))
                    return ModelResult(value=SymbolicList.from_const(rows))
            except (csv.Error, TypeError, ValueError):
                pass
        value, constraint = SymbolicList.symbolic(f"csv_reader_{state.pc}")
        return ModelResult(value=value, constraints=[constraint])


class CsvWriterModel(FunctionModel):
    """Model for csv.writer()/DictWriter()."""

    aliases = ("csv.DictWriter",)
    name = "writer"
    qualname = "csv.writer"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del args, kwargs
        value, constraint = symbolic_object(f"csv_writer_{state.pc}", "csv.writer")
        return ModelResult(value=value, constraints=[constraint], side_effects={"io": True})


class CsvWriterowModel(FunctionModel):
    """Model one CSV row write and preserve the non-negative count contract."""

    name = "csv_writer_writerow"
    qualname = "csv.writer.writerow"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if kwargs or len(args) != 1:
            result = symbolic_int_range(f"csv_writerow_{state.pc}", 0, None)
            return ModelResult(
                value=result.value,
                constraints=result.constraints,
                side_effects=SideEffects.type_error(self.qualname, "writerow() takes one row"),
            )
        result = symbolic_int_range(f"csv_writerow_{state.pc}", 0, None)
        return ModelResult(
            value=result.value,
            constraints=result.constraints,
            side_effects={"io": True},
        )


class CsvWriterowsModel(FunctionModel):
    """Model writing an iterable of CSV rows."""

    name = "csv_writer_writerows"
    qualname = "csv.writer.writerows"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del state
        if kwargs or len(args) != 1:
            return ModelResult.none(
                SideEffects.type_error(self.qualname, "writerows() takes one iterable"),
            )
        return ModelResult.none({"io": True})


csv_models: list[FunctionModel] = [
    CsvReaderModel(),
    CsvWriterModel(),
    CsvWriterowModel(),
    CsvWriterowsModel(),
]
