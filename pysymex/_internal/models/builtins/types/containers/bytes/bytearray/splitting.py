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

"""Bytearray split and join models built on the bytes SSoT."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.models.builtins.types.containers.bytes.shared import (
    bytearray_elements_result,
    bytearray_result,
)
from pysymex._internal.models.contracts.results import ModelResult
from pysymex._internal.models.builtins.types.containers.bytes.splitting import (
    BytesJoinModel,
    BytesPartitionModel,
    BytesRpartitionModel,
    BytesRsplitModel,
    BytesSplitlinesModel,
    BytesSplitModel,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class BytearrayJoinModel(BytesJoinModel):
    """Model for bytearray.join()."""

    qualname = "bytearray.join"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return bytearray_result(super().apply(args, kwargs, state))


class BytearraySplitModel(BytesSplitModel):
    """Model for bytearray.split()."""

    qualname = "bytearray.split"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return bytearray_elements_result(super().apply(args, kwargs, state))


class BytearrayRsplitModel(BytesRsplitModel):
    """Model for bytearray.rsplit()."""

    qualname = "bytearray.rsplit"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return bytearray_elements_result(super().apply(args, kwargs, state))


class BytearrayPartitionModel(BytesPartitionModel):
    """Model for bytearray.partition()."""

    qualname = "bytearray.partition"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return bytearray_elements_result(super().apply(args, kwargs, state))


class BytearrayRPartitionModel(BytesRpartitionModel):
    """Model for bytearray.rpartition()."""

    qualname = "bytearray.rpartition"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return bytearray_elements_result(super().apply(args, kwargs, state))


class BytearrayLinesModel(BytesSplitlinesModel):
    """Model for bytearray.splitlines()."""

    qualname = "bytearray.splitlines"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return bytearray_elements_result(super().apply(args, kwargs, state))
