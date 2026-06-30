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

"""Models for the pickle standard-library module."""

from __future__ import annotations

import pickle
from typing import TYPE_CHECKING

from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelDegradation, ModelResult, SideEffects
from pysymex._internal.models.stdlib.coercion import const_bytes

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class PickleLoadsModel(FunctionModel):
    """Model for pickle.loads()."""

    name = "loads"
    qualname = "pickle.loads"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        data = const_bytes(args[0]) if args else None
        if data is not None:
            try:
                return ModelResult(value=SymbolicValue.from_const(pickle.loads(data)))
            except Exception:  # noqa: BLE001 - mirrors unsafe/untrusted pickle behavior conservatively.
                pass
        value, constraint = SymbolicValue.symbolic(f"pickle_loads_{state.pc}")
        return ModelResult(
            value=value,
            constraints=[constraint],
            side_effects={"deserialization": True},
        )


class PickleDumpsModel(FunctionModel):
    """Model for pickle.dumps()."""

    name = "dumps"
    qualname = "pickle.dumps"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del kwargs
        if args:
            try:
                return ModelResult(value=SymbolicBytes.concrete(pickle.dumps(args[0])))
            except Exception:  # noqa: BLE001 - arbitrary Python objects can fail to pickle.
                pass
        return ModelResult(value=SymbolicBytes.symbolic(f"pickle_dumps_{state.pc}"))


class PickleLoadModel(FunctionModel):
    """Model stream deserialization without invoking a host file object."""

    name = "load"
    qualname = "pickle.load"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        value, constraint = SymbolicValue.symbolic(f"pickle_load_{state.pc}")
        if len(args) != 1:
            return ModelResult(
                value=value,
                constraints=[constraint],
                side_effects=SideEffects.type_error(self.qualname, "load() requires a file"),
            )
        return ModelResult(
            value=value,
            constraints=[constraint],
            side_effects={"deserialization": True, "io": True},
            degradations=[
                ModelDegradation(
                    kind="unknown",
                    label="pickle.load",
                    owner=type(self).__name__,
                    reason="stream bytes and deserialization code execution are external",
                ),
            ],
        )


class PickleDumpModel(FunctionModel):
    """Model serialization to an external stream."""

    name = "dump"
    qualname = "pickle.dump"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        del state
        if len(args) < 2:
            return ModelResult.none(
                SideEffects.type_error(self.qualname, "dump() requires obj and file"),
            )
        return ModelResult.none({"io": True})


pickle_models: list[FunctionModel] = [
    PickleLoadsModel(),
    PickleDumpsModel(),
    PickleLoadModel(),
    PickleDumpModel(),
]
