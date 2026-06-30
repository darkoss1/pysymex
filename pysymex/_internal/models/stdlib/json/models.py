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

"""Symbolic models for json."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelDegradation, ModelResult
from pysymex._internal.models.stdlib.literals import (
    binding_error,
    concrete_call,
    raised_exception,
    stack_value,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class JsonLoadsModel(FunctionModel):
    """Model for json.loads()."""

    name = "loads"
    qualname = "json.loads"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        invalid = binding_error(json.loads, args, kwargs, self.qualname)
        if invalid is not None:
            return invalid
        concrete = concrete_call(args, kwargs)
        if concrete is not None:
            try:
                loader = cast("Callable[..., object]", json.loads)
                return ModelResult(value=stack_value(loader(*concrete[0], **concrete[1])))
            except (json.JSONDecodeError, TypeError, UnicodeDecodeError) as exc:
                return raised_exception(self.qualname, exc)

        result, constraint = SymbolicValue.symbolic(f"json_loads_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            degradations=[
                _json_degradation(self.qualname, "decoded shape depends on symbolic JSON"),
            ],
        )


class JsonDumpsModel(FunctionModel):
    """Model for json.dumps()."""

    name = "dumps"
    qualname = "json.dumps"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        invalid = binding_error(json.dumps, args, kwargs, self.qualname)
        if invalid is not None:
            return invalid
        concrete = concrete_call(args, kwargs)
        if concrete is not None:
            try:
                dumper = cast("Callable[..., str]", json.dumps)
                return ModelResult(
                    value=SymbolicString.from_const(dumper(*concrete[0], **concrete[1])),
                )
            except (TypeError, ValueError) as exc:
                return raised_exception(self.qualname, exc)
        result, constraint = SymbolicString.symbolic(f"json_dumps_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            degradations=[
                _json_degradation(self.qualname, "encoded text depends on symbolic values"),
            ],
        )


class JsonLoadModel(FunctionModel):
    """Model for json.load()."""

    name = "load"
    qualname = "json.load"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        invalid = binding_error(json.load, args, kwargs, self.qualname)
        if invalid is not None:
            return invalid
        result, constraint = SymbolicValue.symbolic(f"json_load_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            side_effects={"io": True},
            degradations=[_json_degradation(self.qualname, "stream contents are external")],
        )


class JsonDumpModel(FunctionModel):
    """Model for json.dump()."""

    name = "dump"
    qualname = "json.dump"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        invalid = binding_error(json.dump, args, kwargs, self.qualname)
        if invalid is not None:
            return invalid
        return ModelResult(
            value=ModelResult.none().value,
            side_effects={"io": True},
            degradations=[_json_degradation(self.qualname, "stream writes are external")],
        )


json_models = [
    JsonLoadsModel(),
    JsonDumpsModel(),
    JsonLoadModel(),
    JsonDumpModel(),
]


def _json_degradation(qualname: str, reason: str) -> ModelDegradation:
    return ModelDegradation(
        kind="precision_loss",
        label=qualname,
        owner="JSON models",
        reason=reason,
    )
