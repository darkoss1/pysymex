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

"""Models for the tomllib standard-library module."""

from __future__ import annotations

import tomllib
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.containers.dicts import SymbolicDict
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


class TomllibLoadsModel(FunctionModel):
    """Model ``tomllib.loads`` with exact concrete parsing."""

    name = "loads"
    qualname = "tomllib.loads"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        invalid = binding_error(tomllib.loads, args, kwargs, self.qualname)
        if invalid is not None:
            return invalid
        concrete = concrete_call(args, kwargs)
        if concrete is not None:
            try:
                loads = cast("Callable[..., object]", tomllib.loads)
                return ModelResult(value=stack_value(loads(*concrete[0], **concrete[1])))
            except (tomllib.TOMLDecodeError, TypeError) as exc:
                return raised_exception(self.qualname, exc)
        value, constraint = SymbolicDict.symbolic(f"toml_{state.pc}")
        return ModelResult(
            value=value,
            constraints=[constraint],
            degradations=[
                _toml_degradation(self.qualname, "table contents depend on symbolic TOML"),
            ],
        )


class TomllibLoadModel(FunctionModel):
    """Model stream-based TOML loading without conflating it with ``loads``."""

    name = "load"
    qualname = "tomllib.load"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        invalid = binding_error(tomllib.load, args, kwargs, self.qualname)
        if invalid is not None:
            return invalid
        value, constraint = SymbolicDict.symbolic(f"toml_stream_{state.pc}")
        return ModelResult(
            value=value,
            constraints=[constraint],
            side_effects={"io": True},
            degradations=[_toml_degradation(self.qualname, "stream bytes are external")],
        )


def _toml_degradation(qualname: str, reason: str) -> ModelDegradation:
    return ModelDegradation(
        kind="precision_loss",
        label=qualname,
        owner="TOML models",
        reason=reason,
    )


tomllib_models: list[FunctionModel] = [TomllibLoadsModel(), TomllibLoadModel()]
