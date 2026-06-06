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

import z3

from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins import FunctionModel, ModelResult
from pysymex.models.builtins.base import none_model_result

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


class JsonLoadsModel(FunctionModel):
    """Model for json.loads()."""

    name = "loads"
    qualname = "json.loads"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if len(args) == 1 and not kwargs:
            parsed = _parse_literal_json(args[0])
            if parsed is not None:
                return ModelResult(value=parsed)

        result, constraint = SymbolicValue.symbolic(f"json_loads_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class JsonDumpsModel(FunctionModel):
    """Model for json.dumps()."""

    name = "dumps"
    qualname = "json.dumps"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"json_dumps_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 2])


class JsonLoadModel(FunctionModel):
    """Model for json.load()."""

    name = "load"
    qualname = "json.load"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"json_load_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            side_effects={"io": True},
        )


class JsonDumpModel(FunctionModel):
    """Model for json.dump()."""

    name = "dump"
    qualname = "json.dump"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        return none_model_result({"io": True})


json_models = [
    JsonLoadsModel(),
    JsonDumpsModel(),
    JsonLoadModel(),
    JsonDumpModel(),
]


__all__ = ["JsonDumpModel", "JsonDumpsModel", "JsonLoadModel", "JsonLoadsModel", "json_models"]


def _parse_literal_json(source: StackValue) -> StackValue | None:
    literal = _literal_json_source(source)
    if literal is None:
        return None
    try:
        parsed = cast("object", json.loads(literal))
    except json.JSONDecodeError:
        return None
    return _json_value_to_stack_value(parsed)


def _literal_json_source(source: StackValue) -> str | None:
    if isinstance(source, str):
        return source
    if isinstance(source, SymbolicString) and z3.is_string_value(source.z3_str):
        return source.z3_str.as_string()
    if isinstance(source, SymbolicValue) and isinstance(source.value, str):
        return source.value
    return None


def _json_value_to_stack_value(value: object) -> StackValue:
    if value is None:
        return SymbolicNone()
    if isinstance(value, dict):
        items = cast("dict[object, object]", value)
        return SymbolicDict.from_const(
            {str(key): _json_value_to_stack_value(item) for key, item in items.items()}
        )
    if isinstance(value, list):
        items = cast("list[object]", value)
        return SymbolicList.from_const([_json_value_to_stack_value(item) for item in items])
    if isinstance(value, str):
        return SymbolicString.from_const(value)
    return SymbolicValue.from_const(value)
