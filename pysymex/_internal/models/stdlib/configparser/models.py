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

"""State-correlated models for :mod:`configparser`."""

from __future__ import annotations

import configparser
from typing import TYPE_CHECKING, Literal, cast

from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelDegradation, ModelResult
from pysymex._internal.models.stdlib.coercion import symbolic_object

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

MethodName = Literal[
    "read",
    "sections",
    "items",
    "get",
    "getint",
    "getfloat",
    "getboolean",
    "has_section",
    "has_option",
    "options",
    "set",
    "add_section",
    "read_dict",
]


def _exception_result(source: str, exc: Exception) -> ModelResult:
    return ModelResult.none(
        {
            "raised_exception": {
                "issue_kind": type(exc).__name__,
                "exception_type": type(exc).__name__,
                "message": str(exc),
                "source": source,
            },
        },
    )


def _parser_receiver(
    args: list[StackValue],
) -> tuple[configparser.ConfigParser | None, list[StackValue]]:
    if args and isinstance(args[0], SymbolicValue):
        payload = getattr(args[0], "_modeled_object", None)
        if isinstance(payload, configparser.ConfigParser):
            return payload, args[1:]
    return None, args


class ConfigParserModel(FunctionModel):
    """Construct a parser payload whose subsequent calls share state."""

    name = "ConfigParser"
    qualname = "configparser.ConfigParser"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        try:
            constructor = cast(
                "Callable[..., configparser.ConfigParser]",
                configparser.ConfigParser,
            )
            parser = constructor(*args, **kwargs)
        except (TypeError, ValueError) as exc:
            return _exception_result(self.qualname, exc)
        value, constraint = symbolic_object(f"configparser_{state.pc}", "configparser.ConfigParser")
        value.attach_modeled_object(parser)
        return ModelResult(value=value, constraints=[constraint])


class ConfigParserMethodModel(FunctionModel):
    """Dispatch a parser method against its correlated concrete payload."""

    aliases: tuple[str, ...] = ()

    def __init__(self, method: MethodName) -> None:
        self.name = f"configparser_ConfigParser_{method}"
        self.qualname = f"configparser.ConfigParser.{method}"
        self._method = method

    def _unknown(self, state: VMState) -> ModelResult:
        degradation = ModelDegradation(
            kind="unknown",
            label=self.qualname,
            owner=type(self).__name__,
            reason="parser receiver or arguments are symbolic and cannot be correlated",
        )
        if self._method in {"set", "add_section", "read_dict"}:
            return ModelResult(value=ModelResult.none().value, degradations=[degradation])
        if self._method in {"sections", "items", "options", "read"}:
            value, constraint = SymbolicList.symbolic(f"configparser_{self._method}_{state.pc}")
            return ModelResult(value=value, constraints=[constraint], degradations=[degradation])
        if self._method in {"has_section", "has_option", "getboolean"}:
            value, constraint = SymbolicValue.symbolic_bool(
                f"configparser_{self._method}_{state.pc}",
            )
            return ModelResult(value=value, constraints=[constraint], degradations=[degradation])
        if self._method == "getint":
            value, constraint = SymbolicValue.symbolic_int(f"configparser_getint_{state.pc}")
            return ModelResult(value=value, constraints=[constraint], degradations=[degradation])
        if self._method == "getfloat":
            value, constraint = SymbolicValue.symbolic_float(f"configparser_getfloat_{state.pc}")
            return ModelResult(value=value, constraints=[constraint], degradations=[degradation])
        value, constraint = SymbolicString.symbolic(f"configparser_get_{state.pc}")
        return ModelResult(value=value, constraints=[constraint], degradations=[degradation])

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        parser, call_args = _parser_receiver(args)
        if parser is None:
            return self._unknown(state)
        if self._method == "read":
            value, constraint = SymbolicList.symbolic(f"configparser_read_{state.pc}")
            return ModelResult(
                value=value,
                constraints=[constraint],
                side_effects={"io": True},
                degradations=[
                    ModelDegradation(
                        kind="unknown",
                        label=self.qualname,
                        owner=type(self).__name__,
                        reason="configuration files are not read from the host",
                    ),
                ],
            )
        try:
            method = getattr(parser, self._method)
            result = method(*call_args, **kwargs)
        except (configparser.Error, KeyError, TypeError, ValueError) as exc:
            return _exception_result(self.qualname, exc)
        if result is None:
            return ModelResult.none({"mutates_arg": 0})
        if isinstance(result, list):
            return ModelResult(value=SymbolicList.from_const(cast("list[StackValue]", result)))
        if isinstance(result, (str, int, float, bool)):
            return ModelResult(value=result)
        return self._unknown(state)


configparser_models: list[FunctionModel] = [
    ConfigParserModel(),
    *(
        ConfigParserMethodModel(method)
        for method in cast(
            "tuple[MethodName, ...]",
            (
                "read",
                "sections",
                "items",
                "get",
                "getint",
                "getfloat",
                "getboolean",
                "has_section",
                "has_option",
                "options",
                "set",
                "add_section",
                "read_dict",
            ),
        )
    ),
]
