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

"""Semantic models for :mod:`urllib.parse`."""

from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING, Literal, cast

import z3

from pysymex._internal.core.types.base import SymbolicType
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelDegradation, ModelResult

if TYPE_CHECKING:
    from collections.abc import Callable

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


_UNRESOLVED = object()


def _concretize(value: object) -> object:
    if isinstance(value, SymbolicString):
        if z3.is_string_value(value.z3_str):
            return value.z3_str.as_string()
        return _UNRESOLVED
    if isinstance(value, (SymbolicType, SymbolicValue)):
        return _UNRESOLVED
    if isinstance(value, (list, tuple)):
        sequence = cast("list[object] | tuple[object, ...]", value)
        converted = [_concretize(item) for item in sequence]
        if any(item is _UNRESOLVED for item in converted):
            return _UNRESOLVED
        return tuple(converted) if isinstance(value, tuple) else converted
    if isinstance(value, dict):
        mapping = cast("dict[object, object]", value)
        converted_mapping: dict[object, object] = {}
        for key, item in mapping.items():
            converted_key = _concretize(key)
            converted_item = _concretize(item)
            if converted_key is _UNRESOLVED or converted_item is _UNRESOLVED:
                return _UNRESOLVED
            converted_mapping[converted_key] = converted_item
        return converted_mapping
    return value


def _concrete_arguments(
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> tuple[list[object], dict[str, object]] | None:
    converted_args = _concretize(args)
    converted_kwargs = _concretize(kwargs)
    if converted_args is _UNRESOLVED or converted_kwargs is _UNRESOLVED:
        return None
    return cast("list[object]", converted_args), cast("dict[str, object]", converted_kwargs)


def _raised(source: str, exc: Exception) -> ModelResult:
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


def _degradation(qualname: str, reason: str) -> ModelDegradation:
    return ModelDegradation(
        kind="precision_loss",
        label=qualname,
        owner="urllib.parse models",
        reason=reason,
    )


class UrlParseModel(FunctionModel):
    """Model URL decomposition into CPython-compatible result tuples."""

    aliases: tuple[str, ...] = ()

    def __init__(self, operation: Literal["urlparse", "urlsplit"]) -> None:
        self.name = operation
        self.qualname = f"urllib.parse.{operation}"
        self._operation = operation

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        concrete = _concrete_arguments(args, kwargs)
        if args and concrete is not None:
            try:
                function = cast(
                    "Callable[..., tuple[StackValue, ...]]",
                    getattr(urllib.parse, self._operation),
                )
                return ModelResult(value=function(*concrete[0], **concrete[1]))
            except (AttributeError, TypeError, UnicodeError, ValueError) as exc:
                return _raised(self.qualname, exc)
        fields = 6 if self._operation == "urlparse" else 5
        values: list[StackValue] = []
        constraints: list[z3.BoolRef] = []
        for index in range(fields):
            value, constraint = SymbolicString.symbolic(
                f"urllib_{self._operation}_{index}_{state.pc}",
            )
            values.append(value)
            constraints.append(constraint)
        return ModelResult(
            value=tuple(values),
            constraints=constraints,
            degradations=[_degradation(self.qualname, "URL components depend on symbolic text")],
        )


class UrlAssembleModel(FunctionModel):
    """Model URL assembly and relative-reference joining."""

    aliases: tuple[str, ...] = ()

    def __init__(self, operation: Literal["urlunparse", "urlunsplit", "urljoin"]) -> None:
        self.name = operation
        self.qualname = f"urllib.parse.{operation}"
        self._operation = operation

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        concrete = _concrete_arguments(args, kwargs)
        if concrete is not None:
            try:
                function = cast(
                    "Callable[..., str | bytes]",
                    getattr(urllib.parse, self._operation),
                )
                return ModelResult(value=function(*concrete[0], **concrete[1]))
            except (TypeError, UnicodeError, ValueError) as exc:
                return _raised(self.qualname, exc)
        value, constraint = SymbolicString.symbolic(f"urllib_{self._operation}_{state.pc}")
        return ModelResult(
            value=value,
            constraints=[constraint],
            degradations=[
                _degradation(self.qualname, "assembled URL depends on symbolic components"),
            ],
        )


class UrlTextTransformModel(FunctionModel):
    """Model quoting and unquoting transforms with exact concrete semantics."""

    aliases: tuple[str, ...] = ()

    def __init__(
        self,
        operation: Literal["quote", "quote_plus", "unquote", "unquote_plus"],
    ) -> None:
        self.name = operation
        self.qualname = f"urllib.parse.{operation}"
        self._operation = operation

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        concrete = _concrete_arguments(args, kwargs)
        if concrete is not None:
            try:
                function = cast("Callable[..., str]", getattr(urllib.parse, self._operation))
                return ModelResult(value=function(*concrete[0], **concrete[1]))
            except (TypeError, UnicodeError, ValueError) as exc:
                return _raised(self.qualname, exc)
        value, constraint = SymbolicString.symbolic(f"urllib_{self._operation}_{state.pc}")
        return ModelResult(
            value=value,
            constraints=[constraint],
            degradations=[
                _degradation(self.qualname, "escaping transform depends on symbolic text"),
            ],
        )


class UrlEncodeModel(FunctionModel):
    """Model query encoding for mappings and pair sequences."""

    name = "urlencode"
    qualname = "urllib.parse.urlencode"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        concrete = _concrete_arguments(args, kwargs)
        if concrete is not None:
            try:
                function = cast("Callable[..., str]", urllib.parse.urlencode)
                return ModelResult(value=function(*concrete[0], **concrete[1]))
            except (TypeError, UnicodeError, ValueError) as exc:
                return _raised(self.qualname, exc)
        value, constraint = SymbolicString.symbolic(f"urllib_urlencode_{state.pc}")
        return ModelResult(
            value=value,
            constraints=[constraint],
            degradations=[_degradation(self.qualname, "query encoding contains symbolic values")],
        )


class ParseQueryModel(FunctionModel):
    """Model query decoding into a mapping or ordered pair list."""

    aliases: tuple[str, ...] = ()

    def __init__(self, operation: Literal["parse_qs", "parse_qsl"]) -> None:
        self.name = operation
        self.qualname = f"urllib.parse.{operation}"
        self._operation = operation

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        concrete = _concrete_arguments(args, kwargs)
        if concrete is not None:
            try:
                function = cast("Callable[..., StackValue]", getattr(urllib.parse, self._operation))
                return ModelResult(value=function(*concrete[0], **concrete[1]))
            except (TypeError, UnicodeError, ValueError) as exc:
                return _raised(self.qualname, exc)
        degradation = [_degradation(self.qualname, "query fields depend on symbolic text")]
        if self._operation == "parse_qsl":
            value, constraint = SymbolicList.symbolic(f"urllib_parse_qsl_{state.pc}")
        else:
            value, constraint = SymbolicDict.symbolic(f"urllib_parse_qs_{state.pc}")
            value.set_value_type("list[str]")
        return ModelResult(value=value, constraints=[constraint], degradations=degradation)


class UrlDefragModel(FunctionModel):
    """Model fragment removal while preserving both result components."""

    name = "urldefrag"
    qualname = "urllib.parse.urldefrag"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        concrete = _concrete_arguments(args, kwargs)
        if concrete is not None:
            try:
                function = cast("Callable[..., tuple[StackValue, ...]]", urllib.parse.urldefrag)
                return ModelResult(value=function(*concrete[0], **concrete[1]))
            except (TypeError, UnicodeError, ValueError) as exc:
                return _raised(self.qualname, exc)
        url, url_constraint = SymbolicString.symbolic(f"urllib_defrag_url_{state.pc}")
        fragment, fragment_constraint = SymbolicString.symbolic(
            f"urllib_defrag_fragment_{state.pc}",
        )
        return ModelResult(
            value=(url, fragment),
            constraints=[url_constraint, fragment_constraint],
            degradations=[
                _degradation(self.qualname, "fragment boundary depends on symbolic text"),
            ],
        )


urllib_parse_models: list[FunctionModel] = [
    UrlParseModel("urlparse"),
    UrlParseModel("urlsplit"),
    UrlAssembleModel("urlunparse"),
    UrlAssembleModel("urlunsplit"),
    UrlAssembleModel("urljoin"),
    UrlTextTransformModel("quote"),
    UrlTextTransformModel("quote_plus"),
    UrlTextTransformModel("unquote"),
    UrlTextTransformModel("unquote_plus"),
    UrlEncodeModel(),
    ParseQueryModel("parse_qs"),
    ParseQueryModel("parse_qsl"),
    UrlDefragModel(),
]
