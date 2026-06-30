"""Tests for semantic urllib.parse models."""

from __future__ import annotations

import urllib.parse

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.models.stdlib.registry import get_stdlib_model
from pysymex._internal.models.stdlib.urllib.models import (
    ParseQueryModel,
    UrlAssembleModel,
    UrlDefragModel,
    UrlEncodeModel,
    UrlParseModel,
    UrlTextTransformModel,
)


def _state() -> VMState:
    return VMState(pc=11)


def test_urlparse_and_urlsplit_preserve_concrete_components() -> None:
    url = "https://user:pass@example.com:8443/a/b?x=1#frag"

    parsed = UrlParseModel("urlparse").apply([url], {}, _state()).value
    split = UrlParseModel("urlsplit").apply([url], {}, _state()).value

    assert parsed == urllib.parse.urlparse(url)
    assert split == urllib.parse.urlsplit(url)


def test_url_assembly_and_text_transforms_match_cpython() -> None:
    joined = UrlAssembleModel("urljoin").apply(
        ["https://example.test/a/", "../b?q=hello world"], {}, _state()
    )
    quoted = UrlTextTransformModel("quote_plus").apply(["a/b c"], {}, _state())
    unquoted = UrlTextTransformModel("unquote").apply(["%2Fadmin%3Fx%3D1"], {}, _state())

    assert joined.value == "https://example.test/b?q=hello world"
    assert quoted.value == "a%2Fb+c"
    assert unquoted.value == "/admin?x=1"


def test_query_models_preserve_repeated_fields_and_blank_values() -> None:
    encoded = UrlEncodeModel().apply([{"tag": ["a", "b"], "empty": ""}], {"doseq": True}, _state())
    parsed = ParseQueryModel("parse_qs").apply(
        [encoded.value], {"keep_blank_values": True}, _state()
    )
    pairs = ParseQueryModel("parse_qsl").apply(
        [encoded.value], {"keep_blank_values": True}, _state()
    )

    assert encoded.value == "tag=a&tag=b&empty="
    assert parsed.value == {"tag": ["a", "b"], "empty": [""]}
    assert pairs.value == [("tag", "a"), ("tag", "b"), ("empty", "")]


def test_urldefrag_preserves_url_and_fragment() -> None:
    result = UrlDefragModel().apply(["https://example.test/a#section"], {}, _state())
    assert result.value == ("https://example.test/a", "section")


def test_symbolic_query_parse_is_typed_and_explicitly_degraded() -> None:
    query, _ = SymbolicString.symbolic("query")
    result = ParseQueryModel("parse_qs").apply([query], {}, _state())

    assert isinstance(result.value, SymbolicDict)
    assert getattr(result.value, "_value_type", None) == "list[str]"
    assert result.constraints
    assert result.degradations


def test_invalid_concrete_calls_report_cpython_exception() -> None:
    result = UrlTextTransformModel("quote").apply([123], {}, _state())
    raised = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(raised)
    assert raised["exception_type"] == "TypeError"


def test_urllib_parse_models_are_registered_by_qualified_name() -> None:
    assert isinstance(get_stdlib_model("urllib.parse.urlparse"), UrlParseModel)
    assert isinstance(get_stdlib_model("urllib.parse.urlencode"), UrlEncodeModel)
    assert isinstance(get_stdlib_model("urllib.parse.parse_qs"), ParseQueryModel)
