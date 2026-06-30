"""Precision contracts for literal parser and serializer models."""

from __future__ import annotations

import json

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.tuples import SymbolicTuple
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.sequences.len import LenModel
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.models.stdlib.ast.models import AstLiteralEvalModel
from pysymex._internal.models.stdlib.json.models import (
    JsonDumpModel,
    JsonDumpsModel,
    JsonLoadModel,
    JsonLoadsModel,
)
from pysymex._internal.models.stdlib.literals import concrete_value
from pysymex._internal.models.stdlib.registry import get_stdlib_model
from pysymex._internal.models.stdlib.tomllib.models import TomllibLoadModel, TomllibLoadsModel


def _state() -> VMState:
    return VMState(pc=13)


def _raised_type(result: object) -> str | None:
    side_effects = getattr(result, "side_effects", {})
    effect = side_effects.get("raised_exception")
    return effect["exception_type"] if SideEffects.is_raised_exception(effect) else None


def test_json_round_trip_preserves_nested_concrete_carriers_and_options() -> None:
    source = SymbolicDict.from_const(
        {
            "enabled": SymbolicValue.from_const(True),
            "items": [SymbolicValue.from_const(2), SymbolicValue.from_const(3)],
        }
    )

    encoded = JsonDumpsModel().apply(
        [source], {"sort_keys": True, "separators": (",", ":")}, _state()
    )
    assert isinstance(encoded.value, SymbolicString)
    assert concrete_value(encoded.value) == json.dumps(
        {"enabled": True, "items": [2, 3]}, sort_keys=True, separators=(",", ":")
    )
    assert not encoded.degradations

    decoded = JsonLoadsModel().apply([encoded.value], {}, _state())
    assert concrete_value(decoded.value) == {"enabled": True, "items": [2, 3]}
    assert not decoded.degradations


def test_json_models_surface_exact_decode_and_encode_failures() -> None:
    malformed = JsonLoadsModel().apply(['{"missing":'], {}, _state())
    unserializable = JsonDumpsModel().apply([{1, 2}], {}, _state())  # type: ignore[list-item]

    assert _raised_type(malformed) == "JSONDecodeError"
    assert _raised_type(unserializable) == "TypeError"


def test_json_symbolic_and_stream_results_declare_precision_loss() -> None:
    symbolic, symbolic_constraint = SymbolicString.symbolic("json_source")
    decoded = JsonLoadsModel().apply([symbolic], {}, _state())
    loaded = JsonLoadModel().apply([SymbolicValue.from_const("stream")], {}, _state())
    dumped = JsonDumpModel().apply([{"x": 1}, SymbolicValue.from_const("stream")], {}, _state())

    assert symbolic_constraint is not None
    assert decoded.degradations[0].label == "json.loads"
    assert loaded.side_effects["io"] is True
    assert loaded.degradations[0].label == "json.load"
    assert dumped.side_effects["io"] is True
    assert dumped.degradations[0].label == "json.dump"


def test_json_models_validate_call_binding_before_fallback() -> None:
    assert _raised_type(JsonLoadsModel().apply([], {}, _state())) == "TypeError"
    assert _raised_type(JsonDumpsModel().apply([1, 2], {}, _state())) == "TypeError"
    assert _raised_type(JsonLoadModel().apply([], {}, _state())) == "TypeError"
    assert _raised_type(JsonDumpModel().apply([1], {}, _state())) == "TypeError"


def test_ast_literal_eval_preserves_actual_literal_shape() -> None:
    mapping = AstLiteralEvalModel().apply(["{'x': (1, 'two')}"], {}, _state())

    assert isinstance(mapping.value, SymbolicDict)
    present, nested = mapping.value.concrete_value_for_key("x")
    assert present is True
    assert isinstance(nested, SymbolicTuple)
    assert concrete_value(mapping.value) == {"x": (1, "two")}


def test_ast_literal_eval_surfaces_syntax_error_and_does_not_assume_list() -> None:
    malformed = AstLiteralEvalModel().apply(["[1,"], {}, _state())
    symbolic, _ = SymbolicString.symbolic("literal_source")
    unknown = AstLiteralEvalModel().apply([symbolic], {}, _state())

    assert _raised_type(malformed) == "SyntaxError"
    assert isinstance(unknown.value, SymbolicValue)
    assert unknown.degradations[0].label == "ast.literal_eval"

    # The union-like result remains eligible for list refinement by an
    # ``isinstance`` guard; affinity alone must not force a false TypeError.
    guarded_length = LenModel().apply([unknown.value], {}, _state())
    assert _raised_type(guarded_length) is None


def test_tomllib_loads_preserves_nested_tables_and_decode_errors() -> None:
    parsed = TomllibLoadsModel().apply(['title = "demo"\n[server]\nport = 8080\n'], {}, _state())
    malformed = TomllibLoadsModel().apply(["title ="], {}, _state())

    assert concrete_value(parsed.value) == {"title": "demo", "server": {"port": 8080}}
    assert _raised_type(malformed) == "TOMLDecodeError"


def test_tomllib_stream_load_is_distinct_and_explicitly_external() -> None:
    loads_model = get_stdlib_model("tomllib.loads")
    load_model = get_stdlib_model("tomllib.load")

    assert isinstance(loads_model, TomllibLoadsModel)
    assert isinstance(load_model, TomllibLoadModel)
    result = load_model.apply([SymbolicValue.from_const("stream")], {}, _state())
    assert isinstance(result.value, SymbolicDict)
    assert result.side_effects["io"] is True
    assert result.degradations[0].label == "tomllib.load"
