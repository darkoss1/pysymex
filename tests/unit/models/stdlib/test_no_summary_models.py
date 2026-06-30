"""Contracts for semantic stdlib models replacing generic summaries."""

from __future__ import annotations

from pathlib import Path

import pysymex._internal.models.stdlib.coercion as coercion
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.models.stdlib.configparser.models import (
    ConfigParserMethodModel,
    ConfigParserModel,
)
from pysymex._internal.models.stdlib.hmac.models import HmacCompareDigestModel
from pysymex._internal.models.stdlib.time.models import TimeSleepModel


def _state() -> VMState:
    return VMState(pc=7)


def test_generic_summary_model_classes_are_removed() -> None:
    assert not hasattr(coercion, "SummaryModel")
    assert not hasattr(coercion, "OpaqueMethodModel")
    assert not hasattr(coercion, "IdentityModel")

    models_root = Path(coercion.__file__).parent
    for source in models_root.rglob("*.py"):
        text = source.read_text(encoding="utf-8")
        assert "SummaryModel" not in text
        assert "OpaqueMethodModel" not in text


def test_configparser_mutations_feed_later_queries() -> None:
    parser = ConfigParserModel().apply([], {}, _state()).value

    ConfigParserMethodModel("add_section").apply([parser, "app"], {}, _state())
    ConfigParserMethodModel("set").apply([parser, "app", "port", "42"], {}, _state())

    assert ConfigParserMethodModel("has_section").apply([parser, "app"], {}, _state()).value is True
    assert (
        ConfigParserMethodModel("has_option").apply([parser, "app", "port"], {}, _state()).value
        is True
    )
    assert (
        ConfigParserMethodModel("getint").apply([parser, "app", "port"], {}, _state()).value == 42
    )
    sections = ConfigParserMethodModel("sections").apply([parser], {}, _state()).value
    assert isinstance(sections, SymbolicList)
    assert sections.concrete_items == ["app"]


def test_hmac_compare_digest_preserves_concrete_equality() -> None:
    model = HmacCompareDigestModel()
    assert model.apply([b"same", b"same"], {}, _state()).value is True
    assert model.apply([b"left", b"right"], {}, _state()).value is False


def test_time_sleep_rejects_negative_delay_without_sleeping() -> None:
    result = TimeSleepModel().apply([-0.1], {}, _state())
    raised = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(raised)
    assert raised["exception_type"] == "ValueError"
