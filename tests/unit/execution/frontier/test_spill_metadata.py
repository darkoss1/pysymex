from __future__ import annotations

from typing import cast

import pytest

from pysymex.core.effects.events import WriteEvent, WriteKind
from pysymex.core.state.types import BlockInfo, LoopCounterKey
from pysymex.execution.frontier.spill.metadata import (
    SpillMetadataDecodeError,
    block_stack_payload,
    decode_block_stack,
    decode_loop_counters,
    decode_loop_iterations,
    decode_write_events,
    loop_counters_payload,
    loop_iterations_payload,
    write_events_payload,
)


def _block_payload() -> dict[str, object]:
    payloads = block_stack_payload((BlockInfo("try", 1, 5, 3),))
    assert payloads is not None
    payload = payloads[0]
    assert isinstance(payload, dict)
    return cast("dict[str, object]", payload)


def _write_event_payload() -> dict[str, object]:
    payloads = write_events_payload(
        (WriteEvent(WriteKind.GLOBAL, "value", 7, True, "STORE_GLOBAL"),)
    )
    assert payloads is not None
    payload = payloads[0]
    assert isinstance(payload, dict)
    return cast("dict[str, object]", payload)


def test_spill_metadata_round_trips_blocks_and_write_events() -> None:
    """Primitive execution metadata round-trips through JSON payloads."""
    assert decode_block_stack([_block_payload()]) == [BlockInfo("try", 1, 5, 3)]
    assert decode_block_stack(
        [{"block_type": "try", "start_pc": 1, "end_pc": 5, "handler_pc": None}]
    ) == [BlockInfo("try", 1, 5, None)]
    assert decode_write_events([_write_event_payload()]) == [
        WriteEvent(WriteKind.GLOBAL, "value", 7, True, "STORE_GLOBAL")
    ]
    assert decode_write_events(
        [{"kind": "GLOBAL", "location": "value", "pc": None, "precise": True, "source": "x"}]
    ) == [WriteEvent(WriteKind.GLOBAL, "value", None, True, "x")]
    assert decode_loop_iterations(loop_iterations_payload(((1, 2), ((1, 2), 3)))) == {
        1: 2,
        (1, 2): 3,
    }
    assert decode_loop_counters(loop_counters_payload(((4, 5),))) == {4: 5}


def test_spill_metadata_accepts_empty_collections() -> None:
    """Missing metadata fields decode as empty runtime metadata."""
    assert block_stack_payload(()) == []
    assert write_events_payload(()) == []
    assert loop_iterations_payload(()) == []
    assert loop_counters_payload(()) == []
    assert decode_block_stack(None) == []
    assert decode_write_events(None) == []
    assert decode_loop_iterations(None) == {}
    assert decode_loop_counters(None) == {}


@pytest.mark.parametrize(
    "blocks",
    [
        {"bad": "container"},
        ["not-object"],
        [{"block_type": 1, "start_pc": 1, "end_pc": 5, "handler_pc": 3}],
        [{"block_type": "try", "start_pc": True, "end_pc": 5, "handler_pc": 3}],
        [{"block_type": "try", "start_pc": 1, "end_pc": None, "handler_pc": 3}],
        [{"block_type": "try", "start_pc": 1, "end_pc": 5, "handler_pc": False}],
        [{"block_type": "try", "start_pc": 1, "end_pc": 5, "handler_pc": "bad"}],
    ],
)
def test_decode_block_stack_rejects_malformed_payloads(blocks: object) -> None:
    """Malformed block metadata fails closed."""
    with pytest.raises(SpillMetadataDecodeError):
        decode_block_stack(blocks)


@pytest.mark.parametrize(
    "events",
    [
        {"bad": "container"},
        ["not-object"],
        [{"kind": "NO_SUCH_KIND", "location": "value", "pc": 7, "precise": True, "source": "x"}],
        [{"kind": "GLOBAL", "location": 1, "pc": 7, "precise": True, "source": "x"}],
        [{"kind": "GLOBAL", "location": "value", "pc": False, "precise": True, "source": "x"}],
        [{"kind": "GLOBAL", "location": "value", "pc": "bad", "precise": True, "source": "x"}],
        [{"kind": "GLOBAL", "location": "value", "pc": 7, "precise": 1, "source": "x"}],
        [{"kind": "GLOBAL", "location": "value", "pc": 7, "precise": True, "source": 1}],
    ],
)
def test_decode_write_events_rejects_malformed_payloads(events: object) -> None:
    """Malformed write-event metadata fails closed."""
    with pytest.raises(SpillMetadataDecodeError):
        decode_write_events(events)


@pytest.mark.parametrize(
    "iterations",
    [
        {"bad": "container"},
        ["not-pair"],
        [[{"kind": "int", "value": 1}, 2, 3]],
        [[{1: "bad"}, 2]],
        [[{"kind": "bad", "value": 1}, 2]],
        [[{"kind": "int", "value": True}, 2]],
        [[{"kind": "int", "value": 1}, True]],
        [[{"kind": "tuple", "items": "bad"}, 2]],
        [[{"kind": "tuple", "items": [1, False]}, 2]],
        [[{"kind": "tuple", "items": [1, "bad"]}, 2]],
    ],
)
def test_decode_loop_iterations_rejects_malformed_payloads(iterations: object) -> None:
    """Malformed loop-iteration metadata fails closed."""
    with pytest.raises(SpillMetadataDecodeError):
        decode_loop_iterations(iterations)


@pytest.mark.parametrize(
    "counters",
    [
        {"bad": "container"},
        ["not-pair"],
        [[True, 2]],
        [[1, False]],
        [["bad", 2]],
        [[1, "bad"]],
    ],
)
def test_decode_loop_counters_rejects_malformed_payloads(counters: object) -> None:
    """Malformed loop-counter metadata fails closed."""
    with pytest.raises(SpillMetadataDecodeError):
        decode_loop_counters(counters)


def test_loop_metadata_payload_rejects_bool_keys_and_counts() -> None:
    """Loop metadata encoding rejects bools masquerading as integers."""
    bool_key = cast("tuple[tuple[LoopCounterKey, int], ...]", ((True, 1),))
    bool_count = cast("tuple[tuple[LoopCounterKey, int], ...]", ((1, True),))
    bool_tuple_key = cast("tuple[tuple[LoopCounterKey, int], ...]", ((((1, True), 1),)))
    bool_counter_key = cast("tuple[tuple[int, int], ...]", ((True, 1),))
    bool_counter_count = cast("tuple[tuple[int, int], ...]", ((1, True),))

    assert loop_iterations_payload(bool_key) is None
    assert loop_iterations_payload(bool_count) is None
    assert loop_iterations_payload(bool_tuple_key) is None
    assert loop_counters_payload(bool_counter_key) is None
    assert loop_counters_payload(bool_counter_count) is None


def test_spill_metadata_payload_rejects_non_exact_metadata_objects() -> None:
    """Metadata encoding accepts only exact SSoT dataclasses."""
    assert block_stack_payload(cast("tuple[BlockInfo, ...]", (object(),))) is None
    assert write_events_payload(cast("tuple[WriteEvent, ...]", (object(),))) is None


def test_spill_metadata_payload_rejects_bool_integer_fields() -> None:
    """Metadata encoding rejects bools that would otherwise pass as integers."""
    block_with_bool_start = BlockInfo("try", cast("int", True), 5, None)
    block_with_bool_handler = BlockInfo("try", 1, 5, cast("int | None", False))
    event_with_bool_pc = WriteEvent(
        WriteKind.GLOBAL,
        "value",
        cast("int | None", False),
        True,
        "x",
    )

    assert block_stack_payload((block_with_bool_start,)) is None
    assert block_stack_payload((block_with_bool_handler,)) is None
    assert write_events_payload((event_with_bool_pc,)) is None


@pytest.mark.parametrize(
    "raw_metadata",
    [
        [{1: "bad"}],
        [[{"kind": "int", "value": 1}, 2, 3]],
    ],
)
def test_decode_loop_iterations_rejects_non_string_keys_and_wrong_pair_lengths(
    raw_metadata: object,
) -> None:
    """Malformed loop metadata container shapes fail closed."""
    with pytest.raises(SpillMetadataDecodeError):
        decode_loop_iterations(raw_metadata)


def test_decode_block_stack_rejects_non_string_payload_keys() -> None:
    """Metadata objects must be string-keyed payloads."""
    with pytest.raises(SpillMetadataDecodeError):
        decode_block_stack([{1: "bad"}])
