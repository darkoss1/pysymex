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

"""Execution-metadata encoding for frontier spill payloads."""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from typing import TypeVar, cast

from pysymex.core.effects.events import WriteEvent, WriteKind
from pysymex.core.state.types import BlockInfo, LoopCounterKey
from pysymex.execution.frontier.spill.values import JsonObject, JsonValue

__all__ = [
    "SpillMetadataDecodeError",
    "block_stack_payload",
    "decode_block_stack",
    "decode_loop_counters",
    "decode_loop_iterations",
    "decode_write_events",
    "loop_counters_payload",
    "loop_iterations_payload",
    "write_events_payload",
]

_EnumT = TypeVar("_EnumT", bound=Enum)


class SpillMetadataDecodeError(ValueError):
    """Raised when spill execution metadata is malformed."""


def block_stack_payload(blocks: tuple[BlockInfo, ...]) -> list[JsonValue] | None:
    """Return JSON-safe control-flow block metadata."""
    encoded: list[JsonValue] = []
    for block in blocks:
        payload = _block_payload(block)
        if payload is None:
            return None
        encoded.append(payload)
    return encoded


def write_events_payload(write_events: tuple[WriteEvent, ...]) -> list[JsonValue] | None:
    """Return JSON-safe write-event metadata."""
    encoded: list[JsonValue] = []
    for event in write_events:
        payload = _write_event_payload(event)
        if payload is None:
            return None
        encoded.append(payload)
    return encoded


def loop_iterations_payload(
    loop_iterations: tuple[tuple[LoopCounterKey, int], ...],
) -> list[JsonValue] | None:
    """Return JSON-safe loop iteration metadata."""
    encoded: list[JsonValue] = []
    for loop_key, count in loop_iterations:
        key_payload = _loop_key_payload(loop_key)
        if key_payload is None or isinstance(count, bool):
            return None
        encoded.append([key_payload, count])
    return encoded


def loop_counters_payload(loop_counters: tuple[tuple[int, int], ...]) -> list[JsonValue] | None:
    """Return JSON-safe loop counter metadata."""
    encoded: list[JsonValue] = []
    for loop_id, count in loop_counters:
        if isinstance(loop_id, bool) or isinstance(count, bool):
            return None
        encoded.append([loop_id, count])
    return encoded


def decode_block_stack(raw_blocks: object) -> list[BlockInfo]:
    """Decode control-flow block metadata from a spill payload."""
    if raw_blocks is None:
        return []
    if not isinstance(raw_blocks, list):
        raise SpillMetadataDecodeError("block stack must be a list")
    return [_decode_block(raw_block) for raw_block in cast("list[object]", raw_blocks)]


def decode_write_events(raw_events: object) -> list[WriteEvent]:
    """Decode write-event metadata from a spill payload."""
    if raw_events is None:
        return []
    if not isinstance(raw_events, list):
        raise SpillMetadataDecodeError("write events must be a list")
    return [_decode_write_event(raw_event) for raw_event in cast("list[object]", raw_events)]


def decode_loop_iterations(raw_iterations: object) -> dict[LoopCounterKey, int]:
    """Decode loop iteration metadata from a spill payload."""
    if raw_iterations is None:
        return {}
    if not isinstance(raw_iterations, list):
        raise SpillMetadataDecodeError("loop iterations must be a list")
    result: dict[LoopCounterKey, int] = {}
    for raw_item in cast("list[object]", raw_iterations):
        pair = _pair_payload(raw_item)
        if pair is None:
            raise SpillMetadataDecodeError("loop iteration metadata is malformed")
        raw_key, raw_count = pair
        result[_decode_loop_key(raw_key)] = _raw_int(raw_count)
    return result


def decode_loop_counters(raw_counters: object) -> dict[int, int]:
    """Decode loop counter metadata from a spill payload."""
    if raw_counters is None:
        return {}
    if not isinstance(raw_counters, list):
        raise SpillMetadataDecodeError("loop counters must be a list")
    result: dict[int, int] = {}
    for raw_item in cast("list[object]", raw_counters):
        pair = _pair_payload(raw_item)
        if pair is None:
            raise SpillMetadataDecodeError("loop counter metadata is malformed")
        raw_loop_id, raw_count = pair
        result[_raw_int(raw_loop_id)] = _raw_int(raw_count)
    return result


def _block_payload(block: BlockInfo) -> JsonObject | None:
    if type(block) is not BlockInfo:
        return None
    if (
        isinstance(block.start_pc, bool)
        or isinstance(block.end_pc, bool)
        or isinstance(block.handler_pc, bool)
    ):
        return None
    return {
        "block_type": block.block_type,
        "start_pc": block.start_pc,
        "end_pc": block.end_pc,
        "handler_pc": block.handler_pc,
    }


def _write_event_payload(event: WriteEvent) -> JsonObject | None:
    if type(event) is not WriteEvent:
        return None
    if isinstance(event.pc, bool):
        return None
    return {
        "kind": event.kind.name,
        "location": event.location,
        "pc": event.pc,
        "precise": event.precise,
        "source": event.source,
    }


def _loop_key_payload(loop_key: LoopCounterKey) -> JsonObject | None:
    if isinstance(loop_key, bool):
        return None
    if isinstance(loop_key, int):
        return {"kind": "int", "value": loop_key}
    items: list[JsonValue] = []
    for item in loop_key:
        if isinstance(item, bool):
            return None
        items.append(item)
    return {"kind": "tuple", "items": items}


def _decode_block(raw_block: object) -> BlockInfo:
    payload = _object_payload(raw_block)
    if payload is None:
        raise SpillMetadataDecodeError("block metadata is malformed")
    return BlockInfo(
        block_type=_required_str(payload, "block_type"),
        start_pc=_required_int(payload, "start_pc"),
        end_pc=_required_int(payload, "end_pc"),
        handler_pc=_optional_int(payload, "handler_pc"),
    )


def _decode_write_event(raw_event: object) -> WriteEvent:
    payload = _object_payload(raw_event)
    if payload is None:
        raise SpillMetadataDecodeError("write event metadata is malformed")
    return WriteEvent(
        kind=_enum_member(WriteKind, _required_str(payload, "kind")),
        location=_required_str(payload, "location"),
        pc=_optional_int(payload, "pc"),
        precise=_required_bool(payload, "precise"),
        source=_required_str(payload, "source"),
    )


def _decode_loop_key(raw_key: object) -> LoopCounterKey:
    payload = _object_payload(raw_key)
    if payload is None:
        raise SpillMetadataDecodeError("loop key metadata is malformed")
    raw_kind = payload.get("kind")
    if raw_kind == "int":
        return _required_int(payload, "value")
    if raw_kind == "tuple":
        raw_items = payload.get("items")
        if not isinstance(raw_items, list):
            raise SpillMetadataDecodeError("loop key metadata is malformed")
        return tuple(_raw_int(item) for item in cast("list[object]", raw_items))
    raise SpillMetadataDecodeError("loop key metadata is malformed")


def _object_payload(raw_payload: object) -> Mapping[str, object] | None:
    if not isinstance(raw_payload, Mapping):
        return None
    raw_mapping = cast("Mapping[object, object]", raw_payload)
    result: dict[str, object] = {}
    for key, value in raw_mapping.items():
        if not isinstance(key, str):
            return None
        result[key] = value
    return result


def _pair_payload(raw_payload: object) -> tuple[object, object] | None:
    if not isinstance(raw_payload, list):
        return None
    items = cast("list[object]", raw_payload)
    if len(items) != 2:
        return None
    return (items[0], items[1])


def _required_str(payload: Mapping[str, object], key: str) -> str:
    raw_value = payload.get(key)
    if isinstance(raw_value, str):
        return raw_value
    raise SpillMetadataDecodeError(f"metadata field {key!r} must be a string")


def _required_int(payload: Mapping[str, object], key: str) -> int:
    raw_value = payload.get(key)
    if isinstance(raw_value, bool):
        raise SpillMetadataDecodeError(f"metadata field {key!r} must be an integer")
    if isinstance(raw_value, int):
        return raw_value
    raise SpillMetadataDecodeError(f"metadata field {key!r} must be an integer")


def _raw_int(raw_value: object) -> int:
    if isinstance(raw_value, bool):
        raise SpillMetadataDecodeError("metadata integer is malformed")
    if isinstance(raw_value, int):
        return raw_value
    raise SpillMetadataDecodeError("metadata integer is malformed")


def _optional_int(payload: Mapping[str, object], key: str) -> int | None:
    raw_value = payload.get(key)
    if raw_value is None:
        return None
    if isinstance(raw_value, bool):
        raise SpillMetadataDecodeError(f"metadata field {key!r} must be an integer")
    if isinstance(raw_value, int):
        return raw_value
    raise SpillMetadataDecodeError(f"metadata field {key!r} must be an integer or null")


def _required_bool(payload: Mapping[str, object], key: str) -> bool:
    raw_value = payload.get(key)
    if isinstance(raw_value, bool):
        return raw_value
    raise SpillMetadataDecodeError(f"metadata field {key!r} must be a bool")


def _enum_member(enum_type: type[_EnumT], name: str) -> _EnumT:
    try:
        return enum_type[name]
    except KeyError as exc:
        raise SpillMetadataDecodeError("metadata enum value is unsupported") from exc
