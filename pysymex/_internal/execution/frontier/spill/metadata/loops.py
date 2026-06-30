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

"""Loop-counter spill metadata encoding and decoding."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.execution.frontier.spill.fields.decode import object_payload

from .fields import pair_payload, raw_int, required_int
from .types import SpillMetadataDecodeError

if TYPE_CHECKING:
    from pysymex._internal.core.state.types import LoopCounterKey
    from pysymex._internal.execution.frontier.spill.values.types import JsonObject, JsonValue


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


def decode_loop_iterations(raw_iterations: object) -> dict[LoopCounterKey, int]:
    """Decode loop iteration metadata from a spill payload."""
    if raw_iterations is None:
        return {}
    if not isinstance(raw_iterations, list):
        msg = "loop iterations must be a list"
        raise SpillMetadataDecodeError(msg)
    result: dict[LoopCounterKey, int] = {}
    for raw_item in cast("list[object]", raw_iterations):
        pair = pair_payload(raw_item)
        if pair is None:
            msg = "loop iteration metadata is malformed"
            raise SpillMetadataDecodeError(msg)
        raw_key, raw_count = pair
        result[_decode_loop_key(raw_key)] = raw_int(raw_count)
    return result


def decode_loop_counters(raw_counters: object) -> dict[int, int]:
    """Decode loop counter metadata from a spill payload."""
    if raw_counters is None:
        return {}
    if not isinstance(raw_counters, list):
        msg = "loop counters must be a list"
        raise SpillMetadataDecodeError(msg)
    result: dict[int, int] = {}
    for raw_item in cast("list[object]", raw_counters):
        pair = pair_payload(raw_item)
        if pair is None:
            msg = "loop counter metadata is malformed"
            raise SpillMetadataDecodeError(msg)
        raw_loop_id, raw_count = pair
        result[raw_int(raw_loop_id)] = raw_int(raw_count)
    return result


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


def _decode_loop_key(raw_key: object) -> LoopCounterKey:
    payload = object_payload(raw_key)
    if payload is None:
        msg = "loop key metadata is malformed"
        raise SpillMetadataDecodeError(msg)
    raw_kind = payload.get("kind")
    if raw_kind == "int":
        return required_int(payload, "value")
    if raw_kind == "tuple":
        raw_items = payload.get("items")
        if not isinstance(raw_items, list):
            msg = "loop key metadata is malformed"
            raise SpillMetadataDecodeError(msg)
        return tuple(raw_int(item) for item in cast("list[object]", raw_items))
    msg = "loop key metadata is malformed"
    raise SpillMetadataDecodeError(msg)
