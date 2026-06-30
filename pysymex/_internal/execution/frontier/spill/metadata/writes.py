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

"""Write-event spill metadata encoding and decoding."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.effects.events import WriteEvent, WriteKind
from pysymex._internal.execution.frontier.spill.fields.decode import object_payload

from .fields import enum_member, optional_int, required_bool, required_str
from .types import SpillMetadataDecodeError

if TYPE_CHECKING:
    from pysymex._internal.execution.frontier.spill.values.types import JsonObject, JsonValue


def write_events_payload(write_events: tuple[WriteEvent, ...]) -> list[JsonValue] | None:
    """Return JSON-safe write-event metadata."""
    encoded: list[JsonValue] = []
    for event in write_events:
        payload = _write_event_payload(event)
        if payload is None:
            return None
        encoded.append(payload)
    return encoded


def decode_write_events(raw_events: object) -> list[WriteEvent]:
    """Decode write-event metadata from a spill payload."""
    if raw_events is None:
        return []
    if not isinstance(raw_events, list):
        msg = "write events must be a list"
        raise SpillMetadataDecodeError(msg)
    return [_decode_write_event(raw_event) for raw_event in cast("list[object]", raw_events)]


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


def _decode_write_event(raw_event: object) -> WriteEvent:
    payload = object_payload(raw_event)
    if payload is None:
        msg = "write event metadata is malformed"
        raise SpillMetadataDecodeError(msg)
    return WriteEvent(
        kind=enum_member(WriteKind, required_str(payload, "kind")),
        location=required_str(payload, "location"),
        pc=optional_int(payload, "pc"),
        precise=required_bool(payload, "precise"),
        source=required_str(payload, "source"),
    )
