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

"""Decode identity-preserving frontier spill value tables."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, cast

from pysymex._internal.execution.frontier.spill.fields.decode import object_payload

from .primitives import is_json_primitive
from .types import VALUE_REF_KEY, SpillValueDecodeError

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pysymex._internal.typing.protocols import StackValue


def decode_spill_value_table(raw_table: object) -> dict[int, StackValue]:
    """Decode a spill value table into reconstructed root values."""
    if not isinstance(raw_table, list):
        msg = "spill value table must be a list"
        raise SpillValueDecodeError(msg)
    values: dict[int, StackValue] = {}
    for index, raw_record in enumerate(cast("list[object]", raw_table)):
        values[index] = _decode_value_record(raw_record, values)
    return values


def decode_spill_value_ref(
    raw_ref: object,
    values: Mapping[int, StackValue],
) -> StackValue:
    """Decode one root reference from a spill payload."""
    mapping = object_payload(raw_ref)
    if mapping is None or set(mapping) != {VALUE_REF_KEY}:
        msg = "spill root value reference is malformed"
        raise SpillValueDecodeError(msg)
    raw_index = mapping[VALUE_REF_KEY]
    if isinstance(raw_index, bool) or not isinstance(raw_index, int):
        msg = "spill root value reference must be an integer"
        raise SpillValueDecodeError(msg)
    try:
        return values[raw_index]
    except KeyError as exc:
        msg = "spill root value reference is out of range"
        raise SpillValueDecodeError(msg) from exc


def _decode_value_record(
    raw_record: object,
    decoded_values: Mapping[int, StackValue],
) -> StackValue:
    """Decode one value-table record."""
    record = object_payload(raw_record)
    if record is None:
        msg = "spill value record must be an object"
        raise SpillValueDecodeError(msg)
    raw_kind = record.get("kind")
    if raw_kind == "primitive":
        raw_value = record.get("value")
        if is_json_primitive(raw_value):
            return cast("StackValue", raw_value)
        msg = "spill primitive record is malformed"
        raise SpillValueDecodeError(msg)
    if raw_kind == "bytes":
        raw_value = record.get("base64")
        if not isinstance(raw_value, str):
            msg = "spill bytes record is malformed"
            raise SpillValueDecodeError(msg)
        try:
            return base64.b64decode(raw_value.encode("ascii"), validate=True)
        except ValueError as exc:
            msg = "spill bytes record is malformed"
            raise SpillValueDecodeError(msg) from exc
    if raw_kind == "tuple":
        raw_items = record.get("items")
        if not isinstance(raw_items, list):
            msg = "spill tuple record is malformed"
            raise SpillValueDecodeError(msg)
        items = [
            decode_spill_value_ref(raw_item, decoded_values)
            for raw_item in cast("list[object]", raw_items)
        ]
        return tuple(items)
    if raw_kind == "list":
        raw_items = record.get("items")
        if not isinstance(raw_items, list):
            msg = "spill list record is malformed"
            raise SpillValueDecodeError(msg)
        return [
            decode_spill_value_ref(raw_item, decoded_values)
            for raw_item in cast("list[object]", raw_items)
        ]
    if raw_kind == "dict":
        raw_items = record.get("items")
        if not isinstance(raw_items, list):
            msg = "spill dict record is malformed"
            raise SpillValueDecodeError(msg)
        result: dict[str, StackValue] = {}
        for raw_item in cast("list[object]", raw_items):
            raw_pair = _list_payload(raw_item)
            if raw_pair is None or len(raw_pair) != 2:
                msg = "spill dict record is malformed"
                raise SpillValueDecodeError(msg)
            raw_key, raw_value_ref = raw_pair
            if not isinstance(raw_key, str):
                msg = "spill dict record is malformed"
                raise SpillValueDecodeError(msg)
            result[raw_key] = decode_spill_value_ref(raw_value_ref, decoded_values)
        return result
    msg = "spill value record kind is unsupported"
    raise SpillValueDecodeError(msg)


def _list_payload(raw_payload: object) -> list[object] | None:
    """Return a list payload from decoded JSON."""
    if not isinstance(raw_payload, list):
        return None
    return cast("list[object]", raw_payload)
