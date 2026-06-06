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

"""Identity-preserving value encoding for frontier spill payloads."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from typing import TypeAlias, cast

from pysymex.typing import StackValue

__all__ = [
    "JsonObject",
    "JsonValue",
    "SpillValueDecodeError",
    "SpillValueEncoder",
    "decode_spill_value_ref",
    "decode_spill_value_table",
]

JsonPrimitive: TypeAlias = bool | int | float | str | None
JsonValue: TypeAlias = JsonPrimitive | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]

_VALUE_REF_KEY = "$ref"


class SpillValueDecodeError(ValueError):
    """Raised when a spill value table or root reference is malformed."""


class SpillValueEncoder:
    """Build an identity-preserving table for spill-safe immutable roots."""

    def __init__(self) -> None:
        self._identity_refs: dict[int, int] = {}
        self._records: list[JsonValue] = []
        self._encoding_stack: set[int] = set()

    def values_payload(self, values: tuple[object, ...]) -> list[JsonValue] | None:
        """Return reference payloads for one positional root collection."""
        encoded: list[JsonValue] = []
        for value in values:
            encoded_value = self.value_ref_payload(value)
            if encoded_value is None:
                return None
            encoded.append(encoded_value)
        return encoded

    def named_values_payload(
        self,
        values: tuple[tuple[str, object], ...],
    ) -> list[JsonValue] | None:
        """Return reference payloads for one string-keyed root collection."""
        encoded: list[JsonValue] = []
        for name, value in values:
            encoded_value = self.value_ref_payload(value)
            if encoded_value is None:
                return None
            encoded.append([name, encoded_value])
        return encoded

    def memory_values_payload(
        self,
        values: tuple[tuple[int, object], ...],
    ) -> list[JsonValue] | None:
        """Return reference payloads for one integer-addressed memory root collection."""
        encoded: list[JsonValue] = []
        for address, value in values:
            encoded_value = self.value_ref_payload(value)
            if encoded_value is None:
                return None
            encoded.append([address, encoded_value])
        return encoded

    def value_ref_payload(self, value: object) -> JsonObject | None:
        """Return a stable reference for a spill-safe root value."""
        identity_key = id(value)
        existing_ref = self._identity_refs.get(identity_key)
        if existing_ref is not None:
            return {_VALUE_REF_KEY: existing_ref}
        if identity_key in self._encoding_stack:
            return None

        self._encoding_stack.add(identity_key)
        try:
            record = self._value_record(value)
            if record is None:
                return None
        finally:
            self._encoding_stack.remove(identity_key)
        value_ref = len(self._records)
        self._records.append(record)
        self._identity_refs[identity_key] = value_ref
        return {_VALUE_REF_KEY: value_ref}

    def value_table_payload(self) -> list[JsonValue]:
        """Return the encoded value table accumulated so far."""
        return list(self._records)

    def _value_record(self, value: object) -> JsonObject | None:
        """Return a JSON record for one spill-safe immutable root."""
        primitive = _json_primitive(value)
        if not isinstance(primitive, _UnsupportedSentinel):
            return {"kind": "primitive", "value": primitive}
        if type(value) is bytes:
            return {
                "kind": "bytes",
                "base64": base64.b64encode(value).decode("ascii"),
            }
        if type(value) is tuple:
            encoded_items: list[JsonValue] = []
            for item in cast("tuple[object, ...]", value):
                encoded_item = self.value_ref_payload(item)
                if encoded_item is None:
                    return None
                encoded_items.append(encoded_item)
            return {"kind": "tuple", "items": encoded_items}
        if type(value) is list:
            encoded_items = []
            for item in cast("list[object]", value):
                encoded_item = self.value_ref_payload(item)
                if encoded_item is None:
                    return None
                encoded_items.append(encoded_item)
            return {"kind": "list", "items": encoded_items}
        if type(value) is dict:
            encoded_items = []
            for key, item in cast("dict[object, object]", value).items():
                if not isinstance(key, str):
                    return None
                encoded_item = self.value_ref_payload(item)
                if encoded_item is None:
                    return None
                encoded_items.append([key, encoded_item])
            return {"kind": "dict", "items": encoded_items}
        return None


def decode_spill_value_table(raw_table: object) -> dict[int, StackValue]:
    """Decode a spill value table into reconstructed root values."""
    if not isinstance(raw_table, list):
        raise SpillValueDecodeError("spill value table must be a list")
    values: dict[int, StackValue] = {}
    for index, raw_record in enumerate(cast("list[object]", raw_table)):
        values[index] = _decode_value_record(raw_record, values)
    return values


def decode_spill_value_ref(
    raw_ref: object,
    values: Mapping[int, StackValue],
) -> StackValue:
    """Decode one root reference from a spill payload."""
    mapping = _object_payload(raw_ref)
    if mapping is None or set(mapping) != {_VALUE_REF_KEY}:
        raise SpillValueDecodeError("spill root value reference is malformed")
    raw_index = mapping[_VALUE_REF_KEY]
    if isinstance(raw_index, bool) or not isinstance(raw_index, int):
        raise SpillValueDecodeError("spill root value reference must be an integer")
    try:
        return values[raw_index]
    except KeyError as exc:
        raise SpillValueDecodeError("spill root value reference is out of range") from exc


def _decode_value_record(
    raw_record: object,
    decoded_values: Mapping[int, StackValue],
) -> StackValue:
    """Decode one value-table record."""
    record = _object_payload(raw_record)
    if record is None:
        raise SpillValueDecodeError("spill value record must be an object")
    raw_kind = record.get("kind")
    if raw_kind == "primitive":
        raw_value = record.get("value")
        if _is_json_primitive(raw_value):
            return cast("StackValue", raw_value)
        raise SpillValueDecodeError("spill primitive record is malformed")
    if raw_kind == "bytes":
        raw_value = record.get("base64")
        if not isinstance(raw_value, str):
            raise SpillValueDecodeError("spill bytes record is malformed")
        try:
            return base64.b64decode(raw_value.encode("ascii"), validate=True)
        except ValueError as exc:
            raise SpillValueDecodeError("spill bytes record is malformed") from exc
    if raw_kind == "tuple":
        raw_items = record.get("items")
        if not isinstance(raw_items, list):
            raise SpillValueDecodeError("spill tuple record is malformed")
        items = [
            decode_spill_value_ref(raw_item, decoded_values)
            for raw_item in cast("list[object]", raw_items)
        ]
        return tuple(items)
    if raw_kind == "list":
        raw_items = record.get("items")
        if not isinstance(raw_items, list):
            raise SpillValueDecodeError("spill list record is malformed")
        return [
            decode_spill_value_ref(raw_item, decoded_values)
            for raw_item in cast("list[object]", raw_items)
        ]
    if raw_kind == "dict":
        raw_items = record.get("items")
        if not isinstance(raw_items, list):
            raise SpillValueDecodeError("spill dict record is malformed")
        result: dict[str, StackValue] = {}
        for raw_item in cast("list[object]", raw_items):
            raw_pair = _list_payload(raw_item)
            if raw_pair is None or len(raw_pair) != 2:
                raise SpillValueDecodeError("spill dict record is malformed")
            raw_key, raw_value_ref = raw_pair
            if not isinstance(raw_key, str):
                raise SpillValueDecodeError("spill dict record is malformed")
            result[raw_key] = decode_spill_value_ref(raw_value_ref, decoded_values)
        return result
    raise SpillValueDecodeError("spill value record kind is unsupported")


def _object_payload(raw_payload: object) -> Mapping[str, object] | None:
    """Return a string-keyed mapping from decoded JSON."""
    if not isinstance(raw_payload, Mapping):
        return None
    raw_mapping = cast("Mapping[object, object]", raw_payload)
    result: dict[str, object] = {}
    for key, value in raw_mapping.items():
        if not isinstance(key, str):
            return None
        result[key] = value
    return result


def _list_payload(raw_payload: object) -> list[object] | None:
    """Return a list payload from decoded JSON."""
    if not isinstance(raw_payload, list):
        return None
    return cast("list[object]", raw_payload)


def _json_primitive(value: object) -> JsonPrimitive | "_UnsupportedSentinel":
    """Return a JSON primitive for a safe immutable VM root."""
    if type(value) is bool:
        return value
    if type(value) is int:
        return value
    if type(value) is float:
        return value
    if type(value) is str:
        return value
    if value is None:
        return None
    return _UNSUPPORTED


def _is_json_primitive(raw_value: object) -> bool:
    """Return whether ``raw_value`` is a JSON primitive accepted as a VM root."""
    return isinstance(raw_value, (bool, int, float, str)) or raw_value is None


class _UnsupportedSentinel:
    """Sentinel for values that must not cross the spill boundary."""


_UNSUPPORTED = _UnsupportedSentinel()
