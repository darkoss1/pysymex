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

"""Identity-preserving encoder for frontier spill value tables."""

from __future__ import annotations

import base64
from typing import cast

from .primitives import UnsupportedValueSentinel, json_primitive
from .types import VALUE_REF_KEY, JsonObject, JsonValue


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
            return {VALUE_REF_KEY: existing_ref}
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
        return {VALUE_REF_KEY: value_ref}

    def value_table_payload(self) -> list[JsonValue]:
        """Return the encoded value table accumulated so far."""
        return list(self._records)

    def _value_record(self, value: object) -> JsonObject | None:
        """Return a JSON record for one spill-safe immutable root."""
        primitive = json_primitive(value)
        if not isinstance(primitive, UnsupportedValueSentinel):
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
