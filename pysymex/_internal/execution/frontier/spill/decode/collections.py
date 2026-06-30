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

"""Collection and root-reference decoding for spilled VM state fields."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.execution.frontier.spill.fields.decode import (
    decoded_pair,
    raise_format_error,
    required_list,
)
from pysymex._internal.execution.frontier.spill.values.decoding import decode_spill_value_ref
from pysymex._internal.execution.frontier.spill.values.types import SpillValueDecodeError

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pysymex._internal.typing.protocols import StackValue


def stack_values(
    payload: Mapping[str, object],
    key: str,
    value_table: Mapping[int, StackValue],
) -> list[StackValue]:
    """Return a primitive stack-value list."""
    return [
        stack_value(raw_value, payload, value_table) for raw_value in required_list(payload, key)
    ]


def named_values(
    payload: Mapping[str, object],
    key: str,
    value_table: Mapping[int, StackValue],
) -> dict[str, StackValue]:
    """Return primitive named values from JSON pairs."""
    values: dict[str, StackValue] = {}
    for raw_pair in required_list(payload, key):
        pair = decoded_pair(raw_pair, payload)
        if len(pair) != 2:
            raise_format_error(payload)
        raw_name, raw_value = pair
        if not isinstance(raw_name, str):
            raise_format_error(payload)
        values[raw_name] = stack_value(raw_value, payload, value_table)
    return values


def memory_values(
    payload: Mapping[str, object],
    key: str,
    value_table: Mapping[int, StackValue],
) -> dict[int, StackValue]:
    """Return primitive memory values from JSON pairs."""
    values: dict[int, StackValue] = {}
    for raw_pair in required_list(payload, key):
        pair = decoded_pair(raw_pair, payload)
        if len(pair) != 2:
            raise_format_error(payload)
        raw_address, raw_value = pair
        if isinstance(raw_address, bool) or not isinstance(raw_address, int):
            raise_format_error(payload)
        values[raw_address] = stack_value(raw_value, payload, value_table)
    return values


def stack_value(
    raw_value: object,
    payload: Mapping[str, object],
    value_table: Mapping[int, StackValue],
) -> StackValue:
    """Return a stack value from a validated value-table reference."""
    try:
        return decode_spill_value_ref(raw_value, value_table)
    except SpillValueDecodeError:
        raise_format_error(payload)


def optional_stack_value(
    payload: Mapping[str, object],
    key: str,
    value_table: Mapping[int, StackValue],
) -> StackValue | None:
    """Return an optional stack value from a value-table reference."""
    raw_value = payload.get(key)
    if raw_value is None:
        return None
    return stack_value(raw_value, payload, value_table)
