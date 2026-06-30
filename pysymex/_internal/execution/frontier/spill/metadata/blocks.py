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

"""Block-stack spill metadata encoding and decoding."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.core.state.types import BlockInfo
from pysymex._internal.execution.frontier.spill.fields.decode import object_payload

from .fields import optional_int, required_int, required_str
from .types import SpillMetadataDecodeError

if TYPE_CHECKING:
    from pysymex._internal.execution.frontier.spill.values.types import JsonObject, JsonValue


def block_stack_payload(blocks: tuple[BlockInfo, ...]) -> list[JsonValue] | None:
    """Return JSON-safe control-flow block metadata."""
    encoded: list[JsonValue] = []
    for block in blocks:
        payload = _block_payload(block)
        if payload is None:
            return None
        encoded.append(payload)
    return encoded


def decode_block_stack(raw_blocks: object) -> list[BlockInfo]:
    """Decode control-flow block metadata from a spill payload."""
    if raw_blocks is None:
        return []
    if not isinstance(raw_blocks, list):
        msg = "block stack must be a list"
        raise SpillMetadataDecodeError(msg)
    return [_decode_block(raw_block) for raw_block in cast("list[object]", raw_blocks)]


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


def _decode_block(raw_block: object) -> BlockInfo:
    payload = object_payload(raw_block)
    if payload is None:
        msg = "block metadata is malformed"
        raise SpillMetadataDecodeError(msg)
    return BlockInfo(
        block_type=required_str(payload, "block_type"),
        start_pc=required_int(payload, "start_pc"),
        end_pc=required_int(payload, "end_pc"),
        handler_pc=optional_int(payload, "handler_pc"),
    )
