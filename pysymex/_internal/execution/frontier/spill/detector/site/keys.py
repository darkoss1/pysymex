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

"""Detector site-key reconstruction from spill payloads."""

from __future__ import annotations

from typing import cast

from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.execution.frontier.spill.detector.fields import enum_member
from pysymex._internal.execution.frontier.spill.detector.types import SpillDetectorDecodeError


def decode_site_key(raw_site_key: object) -> tuple[int, int, IssueKind]:
    """Decode one detector publication site key."""
    if not isinstance(raw_site_key, list):
        msg = "detector site key is malformed"
        raise SpillDetectorDecodeError(msg)
    items = cast("list[object]", raw_site_key)
    if len(items) != 3:
        msg = "detector site key is malformed"
        raise SpillDetectorDecodeError(msg)
    instruction_list_id, pc, raw_kind = items
    if isinstance(instruction_list_id, bool) or not isinstance(instruction_list_id, int):
        msg = "detector site key is malformed"
        raise SpillDetectorDecodeError(msg)
    if isinstance(pc, bool) or not isinstance(pc, int):
        msg = "detector site key is malformed"
        raise SpillDetectorDecodeError(msg)
    if not isinstance(raw_kind, str):
        msg = "detector site key is malformed"
        raise SpillDetectorDecodeError(msg)
    return (instruction_list_id, pc, enum_member(IssueKind, raw_kind))
