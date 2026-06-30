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

"""Digest helpers for frontier spill payloads."""

from __future__ import annotations

import json
from hashlib import sha256
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pysymex._internal.execution.frontier.spill.values.types import JsonValue

EXPECTED_DIGEST_KEY = "expected_digest"
EXPECTED_SPILL_DIGEST_KEY = "expected_spill_digest"
SPILL_INTEGRITY_EXCLUDED_KEYS = frozenset(
    (
        EXPECTED_DIGEST_KEY,
        EXPECTED_SPILL_DIGEST_KEY,
    ),
)


def json_digest_value(value: object) -> JsonValue:
    """Convert digest tuples into deterministic JSON values."""
    if isinstance(value, (bool, int, float, str)) or value is None:
        return value
    if isinstance(value, tuple):
        return [json_digest_value(item) for item in cast("tuple[object, ...]", value)]
    if isinstance(value, list):
        return [json_digest_value(item) for item in cast("list[object]", value)]
    msg = f"unsupported digest value for frontier spill: {type(value).__name__}"
    raise TypeError(msg)


def spill_payload_integrity_digest(payload: Mapping[str, object]) -> str:
    """Return a cold-path digest for spill payload fields outside capsule truth.

    The capsule digest remains the semantic proof boundary. This integrity digest
    is a deterministic fail-closed guard against accidental spill-file mutation
    for serialized runtime fields that are reconstructed before the capsule
    digest is rechecked.
    """
    digest_payload = {
        key: value for key, value in payload.items() if key not in SPILL_INTEGRITY_EXCLUDED_KEYS
    }
    canonical = json.dumps(digest_payload, sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode("utf-8")).hexdigest()
