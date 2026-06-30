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

"""Evidence fingerprints for POLAR frontier parity checks."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from enum import Enum
from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.types.havoc import havoc_values_may_exist, is_havoc

if TYPE_CHECKING:
    from pysymex._internal.core.state.deferred import DeferredStateIssue

EvidenceDigest = tuple[object, ...]


def detector_obligation_digest(
    deferred_issues: tuple[DeferredStateIssue, ...],
) -> EvidenceDigest:
    """Return deterministic detector-sidecar facts for capsule/checkpoint parity."""
    return tuple(_deferred_issue_digest(deferred) for deferred in deferred_issues)


def havoc_root_count(values: Iterable[object]) -> int:
    """Return the number of live top-level roots that carry havoc precision loss."""
    if not havoc_values_may_exist():
        return 0
    count = 0
    for value in values:
        if is_havoc(value):
            count += 1
    return count


def _deferred_issue_digest(deferred: DeferredStateIssue) -> tuple[object, ...]:
    return (
        "deferred",
        _stable_value_digest(deferred.site_key),
        _issue_payload_digest(deferred.issue),
    )


def _issue_payload_digest(issue: object) -> object:
    fields: list[tuple[str, object]] = []
    for name in (
        "kind",
        "message",
        "constraints",
        "model",
        "pc",
        "line_number",
        "function_name",
        "filename",
        "file",
        "line",
        "column",
        "confidence",
        "likelihood",
        "severity",
        "detector_name",
        "suppression_reason",
        "counterexample",
        "is_caught",
    ):
        value = getattr(issue, name, _MISSING)
        if value is not _MISSING:
            fields.append((name, _stable_value_digest(cast("object", value))))
    if fields:
        return (
            "issue",
            type(issue).__module__,
            type(issue).__qualname__,
            tuple(fields),
        )
    return _stable_value_digest(issue)


def _stable_value_digest(value: object) -> object:
    if isinstance(value, (bool, int, float, str)) or value is None:
        return value
    if isinstance(value, bytes):
        return ("bytes", value.hex())
    if isinstance(value, Enum):
        return (
            "enum",
            type(value).__module__,
            type(value).__qualname__,
            value.name,
            _stable_value_digest(value.value),
        )
    if isinstance(value, z3.AstRef):
        return ("z3_ast", value.hash(), str(value))
    if isinstance(value, z3.ModelRef):
        return ("z3_model", str(value))
    if isinstance(value, tuple):
        tuple_value = cast("tuple[object, ...]", value)
        return tuple(_stable_value_digest(item) for item in tuple_value)
    if isinstance(value, list):
        list_value = cast("list[object]", value)
        return tuple(_stable_value_digest(item) for item in list_value)
    if isinstance(value, frozenset):
        frozen_value = cast("frozenset[object]", value)
        return tuple(sorted((_stable_value_digest(item) for item in frozen_value), key=repr))
    if isinstance(value, set):
        set_value = cast("set[object]", value)
        return tuple(sorted((_stable_value_digest(item) for item in set_value), key=repr))
    if isinstance(value, Mapping):
        raw_mapping = cast("Mapping[object, object]", value)
        return tuple(
            sorted(
                (
                    (_stable_value_digest(key), _stable_value_digest(item_value))
                    for key, item_value in raw_mapping.items()
                ),
                key=repr,
            ),
        )
    return ("object", type(value).__module__, type(value).__qualname__, repr(value))


class _MissingSentinel:
    """Sentinel for issue fields absent on generic deferred payloads."""


_MISSING = _MissingSentinel()
