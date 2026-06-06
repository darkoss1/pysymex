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

"""Manifest schema for contract regression expectations."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Self, TypeVar

from pysymex.contracts.types import ContractKind, VerificationResult

_EnumT = TypeVar("_EnumT", bound=Enum)


@dataclass(frozen=True, slots=True)
class ContractRegressionExpectation:
    """Expected outcome for one public contract regression case."""

    case: str
    frontend: str
    expected_status: VerificationResult
    kind: ContractKind
    family: str = ""
    requires_counterexample: bool = False
    allowed_unknown: bool = False

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> Self:
        """Build an expectation from JSON-like manifest data."""
        return cls(
            case=_required_string(data, "case"),
            frontend=_required_string(data, "frontend"),
            expected_status=_required_enum(
                VerificationResult,
                data,
                "expected_status",
            ),
            kind=_required_enum(ContractKind, data, "kind"),
            family=_optional_string(data, "family"),
            requires_counterexample=_optional_bool(data, "requires_counterexample"),
            allowed_unknown=_optional_bool(data, "allowed_unknown"),
        )

    def to_manifest(self) -> dict[str, object]:
        """Return the stable JSON-like manifest representation."""
        manifest: dict[str, object] = {
            "case": self.case,
            "frontend": self.frontend,
            "expected_status": self.expected_status.name,
            "kind": self.kind.name,
            "requires_counterexample": self.requires_counterexample,
            "allowed_unknown": self.allowed_unknown,
        }
        if self.family:
            manifest["family"] = self.family
        return manifest


def _required_string(data: Mapping[str, object], field: str) -> str:
    """Return a required string manifest field."""
    value = data.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"contract regression manifest field {field!r} must be a string")
    return value


def _optional_string(data: Mapping[str, object], field: str) -> str:
    """Return an optional string manifest field."""
    value = data.get(field, "")
    if not isinstance(value, str):
        raise ValueError(f"contract regression manifest field {field!r} must be a string")
    return value


def _required_enum(
    enum_type: type[_EnumT],
    data: Mapping[str, object],
    field: str,
) -> _EnumT:
    """Return a required enum field by member name."""
    value = data.get(field)
    if not isinstance(value, str):
        raise ValueError(f"contract regression manifest field {field!r} must be a string")
    try:
        return enum_type[value]
    except KeyError as exc:
        raise ValueError(
            f"contract regression manifest field {field!r} has invalid value {value!r}"
        ) from exc


def _optional_bool(data: Mapping[str, object], field: str) -> bool:
    """Return an optional boolean manifest field."""
    value = data.get(field, False)
    if not isinstance(value, bool):
        raise ValueError(f"contract regression manifest field {field!r} must be a bool")
    return value


__all__ = ["ContractRegressionExpectation"]
