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

"""Abstract stack marker values for callable contract safety analysis."""

from __future__ import annotations

from pysymex._internal.contracts.callable.policy import APPROVED_CALL_TARGETS


class _Unknown:
    """Sentinel for bytecode values that cannot be approved as call targets."""


class _SafeAttributeBase:
    """Sentinel for traced parameters whose attributes are modeled proxies."""


SafeValue = object()
UnknownValue = _Unknown()
SafeAttributeBaseValue = _SafeAttributeBase()


def loaded_value_marker(value: object) -> object:
    """Return an abstract stack marker for a loaded global or closure value."""
    if any(value is target for target in APPROVED_CALL_TARGETS):
        return value
    if is_safe_concrete_value(value):
        return SafeValue
    return UnknownValue


def is_safe_concrete_value(value: object) -> bool:
    """Return whether using *value* cannot execute user-defined host code."""
    return isinstance(value, (bool, int, float, str, bytes, type(None)))


def is_safe_expression_marker(value: object) -> bool:
    """Return whether an abstract value may participate in Z3/scalar operations."""
    return value is SafeValue or value is SafeAttributeBaseValue
