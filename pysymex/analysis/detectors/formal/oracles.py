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

"""Concrete Python exception oracles for detector differential checks."""

from __future__ import annotations

from collections.abc import Sequence


def oracle_division_risk(value: object) -> bool:
    """Determine concrete division-by-zero risk for a value by execution.

    Args:
        value: The divisor value to test.

    Returns:
        True if concrete division by the value raises ZeroDivisionError, otherwise False.
    """
    try:
        if not isinstance(value, (int, float)):
            return False
        _ = 1 / value
        return False
    except ZeroDivisionError:
        return True
    except Exception:
        return False


def oracle_index_risk(seq: Sequence[object], index: object) -> bool:
    """Determine concrete index boundary risk by attempting sequence subscription.

    Args:
        seq: The sequence to index into.
        index: The index value to test.

    Returns:
        True if the subscription raises IndexError, otherwise False.
    """
    try:
        if not isinstance(index, int):
            return False
        _ = seq[index]
        return False
    except IndexError:
        return True
    except Exception:
        return False


def oracle_none_risk(is_none: bool, name: str) -> bool:
    """Determine concrete None dereference risk using identifier names and null state.

    Args:
        is_none: True if the object represents None.
        name: The name/identifier of the object.

    Returns:
        True if the object is None and does not match any ignored patterns/names,
        otherwise False.
    """
    skip_names = {"self", "cls", "module", "builtins", "__builtins__"}
    skip_prefixes = ("_", "self.", "cls.", "tpl_", "args_", "kwargs_")
    if name in skip_names or any(name.startswith(p) for p in skip_prefixes):
        return False
    if not is_none:
        return False
    try:
        raise AttributeError
    except AttributeError:
        return True


def oracle_key_risk(mapping: dict[str, int], key: object) -> bool:
    """Determine concrete KeyError risk by attempting dict lookup.

    Args:
        mapping: The dictionary to search.
        key: The key value to test.

    Returns:
        True if dictionary lookup raises KeyError, otherwise False.
    """
    try:
        if not isinstance(key, str):
            return False
        _ = mapping[key]
        return False
    except KeyError:
        return True
    except Exception:
        return False


__all__ = [
    "oracle_division_risk",
    "oracle_index_risk",
    "oracle_key_risk",
    "oracle_none_risk",
]
