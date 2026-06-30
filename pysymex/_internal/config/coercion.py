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

"""Coercion helpers for user-provided configuration values."""

from __future__ import annotations


def _debug_default(kind: str, value: object) -> None:
    """Log fallback coercion without making config import logger eagerly."""
    try:
        from pysymex._internal.logging.root import get_logger
    except ImportError:
        return
    get_logger(__name__).debug("Using default %s config value for %r", kind, value)


class ConfigCoercion:
    """Domain owner for config value coercion."""

    @staticmethod
    def to_int(value: object, default: int) -> int:
        """Convert a generic config value to ``int``, returning ``default`` on failure."""
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str):
            try:
                return int(value.strip())
            except ValueError:
                _debug_default("int", value)
                return default
        return default

    @staticmethod
    def to_float(value: object, default: float) -> float:
        """Convert a generic config value to ``float``, returning ``default`` on failure."""
        if isinstance(value, bool):
            return float(int(value))
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value.strip())
            except ValueError:
                _debug_default("float", value)
                return default
        return default

    @staticmethod
    def to_optional_int(value: object) -> int | None:
        """Convert a present config value to ``int`` while preserving omission as ``None``."""
        if value is None:
            return None
        return ConfigCoercion.to_int(value, 0)

    @staticmethod
    def to_optional_float(value: object) -> float | None:
        """Convert a present config value to ``float`` while preserving omission as ``None``."""
        if value is None:
            return None
        return ConfigCoercion.to_float(value, 0.0)

    @staticmethod
    def to_bool(value: object, default: bool, *, accept_float: bool = True) -> bool:
        """Convert a generic config value to ``bool``, returning ``default`` on failure."""
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value != 0
        if accept_float and isinstance(value, float):
            return value != 0.0
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"1", "true", "yes", "on"}:
                return True
            if lowered in {"0", "false", "no", "off"}:
                return False
        return default
