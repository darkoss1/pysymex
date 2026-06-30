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

"""Shared code and global-map inspection helpers for entrypoint global selectors."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import CodeType
from typing import cast


class GlobalsInspection:
    """Domain owner for function global-map and bytecode name inspection."""

    @staticmethod
    def globals_for(func: Callable[..., object]) -> Mapping[str, object]:
        """Return the mapping of globals already present on ``func``."""
        raw_globals = getattr(func, "__globals__", {})
        if isinstance(raw_globals, dict):
            return cast("Mapping[str, object]", raw_globals)
        if isinstance(raw_globals, Mapping):
            return cast("Mapping[str, object]", raw_globals)
        return {}

    @staticmethod
    def referenced_names(code: CodeType) -> set[str]:
        """Return names referenced by *code* and nested code constants."""
        names = set(code.co_names)
        for const in code.co_consts:
            if isinstance(const, CodeType):
                names.update(GlobalsInspection.referenced_names(const))
        return names
