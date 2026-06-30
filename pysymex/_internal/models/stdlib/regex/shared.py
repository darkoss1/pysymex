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

"""Shared helpers for regex stdlib models."""

from __future__ import annotations

import re
from typing import cast

from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue

get_symbolic_string = SymbolicString.resolve


def get_pattern_string(arg: object) -> str | None:
    """Extract pattern string from argument (concrete or compiled)."""
    if isinstance(arg, str):
        return arg
    if isinstance(arg, re.Pattern):
        return cast("re.Pattern[str]", arg).pattern
    if isinstance(arg, SymbolicValue):
        pattern = getattr(arg, "pattern", None)
        if isinstance(pattern, str):
            return pattern
    if isinstance(arg, SymbolicString):
        return None
    return None
