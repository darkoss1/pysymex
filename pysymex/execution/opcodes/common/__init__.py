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

"""Stable re-exports for shared common opcode helpers.

Surfaces builtin-type metadata and numeric opcode utilities consumed by
version-specific opcode packages. Does not register handlers or own VM
dispatch; see :mod:`pysymex.execution.opcodes` for opcode routing.
"""

from __future__ import annotations

from .builtin_types import BUILTIN_TYPES
from .numeric.helpers import (
    check_division_by_zero,
    check_negative_shift,
)
from .numeric.ops import (
    handle_numeric_binary_op,
    handle_unary_invert,
)

__all__ = [
    "BUILTIN_TYPES",
    "check_division_by_zero",
    "check_negative_shift",
    "handle_numeric_binary_op",
    "handle_unary_invert",
]
