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

"""Neutral Z3 expression helpers shared by core packages without import cycles."""

from __future__ import annotations

import z3


def safe_z3_eq(a: object, b: object) -> bool:
    """Return true only for structurally identical Z3 expressions in the same context."""
    if a is b:
        return True
    if not isinstance(a, z3.ExprRef) or not isinstance(b, z3.ExprRef):
        return False
    if a.ctx is not b.ctx:
        return False
    try:
        return bool(z3.eq(a, b))
    except z3.Z3Exception:
        return False


__all__ = ["safe_z3_eq"]
