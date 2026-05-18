# pysymex: Python Symbolic Execution & Formal Verification
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

"""Canonical Z3 sentinel constants for the pysymex engine.

Every module that needs ``Z3_TRUE``, ``Z3_FALSE``, or ``Z3_ZERO`` MUST
import them from here.  This eliminates object-identity divergence
caused by independent ``z3.BoolVal()`` / ``z3.IntVal()`` calls in
separate modules, which silently broke ``is``-based fast-path checks.

This module is placed directly under ``pysymex.core`` (not under
``pysymex.core.solver``) to avoid triggering the ``solver/__init__.py``
import chain, which eagerly loads ``engine.py`` and causes circular
imports when ``scalars.py`` is still being initialized.
"""

from __future__ import annotations

import z3

Z3_TRUE: z3.BoolRef = z3.BoolVal(True)
Z3_FALSE: z3.BoolRef = z3.BoolVal(False)
Z3_ZERO: z3.ArithRef = z3.IntVal(0)
Z3_ONE: z3.ArithRef = z3.IntVal(1)
Z3_FLOAT_ZERO: z3.FPRef = z3.FPVal(0.0, z3.Float64())
Z3_EMPTY_STRING: z3.SeqRef = z3.StringVal("")

__all__ = ["Z3_EMPTY_STRING", "Z3_FALSE", "Z3_FLOAT_ZERO", "Z3_ONE", "Z3_TRUE", "Z3_ZERO"]
