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

"""Backward-compatible re-export of :class:`ContractCompiler`.

This module exists solely so that existing import paths work unchanged::

    from pysymex.analysis.contracts.compiler import ContractCompiler

The canonical implementation now lives in :mod:`pysymex.contracts.compiler`.
"""

from __future__ import annotations

from pysymex.contracts.compiler import ContractCompiler

__all__ = ["ContractCompiler"]
