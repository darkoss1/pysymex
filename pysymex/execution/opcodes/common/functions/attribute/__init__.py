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

"""Attribute load/store and descriptor protocol helpers for function opcodes.

Submodules split ``LOAD_ATTR``, ``STORE_ATTR``, ``DELETE_ATTR``, and dynamic ``getattr``
chains. See :mod:`pysymex.execution.opcodes.common.functions.attribute.load` and
:mod:`pysymex.execution.opcodes.common.functions.attribute.protocols`.
"""

from __future__ import annotations
