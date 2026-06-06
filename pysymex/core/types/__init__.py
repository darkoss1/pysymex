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

"""Symbolic-type package.

Runtime ownership lives in direct modules:

* :mod:`pysymex.core.types.base` owns the shared symbolic base contracts.
* :mod:`pysymex.core.types.scalars` owns scalar carrier implementations.
* :mod:`pysymex.core.types.containers` owns container carrier implementations.
* :mod:`pysymex.core.types.coercion` owns symbolic conversion helpers.
* :mod:`pysymex.core.types.factory` owns Python and type-hint construction.
* :mod:`pysymex.core.types.predicates` owns symbolic type predicates.
"""
