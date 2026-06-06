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

"""Constraint-independence package.

Runtime ownership lives in direct modules:

* :mod:`pysymex.core.solver.independence.optimizer` owns
  ``ConstraintIndependenceOptimizer``.
* :mod:`pysymex.core.solver.independence.slicing` owns slice selection.
* :mod:`pysymex.core.solver.independence.cache` owns slice/cache helpers.
* :mod:`pysymex.core.solver.independence.lifecycle` owns registration lifecycle.
* :mod:`pysymex.core.solver.independence.protocols` owns Z3 conversion protocols.
* :mod:`pysymex.core.solver.independence.union_find` owns ``UnionFind``.
"""
