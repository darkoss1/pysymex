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

"""Core memory package.

Runtime ownership lives in direct modules:

- :mod:`pysymex.core.memory.types` owns memory records and symbolic addresses.
- :mod:`pysymex.core.memory.alias_queries` owns alias-query evidence.
- :mod:`pysymex.core.memory.heap.store` owns the symbolic heap store.
- :mod:`pysymex.core.memory.heap.state` owns composite memory state.
- :mod:`pysymex.core.memory.heap.snapshots` owns snapshot records.

New internal code should import direct owners instead of routing through this
package initializer.
"""
