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

"""Core container and compound symbolic type package.

Runtime ownership lives in direct modules:

- :mod:`pysymex.core.types.containers.bytes` owns byte and bytearray carriers.
- :mod:`pysymex.core.types.containers.dict_views` owns live dictionary view carriers.
- :mod:`pysymex.core.types.containers.dicts` owns dictionary carriers.
- :mod:`pysymex.core.types.containers.iterator_sources` owns lazy iterator
  source descriptors.
- :mod:`pysymex.core.types.containers.lists` owns list carriers.
- :mod:`pysymex.core.types.containers.objects` owns object carriers.
- :mod:`pysymex.core.types.containers.callable_iterators` owns callable-sentinel
  iterator carriers.
- :mod:`pysymex.core.types.containers.sequences` owns tuple, set, and iterator
  carriers.
- :mod:`pysymex.core.types.containers.helpers` owns shared container helpers.

New internal code should import direct owners instead of routing through this
package initializer.
"""
