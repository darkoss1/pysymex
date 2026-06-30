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

"""Shared facts for path-like symbolic string carriers."""

from __future__ import annotations

# Prefixes used by stdlib pathlib models when returning path-like symbolic strings.
PATH_STRING_PREFIXES = ("path_", "purepath_", "pureposixpath_")

# Path-like properties modeled as symbolic strings.
PATH_STRING_STRING_PROPERTIES = frozenset(("name", "parent", "stem", "suffix"))

# Path-like properties modeled as symbolic sequences.
PATH_STRING_SEQUENCE_PROPERTIES = frozenset(("suffixes",))

PATH_STRING_ATTRIBUTE_NAMES = PATH_STRING_STRING_PROPERTIES | PATH_STRING_SEQUENCE_PROPERTIES
