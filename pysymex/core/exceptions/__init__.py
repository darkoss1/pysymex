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

"""Core symbolic exception package.

Runtime ownership lives in direct modules:

- :mod:`pysymex.core.exceptions.objects` owns symbolic exception carriers and
  handler records.
- :mod:`pysymex.core.exceptions.state` owns path-local exception state.
- :mod:`pysymex.core.exceptions.contracts` owns raises-contract metadata.
- :mod:`pysymex.core.exceptions.categories` owns exception classification facts.
- :mod:`pysymex.core.exceptions.builtins` owns built-in exception hierarchy
  helpers.
- :mod:`pysymex.core.exceptions.analyzer` owns occurrence and contract analysis.

New internal code should import direct owners instead of routing through this
package initializer.
"""
