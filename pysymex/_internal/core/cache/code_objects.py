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

"""Public code-object cache exports and process-cache registration."""

from __future__ import annotations

from pysymex._internal.core.cache.code.exceptions import get_exception_entries
from pysymex._internal.core.cache.code.instructions import get_instructions
from pysymex._internal.core.cache.control import register_process_cache_clearer


def _clear_code_object_caches() -> None:
    """Clear process-local code-object instruction metadata caches."""
    get_instructions.cache_clear()
    get_exception_entries.cache_clear()


register_process_cache_clearer("core.code_object_caches", _clear_code_object_caches)
