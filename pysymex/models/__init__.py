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

"""Models module for Python builtins and standard library (lazy-loaded).

All public symbols are loaded on first access via ``__getattr__``.
"""

from __future__ import annotations

from pysymex.lazy import lazy_dir, lazy_getattr
from pysymex.models.model_exports import MODEL_EXPORTS

_EXPORTS = MODEL_EXPORTS


def __getattr__(name: str) -> object:
    """Lazy-load model exports to prevent eager side-effect imports."""
    return lazy_getattr(name, __name__, _EXPORTS, globals())


def __dir__() -> list[str]:
    """Dir."""
    return lazy_dir(_EXPORTS, globals())
