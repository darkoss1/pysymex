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

from __future__ import annotations

MODEL_EXPORTS_3 = {
    "get_collections_model": ("pysymex.models.stdlib.collections", "get_collections_model"),
    "register_collections_models": (
        "pysymex.models.stdlib.collections",
        "register_collections_models",
    ),
    "ITERTOOLS_MODELS": ("pysymex.models.stdlib.itertools", "ITERTOOLS_MODELS"),
    "get_itertools_model": ("pysymex.models.stdlib.itertools", "get_itertools_model"),
    "register_itertools_models": ("pysymex.models.stdlib.itertools", "register_itertools_models"),
    "FUNCTOOLS_MODELS": ("pysymex.models.stdlib.functools", "FUNCTOOLS_MODELS"),
    "PartialModel": ("pysymex.models.stdlib.functools", "PartialModel"),
    "get_functools_model": ("pysymex.models.stdlib.functools", "get_functools_model"),
    "register_functools_models": ("pysymex.models.stdlib.functools", "register_functools_models"),
    "PATHLIB_MODELS": ("pysymex.models.stdlib.pathlib.registry", "PATHLIB_MODELS"),
}
