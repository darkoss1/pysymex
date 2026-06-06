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

"""Models for the functools module."""

from __future__ import annotations

from pysymex.models.stdlib.functools.cache import (
    CachedPropertyModel,
    LRUCacheModel,
    model_cached_property,
    model_lru_cache,
)
from pysymex.models.stdlib.functools.cmp import model_cmp_to_key
from pysymex.models.stdlib.functools.core import (
    PartialModel,
    WrappedWrapper,
    model_partial,
    model_reduce,
    model_singledispatch,
    model_total_ordering,
    model_wraps,
)
from pysymex.models.stdlib.functools.registry import (
    FUNCTOOLS_MODELS,
    get_functools_model,
    register_functools_models,
)

__all__ = [
    "CachedPropertyModel",
    "FUNCTOOLS_MODELS",
    "LRUCacheModel",
    "PartialModel",
    "WrappedWrapper",
    "get_functools_model",
    "model_cached_property",
    "model_cmp_to_key",
    "model_lru_cache",
    "model_partial",
    "model_reduce",
    "model_singledispatch",
    "model_total_ordering",
    "model_wraps",
    "register_functools_models",
]
