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

"""functools model registry."""

from __future__ import annotations

from collections.abc import Callable

from pysymex.models.stdlib.functools.cache import model_cached_property, model_lru_cache
from pysymex.models.stdlib.functools.cmp import model_cmp_to_key
from pysymex.models.stdlib.functools.core import (
    model_partial,
    model_reduce,
    model_singledispatch,
    model_total_ordering,
    model_wraps,
)

FUNCTOOLS_MODELS: dict[str, Callable[..., object]] = {
    "partial": model_partial,
    "reduce": model_reduce,
    "lru_cache": model_lru_cache,
    "cached_property": model_cached_property,
    "wraps": model_wraps,
    "total_ordering": model_total_ordering,
    "cmp_to_key": model_cmp_to_key,
    "singledispatch": model_singledispatch,
}


def get_functools_model(name: str) -> Callable[..., object] | None:
    """Get the model for a functools function.

    Args:
        name: Name of the functools function

    Returns:
        The model or None if not found
    """
    return FUNCTOOLS_MODELS.get(name)


def register_functools_models() -> dict[str, Callable[..., object]]:
    """Register all functools models.

    Returns:
        Dict mapping fully qualified names to models
    """
    return {f"functools.{name}": model for name, model in FUNCTOOLS_MODELS.items()}


__all__ = ["FUNCTOOLS_MODELS", "get_functools_model", "register_functools_models"]
