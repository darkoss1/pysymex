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

"""itertools model registry."""

from __future__ import annotations

from collections.abc import Callable

from pysymex.models.stdlib.itertools.combinatorics import (
    model_combinations,
    model_combinations_with_replacement,
    model_permutations,
    model_product,
    model_zip_longest,
)
from pysymex.models.stdlib.itertools.infinite import model_count, model_cycle, model_repeat
from pysymex.models.stdlib.itertools.sequences import (
    model_accumulate,
    model_chain,
    model_chain_from_iterable,
    model_dropwhile,
    model_groupby,
    model_islice,
    model_takewhile,
)

ITERTOOLS_MODELS: dict[str, Callable[..., object]] = {
    "chain": model_chain,
    "chain.from_iterable": model_chain_from_iterable,
    "islice": model_islice,
    "groupby": model_groupby,
    "product": model_product,
    "permutations": model_permutations,
    "combinations": model_combinations,
    "combinations_with_replacement": model_combinations_with_replacement,
    "count": model_count,
    "cycle": model_cycle,
    "repeat": model_repeat,
    "accumulate": model_accumulate,
    "takewhile": model_takewhile,
    "dropwhile": model_dropwhile,
    "zip_longest": model_zip_longest,
}


def get_itertools_model(name: str) -> Callable[..., object] | None:
    """Get the model function for an itertools function.

    Args:
        name: Name of the itertools function

    Returns:
        The model function or None if not found
    """
    return ITERTOOLS_MODELS.get(name)


def register_itertools_models() -> dict[str, Callable[..., object]]:
    """Register all itertools models.

    Returns:
        Dict mapping fully qualified names to model functions
    """
    return {f"itertools.{name}": model for name, model in ITERTOOLS_MODELS.items()}


__all__ = ["ITERTOOLS_MODELS", "get_itertools_model", "register_itertools_models"]
