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

"""Models for the itertools module."""

from __future__ import annotations

from pysymex.models.stdlib.itertools.combinatorics import (
    model_combinations,
    model_combinations_with_replacement,
    model_permutations,
    model_product,
    model_zip_longest,
)
from pysymex.models.stdlib.itertools.infinite import (
    model_count,
    model_cycle,
    model_repeat,
)
from pysymex.models.stdlib.itertools.registry import (
    ITERTOOLS_MODELS,
    get_itertools_model,
    register_itertools_models,
)
from pysymex.models.stdlib.itertools.sequences import (
    ChainModel,
    model_accumulate,
    model_chain,
    model_chain_from_iterable,
    model_dropwhile,
    model_groupby,
    model_islice,
    model_takewhile,
)

__all__ = [
    "ITERTOOLS_MODELS",
    "ChainModel",
    "get_itertools_model",
    "model_accumulate",
    "model_chain",
    "model_chain_from_iterable",
    "model_combinations",
    "model_combinations_with_replacement",
    "model_count",
    "model_cycle",
    "model_dropwhile",
    "model_groupby",
    "model_islice",
    "model_permutations",
    "model_product",
    "model_repeat",
    "model_takewhile",
    "model_zip_longest",
    "register_itertools_models",
]
