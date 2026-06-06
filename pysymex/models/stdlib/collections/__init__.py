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

"""Public exports for collections models."""

from __future__ import annotations

from pysymex.models.stdlib.collections.counter import CounterModel
from pysymex.models.stdlib.collections.defaultdict import DefaultDictModel
from pysymex.models.stdlib.collections.deque import DequeModel
from pysymex.models.stdlib.collections.mappings import ChainMapModel, OrderedDictModel

COLLECTIONS_MODELS = {
    "Counter": CounterModel,
    "defaultdict": DefaultDictModel,
    "deque": DequeModel,
    "OrderedDict": OrderedDictModel,
    "ChainMap": ChainMapModel,
}


def get_collections_model(name: str) -> type | None:
    """Get the model class for a collections type."""
    return COLLECTIONS_MODELS.get(name)


def register_collections_models() -> dict[str, type]:
    """Register all collections models."""
    return {
        "collections.Counter": CounterModel,
        "collections.defaultdict": DefaultDictModel,
        "collections.deque": DequeModel,
        "collections.OrderedDict": OrderedDictModel,
        "collections.ChainMap": ChainMapModel,
    }


__all__ = [
    "COLLECTIONS_MODELS",
    "ChainMapModel",
    "CounterModel",
    "DefaultDictModel",
    "DequeModel",
    "OrderedDictModel",
    "get_collections_model",
    "register_collections_models",
]
