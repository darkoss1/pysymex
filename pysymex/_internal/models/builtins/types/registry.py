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

"""Single assembly point for builtin type method models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.models.builtins.types.containers.bytes.registry import BYTES_MODELS
from pysymex._internal.models.builtins.types.containers.dicts.registry import DICT_MODELS
from pysymex._internal.models.builtins.types.containers.frozensets.registry import FROZENSET_MODELS
from pysymex._internal.models.builtins.types.containers.lists.registry import LIST_MODELS
from pysymex._internal.models.builtins.types.containers.sets.registry import SET_MODELS
from pysymex._internal.models.builtins.types.containers.strings.registry import STRING_MODELS
from pysymex._internal.models.builtins.types.containers.tuples.registry import TUPLE_MODELS
from pysymex._internal.models.builtins.types.numeric.models import INT_FLOAT_MODELS

if TYPE_CHECKING:
    from pysymex._internal.models.contracts.function import FunctionModel


def builtin_type_models() -> list[FunctionModel]:
    """Return models owned by Python builtin type objects."""
    return [
        *DICT_MODELS,
        *LIST_MODELS,
        *STRING_MODELS,
        *SET_MODELS,
        *TUPLE_MODELS,
        *BYTES_MODELS,
        *FROZENSET_MODELS,
        *INT_FLOAT_MODELS,
    ]
