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

"""Builtin iteration, reduction, ordering, and truth model registry."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.models.builtins.iteration.aggregates import (
    EnumerateModel,
    SortedModel,
    SumModel,
    ZipModel,
)
from pysymex._internal.models.builtins.iteration.iter_model import IterModel
from pysymex._internal.models.builtins.iteration.lazy import FilterModel, MapModel
from pysymex._internal.models.builtins.iteration.next_model import NextModel
from pysymex._internal.models.builtins.iteration.reversed_model import ReversedModel
from pysymex._internal.models.builtins.iteration.truth import AllModel, AnyModel
from pysymex._internal.models.builtins.numeric.max import MaxModel
from pysymex._internal.models.builtins.numeric.min import MinModel
from pysymex._internal.models.builtins.reflection.identity import AiterModel, AnextModel
from pysymex._internal.models.builtins.sequences.len import LenModel
from pysymex._internal.models.builtins.sequences.range import RangeModel

if TYPE_CHECKING:
    from pysymex._internal.models.contracts.function import FunctionModel

iteration_models: list[FunctionModel] = [
    LenModel(),
    RangeModel(),
    EnumerateModel(),
    ZipModel(),
    MapModel(),
    FilterModel(),
    IterModel(),
    NextModel(),
    ReversedModel(),
    SumModel(),
    MinModel(),
    MaxModel(),
    SortedModel(),
    AllModel(),
    AnyModel(),
    AiterModel(),
    AnextModel(),
]
