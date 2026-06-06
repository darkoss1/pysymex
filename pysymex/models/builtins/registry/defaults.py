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

"""Default builtin model assembly for the model registry."""

from __future__ import annotations

from typing import TypeAlias

from pysymex.models.builtins.base import FunctionModel
from pysymex.models.builtins.core.abs import AbsModel
from pysymex.models.builtins.core.collections import ListModel, NoneModel
from pysymex.models.builtins.core.conversions.numeric import FloatModel
from pysymex.models.builtins.core.conversions.scalar import BoolModel, IntModel, StrModel
from pysymex.models.builtins.core.iterables import (
    EnumerateModel,
    FilterModel,
    MapModel,
    SortedModel,
    SumModel,
    ZipModel,
)
from pysymex.models.builtins.core.len import LenModel
from pysymex.models.builtins.core.max import MaxModel
from pysymex.models.builtins.core.min import MinModel
from pysymex.models.builtins.core.range import RangeModel
from pysymex.models.builtins.core.type_checks import IsinstanceModel, PrintModel, TypeModel
from pysymex.models.builtins.exceptions import create_exception_models
from pysymex.models.builtins.registry.external_defaults import external_default_models
from pysymex.models.builtins.types import TypeModel as TypeObjectModel

RegistryModel: TypeAlias = FunctionModel | TypeObjectModel


def default_builtin_models() -> list[RegistryModel]:
    """Build the default builtin, stdlib, and container model list."""
    from pysymex.models.builtins.core.conversions.numeric import ComplexModel, SliceModel

    return [
        IntModel(),
        FloatModel(),
        BoolModel(),
        StrModel(),
        ListModel(),
        NoneModel(),
        TypeModel(),
        PrintModel(),
        AbsModel(),
        MinModel(),
        MaxModel(),
        SumModel(),
        ZipModel(),
        RangeModel(),
        EnumerateModel(),
        FilterModel(),
        MapModel(),
        IsinstanceModel(),
        LenModel(),
        SortedModel(),
        *create_exception_models(),
        ComplexModel(),
        SliceModel(),
        *external_default_models(),
    ]
