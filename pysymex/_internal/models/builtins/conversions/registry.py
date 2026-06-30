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

"""Builtin constructor and conversion model registry."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.models.builtins.bytes.constructors import BytearrayModel, BytesModel
from pysymex._internal.models.builtins.constructors.collections import ListModel, NoneModel
from pysymex._internal.models.builtins.constructors.object import MemoryviewModel, ObjectModel
from pysymex._internal.models.builtins.constructors.set import FrozensetModel
from pysymex._internal.models.builtins.conversions.boolean import BoolModel
from pysymex._internal.models.builtins.conversions.numeric import (
    ComplexModel,
    FloatModel,
    SliceModel,
)
from pysymex._internal.models.builtins.conversions.scalar import IntModel, StrModel
from pysymex._internal.models.builtins.reflection.namespace import DictModel
from pysymex._internal.models.builtins.reflection.type_checks import TypeModel

if TYPE_CHECKING:
    from pysymex._internal.models.contracts.function import FunctionModel
    from pysymex._internal.models.contracts.types import TypeModel as BuiltinTypeModel

conversion_models: list[FunctionModel | BuiltinTypeModel] = [
    IntModel(),
    FloatModel(),
    BoolModel(),
    StrModel(),
    BytesModel(),
    BytearrayModel(),
    ListModel(),
    DictModel(),
    FrozensetModel(),
    NoneModel(),
    ObjectModel(),
    TypeModel(),
    MemoryviewModel(),
    ComplexModel(),
    SliceModel(),
]
