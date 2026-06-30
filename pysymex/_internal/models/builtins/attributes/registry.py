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

"""Builtin attribute and descriptor model registry."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.models.builtins.attributes.descriptors import (
    ClassmethodModel,
    PropertyModel,
    StaticmethodModel,
)
from pysymex._internal.models.builtins.attributes.getattr import GetattrModel
from pysymex._internal.models.builtins.attributes.mutation import (
    DelattrModel,
    HasattrModel,
    SetattrModel,
)

if TYPE_CHECKING:
    from pysymex._internal.models.contracts.function import FunctionModel

attribute_models: list[FunctionModel] = [
    GetattrModel(),
    HasattrModel(),
    SetattrModel(),
    DelattrModel(),
    PropertyModel(),
    ClassmethodModel(),
    StaticmethodModel(),
]
