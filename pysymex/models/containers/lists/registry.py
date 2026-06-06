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

"""Registry for symbolic list models."""

from __future__ import annotations

from .items import (
    ListCopyModel,
    ListDelitemModel,
    ListSetitemModel,
    ListSliceModel,
)
from .mutations.growth import ListAppendModel, ListExtendModel, ListInsertModel
from .mutations.ordering import ListReverseModel, ListSortModel
from .mutations.removal import ListClearModel, ListPopModel, ListRemoveModel
from .operators import (
    ListAddModel,
    ListIaddModel,
    ListImulModel,
    ListMulModel,
)
from .queries import (
    ListContainsModel,
    ListCountModel,
    ListEqModel,
    ListIndexModel,
    ListLenModel,
)

LIST_MODELS = [
    ListAppendModel(),
    ListExtendModel(),
    ListInsertModel(),
    ListRemoveModel(),
    ListPopModel(),
    ListClearModel(),
    ListIndexModel(),
    ListCountModel(),
    ListSortModel(),
    ListReverseModel(),
    ListCopyModel(),
    ListSliceModel(),
    ListContainsModel(),
    ListLenModel(),
    ListSetitemModel(),
    ListDelitemModel(),
    ListAddModel(),
    ListMulModel(),
    ListEqModel(),
    ListIaddModel(),
    ListImulModel(),
]
