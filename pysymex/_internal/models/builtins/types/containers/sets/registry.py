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

"""Registry for symbolic set models."""

from __future__ import annotations

from .constructor import SetConstructorModel
from .mutations.membership import SetAddModel, SetDiscardModel, SetRemoveModel
from .mutations.pop_clear import SetClearModel, SetPopModel
from .operations import (
    SetCopyModel,
    SetDifferenceModel,
    SetIntersectionModel,
    SetSymDiffModel,
    SetUnionModel,
)
from .queries import (
    SetContainsModel,
    SetIsdisjointModel,
    SetIssubsetModel,
    SetIssupersetModel,
    SetLenModel,
)
from .updates import (
    SetDiffUpdateModel,
    SetIntersectUpdateModel,
    SetSymDiffUpdateModel,
    SetUpdateModel,
)

SET_MODELS = [
    SetConstructorModel(),
    SetAddModel(),
    SetRemoveModel(),
    SetDiscardModel(),
    SetPopModel(),
    SetClearModel(),
    SetCopyModel(),
    SetUnionModel(),
    SetIntersectionModel(),
    SetDifferenceModel(),
    SetSymDiffModel(),
    SetIssubsetModel(),
    SetIssupersetModel(),
    SetIsdisjointModel(),
    SetUpdateModel(),
    SetIntersectUpdateModel(),
    SetDiffUpdateModel(),
    SetSymDiffUpdateModel(),
    SetContainsModel(),
    SetLenModel(),
]
