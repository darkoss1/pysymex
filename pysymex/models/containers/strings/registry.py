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

"""Registry for symbolic string container models."""

from __future__ import annotations

from .case import (
    StrCapitalizeModel,
    StrCasefoldModel,
    StrLowerModel,
    StrSwapcaseModel,
    StrTitleModel,
    StrUpperModel,
)
from .classification.case import (
    StrIslowerModel,
    StrIstitleModel,
    StrIsupperModel,
)
from .classification.content import (
    StrIsalnumModel,
    StrIsalphaModel,
    StrIsdecimalModel,
    StrIsdigitModel,
    StrIsnumericModel,
    StrIsspaceModel,
)
from .classification.special import StrIsasciiModel, StrIsidentifierModel, StrIsprintableModel
from .encoding import (
    StrEncodeModel,
    StrExpandtabsModel,
    StrMaketransModel,
    StrTranslateModel,
)
from .formatting import (
    StrCenterModel,
    StrFormatMapModel,
    StrFormatModel,
    StrLjustModel,
    StrRjustModel,
    StrZfillModel,
)
from .search.affixes import StrEndswithModel, StrReplaceModel, StrStartswithModel
from .search.counts import StrContainsModel, StrCountModel
from .search.indexing import StrFindModel, StrIndexModel, StrRfindModel, StrRindexModel
from .splitting import (
    StrJoinModel,
    StrPartitionModel,
    StrRpartitionModel,
    StrRsplitModel,
    StrSplitlinesModel,
    StrSplitModel,
)
from .trimming import (
    StrLstripModel,
    StrRemovePrefixModel,
    StrRemoveSuffixModel,
    StrRstripModel,
    StrStripModel,
)
from .shared import FunctionModel

STRING_MODELS: list[FunctionModel] = [
    StrLowerModel(),
    StrUpperModel(),
    StrCapitalizeModel(),
    StrTitleModel(),
    StrSwapcaseModel(),
    StrStripModel(),
    StrLstripModel(),
    StrRstripModel(),
    StrSplitModel(),
    StrRsplitModel(),
    StrJoinModel(),
    StrReplaceModel(),
    StrStartswithModel(),
    StrEndswithModel(),
    StrFindModel(),
    StrRfindModel(),
    StrIndexModel(),
    StrRindexModel(),
    StrCountModel(),
    StrContainsModel(),
    StrFormatModel(),
    StrFormatMapModel(),
    StrIsdigitModel(),
    StrIsalphaModel(),
    StrIsalnumModel(),
    StrIsspaceModel(),
    StrIslowerModel(),
    StrIsupperModel(),
    StrIstitleModel(),
    StrIsprintableModel(),
    StrIsidentifierModel(),
    StrIsdecimalModel(),
    StrIsnumericModel(),
    StrCenterModel(),
    StrLjustModel(),
    StrRjustModel(),
    StrZfillModel(),
    StrRemovePrefixModel(),
    StrRemoveSuffixModel(),
    StrPartitionModel(),
    StrRpartitionModel(),
    StrSplitlinesModel(),
    StrEncodeModel(),
    StrCasefoldModel(),
    StrExpandtabsModel(),
    StrMaketransModel(),
    StrTranslateModel(),
]
STRING_MODELS.extend([StrIsasciiModel()])
