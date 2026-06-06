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

"""Registry for symbolic bytes and bytearray models."""

from __future__ import annotations

from .bytearray.growth import (
    BytearrayAppendModel,
    BytearrayExtendModel,
    BytearrayInsertModel,
)
from .bytearray.misc import BytearrayCopyModel, BytearrayReverseModel
from .bytearray.removal import (
    BytearrayClearModel,
    BytearrayPopModel,
    BytearrayRemoveModel,
)
from .bytearray.search import (
    BytearrayContainsModel,
    BytearrayCountModel,
    BytearrayEndswithModel,
    BytearrayFindModel,
    BytearrayIndexModel,
    BytearrayRfindModel,
    BytearrayRindexModel,
    BytearrayStartswithModel,
)
from .bytearray.splitting import (
    BytearrayJoinModel,
    BytearrayPartitionModel,
    BytearrayRpartitionModel,
    BytearrayRsplitModel,
    BytearraySplitlinesModel,
    BytearraySplitModel,
)
from .classification import (
    BytearrayIsasciiModel,
    BytesIsalnumModel,
    BytesIsalphaModel,
    BytesIsasciiModel,
    BytesIsdigitModel,
    BytesIslowerModel,
    BytesIsspaceModel,
    BytesIstitleModel,
    BytesIsupperModel,
)
from .decoding import BytearrayDecodeModel, BytesDecodeModel
from .formatting import (
    BytearrayHexModel,
    BytesCenterModel,
    BytesHexModel,
    BytesLenModel,
    BytesLjustModel,
    BytesRjustModel,
    BytesZfillModel,
)
from .search.affixes import BytesEndswithModel, BytesStartswithModel
from .search.counts import BytesContainsModel, BytesCountModel
from .search.indexing import BytesFindModel, BytesIndexModel, BytesRfindModel, BytesRindexModel
from .splitting import (
    BytesJoinModel,
    BytesPartitionModel,
    BytesRpartitionModel,
    BytesRsplitModel,
    BytesSplitlinesModel,
    BytesSplitModel,
)
from .transforms.case import (
    BytearrayCapitalizeModel,
    BytearrayLowerModel,
    BytearraySwapcaseModel,
    BytearrayTitleModel,
    BytearrayUpperModel,
    BytesCapitalizeModel,
    BytesLowerModel,
    BytesSwapcaseModel,
    BytesTitleModel,
    BytesUpperModel,
)
from .transforms.replace import BytearrayReplaceModel, BytesReplaceModel
from .transforms.trimming import (
    BytearrayLstripModel,
    BytearrayRemovePrefixModel,
    BytearrayRemoveSuffixModel,
    BytearrayRstripModel,
    BytearrayStripModel,
    BytesLstripModel,
    BytesRemovePrefixModel,
    BytesRemoveSuffixModel,
    BytesRstripModel,
    BytesStripModel,
)
from .translation import (
    BytesExpandtabsModel,
    BytesMaketransModel,
    BytesTranslateModel,
)
from .shared import FunctionModel

BYTES_MODELS: list[FunctionModel] = [
    BytesDecodeModel(),
    BytesCountModel(),
    BytesFindModel(),
    BytesRfindModel(),
    BytesIndexModel(),
    BytesRindexModel(),
    BytesJoinModel(),
    BytesSplitModel(),
    BytesRsplitModel(),
    BytesReplaceModel(),
    BytesStripModel(),
    BytesLstripModel(),
    BytesRstripModel(),
    BytesStartswithModel(),
    BytesEndswithModel(),
    BytesUpperModel(),
    BytesLowerModel(),
    BytesTitleModel(),
    BytesCapitalizeModel(),
    BytesSwapcaseModel(),
    BytesContainsModel(),
    BytesLenModel(),
    BytesHexModel(),
    BytesPartitionModel(),
    BytesRpartitionModel(),
    BytesSplitlinesModel(),
    BytesCenterModel(),
    BytesLjustModel(),
    BytesRjustModel(),
    BytesZfillModel(),
    BytesTranslateModel(),
    BytesMaketransModel(),
    BytesExpandtabsModel(),
    BytesIsdigitModel(),
    BytesIsalphaModel(),
    BytesIsalnumModel(),
    BytesIsspaceModel(),
    BytesIslowerModel(),
    BytesIsupperModel(),
    BytesIstitleModel(),
    BytesRemovePrefixModel(),
    BytesRemoveSuffixModel(),
    BytearrayAppendModel(),
    BytearrayExtendModel(),
    BytearrayInsertModel(),
    BytearrayPopModel(),
    BytearrayRemoveModel(),
    BytearrayClearModel(),
    BytearrayReverseModel(),
    BytearrayCopyModel(),
    BytearrayDecodeModel(),
    BytearrayHexModel(),
    BytearrayReplaceModel(),
    BytearrayStripModel(),
    BytearrayLstripModel(),
    BytearrayRstripModel(),
    BytearrayUpperModel(),
    BytearrayLowerModel(),
    BytearrayTitleModel(),
    BytearrayCapitalizeModel(),
    BytearraySwapcaseModel(),
    BytearrayRemovePrefixModel(),
    BytearrayRemoveSuffixModel(),
    BytearrayCountModel(),
    BytearrayFindModel(),
    BytearrayRfindModel(),
    BytearrayIndexModel(),
    BytearrayRindexModel(),
    BytearrayContainsModel(),
    BytearrayStartswithModel(),
    BytearrayEndswithModel(),
    BytearrayJoinModel(),
    BytearraySplitModel(),
    BytearrayRsplitModel(),
    BytearrayPartitionModel(),
    BytearrayRpartitionModel(),
    BytearraySplitlinesModel(),
]
BYTES_MODELS.extend([BytesIsasciiModel(), BytearrayIsasciiModel()])
