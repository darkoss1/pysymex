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

"""Bytearray search models built on the bytes scalar-result SSoT."""

from __future__ import annotations

from ..search.affixes import BytesEndswithModel, BytesStartswithModel
from ..search.counts import BytesContainsModel, BytesCountModel
from ..search.indexing import BytesFindModel, BytesIndexModel, BytesRfindModel, BytesRindexModel

__all__ = [
    "BytearrayContainsModel",
    "BytearrayCountModel",
    "BytearrayEndswithModel",
    "BytearrayFindModel",
    "BytearrayIndexModel",
    "BytearrayRfindModel",
    "BytearrayRindexModel",
    "BytearrayStartswithModel",
]


class BytearrayCountModel(BytesCountModel):
    """Model for bytearray.count()."""

    qualname = "bytearray.count"


class BytearrayContainsModel(BytesContainsModel):
    """Model for bytearray.__contains__()."""

    qualname = "bytearray.__contains__"


class BytearrayFindModel(BytesFindModel):
    """Model for bytearray.find()."""

    qualname = "bytearray.find"


class BytearrayRfindModel(BytesRfindModel):
    """Model for bytearray.rfind()."""

    qualname = "bytearray.rfind"


class BytearrayIndexModel(BytesIndexModel):
    """Model for bytearray.index()."""

    qualname = "bytearray.index"


class BytearrayRindexModel(BytesRindexModel):
    """Model for bytearray.rindex()."""

    qualname = "bytearray.rindex"


class BytearrayStartswithModel(BytesStartswithModel):
    """Model for bytearray.startswith()."""

    qualname = "bytearray.startswith"


class BytearrayEndswithModel(BytesEndswithModel):
    """Model for bytearray.endswith()."""

    qualname = "bytearray.endswith"
