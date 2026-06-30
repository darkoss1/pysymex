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

"""dataclasses model registry."""

from __future__ import annotations

from pysymex._internal.models.stdlib.dataclasses.factory import (
    dataclass_model,
    make_dataclass_model,
)
from pysymex._internal.models.stdlib.dataclasses.model_ops import (
    DataclassModelOps,
    FieldInfo,
    KWOnlySentinel,
    MissingSentinel,
)

DATACLASSES_MODELS = {
    "dataclass": dataclass_model,
    "field": DataclassModelOps.field_model,
    "Field": FieldInfo,
    "asdict": DataclassModelOps.asdict_model,
    "astuple": DataclassModelOps.astuple_model,
    "make_dataclass": make_dataclass_model,
    "replace": DataclassModelOps.replace_model,
    "is_dataclass": DataclassModelOps.is_dataclass_model,
    "fields": DataclassModelOps.fields_model,
    "MISSING": MissingSentinel(),
    "KW_ONLY": KWOnlySentinel(),
}
