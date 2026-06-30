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

"""Runtime helpers and symbolic adapters for the :mod:`dataclasses` family."""

from __future__ import annotations

import pysymex._internal.models.stdlib.dataclasses.factory
import pysymex._internal.models.stdlib.dataclasses.model_ops
import pysymex._internal.models.stdlib.dataclasses.models
import pysymex._internal.models.stdlib.dataclasses.registry

dataclass_model = pysymex._internal.models.stdlib.dataclasses.factory.dataclass_model
make_dataclass_model = pysymex._internal.models.stdlib.dataclasses.factory.make_dataclass_model

DataclassModelOps = pysymex._internal.models.stdlib.dataclasses.model_ops.DataclassModelOps
FieldInfo = pysymex._internal.models.stdlib.dataclasses.model_ops.FieldInfo
KWOnlySentinel = pysymex._internal.models.stdlib.dataclasses.model_ops.KWOnlySentinel
MissingSentinel = pysymex._internal.models.stdlib.dataclasses.model_ops.MissingSentinel

AsDataclassModel = pysymex._internal.models.stdlib.dataclasses.models.AsDataclassModel
AstupleModel = pysymex._internal.models.stdlib.dataclasses.models.AstupleModel
DataclassFieldModel = pysymex._internal.models.stdlib.dataclasses.models.DataclassFieldModel
DataclassModel = pysymex._internal.models.stdlib.dataclasses.models.DataclassModel
FieldsModel = pysymex._internal.models.stdlib.dataclasses.models.FieldsModel
ReplaceModel = pysymex._internal.models.stdlib.dataclasses.models.ReplaceModel
dataclasses_models = pysymex._internal.models.stdlib.dataclasses.models.dataclasses_models

DATACLASSES_MODELS = pysymex._internal.models.stdlib.dataclasses.registry.DATACLASSES_MODELS

field_model = DataclassModelOps.field_model
asdict_model = DataclassModelOps.asdict_model
astuple_model = DataclassModelOps.astuple_model
replace_model = DataclassModelOps.replace_model
is_dataclass_model = DataclassModelOps.is_dataclass_model
fields_model = DataclassModelOps.fields_model
dataclass_fields_model = DataclassModelOps.dataclass_fields_model
