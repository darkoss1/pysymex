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

"""Registry for symbolic dict models."""

from __future__ import annotations

from .access import (
    DictContainsModel,
    DictEqModel,
    DictGetitemModel,
    DictGetModel,
    DictLenModel,
)
from .constructors import DictFromkeysModel
from .mutations.bulk import DictClearModel, DictSetdefaultModel, DictUpdateModel
from .mutations.items import DictDelitemModel, DictSetitemModel
from .mutations.pop import DictPopitemModel, DictPopModel
from .operators import (
    DictIorModel,
    DictOrModel,
)
from .views import (
    DictCopyModel,
    DictItemsModel,
    DictKeysModel,
    DictValuesModel,
)

DICT_MODELS = [
    DictGetModel(),
    DictGetitemModel(),
    DictSetitemModel(),
    DictDelitemModel(),
    DictKeysModel(),
    DictValuesModel(),
    DictItemsModel(),
    DictPopModel(),
    DictPopitemModel(),
    DictUpdateModel(),
    DictClearModel(),
    DictCopyModel(),
    DictSetdefaultModel(),
    DictContainsModel(),
    DictLenModel(),
    DictFromkeysModel(),
    DictEqModel(),
    DictOrModel(),
    DictIorModel(),
]
