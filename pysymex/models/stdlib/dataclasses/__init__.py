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

"""Runtime-mimicking helper models for the ``dataclasses`` module.

Symbolic ``FunctionModel`` handlers for execution-time registry use live under
``pysymex.models.stdlib.data.dataclasses``.
"""

from __future__ import annotations

from pysymex.models.stdlib.dataclass_helpers import (
    FieldInfo,
    asdict_model,
    astuple_model,
    dataclass_fields_model,
    field_model,
    fields_model,
    is_dataclass_model,
    replace_model,
)
from pysymex.models.stdlib.dataclasses.factory import (
    dataclass_model,
    make_dataclass_model,
)
from pysymex.models.stdlib.dataclasses.registry import (
    DATACLASSES_MODELS,
    get_dataclasses_model,
)

__all__ = [
    "DATACLASSES_MODELS",
    "FieldInfo",
    "asdict_model",
    "astuple_model",
    "dataclass_fields_model",
    "dataclass_model",
    "field_model",
    "fields_model",
    "get_dataclasses_model",
    "is_dataclass_model",
    "make_dataclass_model",
    "replace_model",
]
