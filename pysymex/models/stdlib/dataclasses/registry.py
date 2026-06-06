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

from pysymex.models.stdlib.dataclass_helpers import (
    FieldInfo,
    KWOnlySentinel,
    MissingSentinel,
    asdict_model,
    astuple_model,
    field_model,
    fields_model,
    is_dataclass_model,
    replace_model,
)
from pysymex.models.stdlib.dataclasses.factory import dataclass_model, make_dataclass_model


DATACLASSES_MODELS = {
    "dataclass": dataclass_model,
    "field": field_model,
    "Field": FieldInfo,
    "asdict": asdict_model,
    "astuple": astuple_model,
    "make_dataclass": make_dataclass_model,
    "replace": replace_model,
    "is_dataclass": is_dataclass_model,
    "fields": fields_model,
    "MISSING": MissingSentinel(),
    "KW_ONLY": KWOnlySentinel(),
}


def get_dataclasses_model(name: str) -> object | None:
    """Get a dataclasses model by name."""
    return DATACLASSES_MODELS.get(name)


__all__ = ["DATACLASSES_MODELS", "get_dataclasses_model"]
