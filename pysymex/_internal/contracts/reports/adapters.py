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

"""Adapters from contract evidence to report-facing values."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

import z3


def extract_counterexample_from_model(model: object) -> dict[str, object]:
    """Convert a Z3 model or mapping into report counterexample data."""
    if isinstance(model, Mapping):
        mapping = cast("Mapping[object, object]", model)
        return {str(key): value for key, value in mapping.items()}
    if not isinstance(model, z3.ModelRef):
        return {}

    def is_true_model_value(value: object) -> bool:
        """Return whether a model value should be treated as true."""
        return (isinstance(value, z3.BoolRef) and z3.is_true(value)) or str(value) == "True"

    def model_value_to_int_or_str(value: object) -> int | str:
        """Normalize a model value to ``int`` when possible, otherwise ``str``."""
        as_long = getattr(value, "as_long", None)
        if callable(as_long):
            long_value: object = as_long()
            if isinstance(long_value, int):
                return long_value
        return str(value)

    result: dict[str, dict[str, object]] = {}
    for decl in model.decls():
        name = decl.name()
        value: object = model[decl]
        if name.endswith("_int"):
            bucket = result.setdefault(name[:-4], {})
            bucket["int"] = value
        elif name.endswith("_bool"):
            bucket = result.setdefault(name[:-5], {})
            bucket["bool"] = value
        elif name.endswith("_is_int"):
            bucket = result.setdefault(name[:-7], {})
            bucket["is_int"] = value
        elif name.endswith("_is_bool"):
            bucket = result.setdefault(name[:-8], {})
            bucket["is_bool"] = value
        elif name.endswith("_str"):
            bucket = result.setdefault(name[:-4], {})
            bucket["str"] = value
        elif name.endswith("_len"):
            bucket = result.setdefault(name[:-4], {})
            bucket["len"] = value
        else:
            result[name] = {"value": value}

    formatted: dict[str, object] = {}
    for var, info in result.items():
        is_int_val = info.get("is_int")
        if is_true_model_value(is_int_val):
            formatted[var] = model_value_to_int_or_str(info.get("int"))
            continue

        is_bool_val = info.get("is_bool")
        if is_true_model_value(is_bool_val):
            val = info.get("bool")
            formatted[var] = is_true_model_value(val) if hasattr(val, "decl") else bool(val)
            continue

        if "str" in info:
            val_str = str(info.get("str"))
            if val_str.startswith('"') and val_str.endswith('"'):
                val_str = val_str[1:-1]
            formatted[var] = val_str
        elif "int" in info:
            formatted[var] = model_value_to_int_or_str(info.get("int"))
        elif "value" in info:
            val = info["value"]
            if hasattr(val, "as_long"):
                formatted[var] = model_value_to_int_or_str(val)
            elif hasattr(val, "decl"):
                formatted[var] = is_true_model_value(val)
            else:
                formatted[var] = str(val)
        else:
            formatted[var] = str(info)
    return formatted
