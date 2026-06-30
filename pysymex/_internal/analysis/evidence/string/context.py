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

"""String-derived integer context helpers for detector witness probes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.evidence.integer.equalities import IntegerEqualities

if TYPE_CHECKING:
    import z3


def has_string_context_integers(integer_variables: list[z3.ArithRef]) -> bool:
    """Return whether integer names look derived from string modeling."""
    for variable in integer_variables:
        name = variable.decl().name()
        if name.startswith("ord_") and name.endswith("_int"):
            return True
        if name.startswith("len_") and name.endswith("_int"):
            return True
        if "count" in name and name.endswith("_int"):
            return True
        if _is_missing_string_search_index(name) or _is_neutral_salt(name):
            return True
    return False


def string_context_integer_assignment(
    integer_variables: list[z3.ArithRef],
    *,
    formula: z3.BoolRef,
    source_text: str,
    bin_text: str | None,
) -> tuple[int, ...] | None:
    """Return one complete assignment for string-derived integer helper variables."""
    ord_variables = IntegerEqualities.ordered_ord_variables(integer_variables)
    if len(ord_variables) > len(source_text):
        return None
    values_by_name: dict[str, int] = {}
    for variable in integer_variables:
        name = variable.decl().name()
        if name.startswith("len_") and name.endswith("_int"):
            values_by_name[name] = len(source_text)
        elif "count" in name and name.endswith("_int") and bin_text is not None:
            values_by_name[name] = bin_text.count("1")
        elif _is_missing_string_search_index(name):
            values_by_name[name] = -1
        elif _is_neutral_salt(name):
            values_by_name[name] = 0
    for index, variable in enumerate(ord_variables):
        values_by_name[variable.decl().name()] = ord(source_text[index])
    IntegerEqualities.infer_values(
        formula=formula,
        integer_variables=integer_variables,
        values_by_name=values_by_name,
    )
    if any(variable.decl().name() not in values_by_name for variable in integer_variables):
        return None
    return tuple(values_by_name[variable.decl().name()] for variable in integer_variables)


def _is_missing_string_search_index(name: str) -> bool:
    return name.endswith("_int") and (name.startswith(("find_", "rfind_", "index_", "rindex_")))


def _is_neutral_salt(name: str) -> bool:
    return name == "salt_int" or name.endswith("_salt_int")
