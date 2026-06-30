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

"""String value-set generation for detector witness probes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.analysis.evidence.integer.equalities import IntegerEqualities
from pysymex._internal.analysis.evidence.string.literals import StringWitnesses

if TYPE_CHECKING:
    import z3


def string_witness_value_sets(
    string_variables: list[z3.SeqRef],
    integer_variables: list[z3.ArithRef],
    formula: z3.BoolRef,
) -> tuple[tuple[tuple[str, ...], frozenset[str]], ...]:
    """Return bounded string assignments and their active symbolic prefixes."""
    string_count = len(string_variables)
    string_prefixes = tuple(
        variable.decl().name().removesuffix("_str") for variable in string_variables
    )
    candidates = StringWitnesses.candidates(formula)
    if string_count == 1:
        prefix = string_prefixes[0]
        return tuple(((text,), frozenset((prefix,))) for text in candidates)
    if string_count != 2:
        return ()
    values: list[tuple[tuple[str, ...], frozenset[str]]] = []
    integer_prefixes = IntegerEqualities.slot_prefixes(integer_variables)
    for inactive_index, inactive_prefix in enumerate(string_prefixes):
        if inactive_prefix not in integer_prefixes:
            continue
        active_index = 1 - inactive_index
        active_prefix = string_prefixes[active_index]
        for source_text in candidates:
            string_values = ["", ""]
            string_values[inactive_index] = ""
            string_values[active_index] = source_text
            values.append((tuple(string_values), frozenset((active_prefix,))))
    if _has_bin_count_shape(string_prefixes, integer_variables):
        for source_text in candidates:
            for bin_text in StringWitnesses.bin_candidates(formula):
                values.append(((source_text, bin_text), frozenset(string_prefixes)))
                values.append(((bin_text, source_text), frozenset(string_prefixes)))
    return tuple(dict.fromkeys(values))


def source_string_witness(string_values: tuple[str, ...]) -> str:
    """Return the non-binary source text from a string witness tuple."""
    for value in string_values:
        if not value.startswith("0b"):
            return value
    return string_values[0]


def bin_string_witness(string_values: tuple[str, ...]) -> str | None:
    """Return the binary text witness from a string witness tuple, if present."""
    for value in string_values:
        if value.startswith("0b") and all(character in {"0", "1"} for character in value[2:]):
            return value
    return None


def string_context_text_pairs(formula: z3.ExprRef) -> tuple[tuple[str, str | None], ...]:
    """Return source/bin text pairs for string-derived integer-only probes."""
    source_values = StringWitnesses.candidates(formula)
    bin_values = (None, *StringWitnesses.bin_candidates(formula))
    return tuple(
        (source_text, bin_text) for source_text in source_values for bin_text in bin_values
    )


def _has_bin_count_shape(
    string_prefixes: tuple[str, ...],
    integer_variables: list[z3.ArithRef],
) -> bool:
    return any(prefix.startswith("bin_") for prefix in string_prefixes) or any(
        "count" in variable.decl().name() for variable in integer_variables
    )
