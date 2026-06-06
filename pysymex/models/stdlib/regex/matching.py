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

"""Regex match/search/fullmatch models."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.core.constants import Z3_FALSE, Z3_ZERO
from pysymex.logger import get_logger
from pysymex.core.types.scalars.values import SymbolicValue

logger = get_logger(__name__)
from pysymex.models.builtins import FunctionModel, ModelResult
from pysymex.models.containers.strings.shared import concrete_string_literal
from pysymex.models.stdlib.regex.compiler import compile_pattern
from pysymex.models.stdlib.regex.shared import get_pattern_string, get_symbolic_string

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


def _match_or_none_value(name: str, matches: z3.BoolRef) -> SymbolicValue:
    """Represent Python's truthy Match object or falsy None result."""
    return SymbolicValue(
        _name=name,
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        z3_addr=z3.Int(f"{name}_addr"),
        is_obj=matches,
        is_none=z3.Not(matches),
        affinity_type="match_or_none",
    )


class ReMatchModel(FunctionModel):
    """Model for re.match() - match at beginning of string.
    Returns:
    - Match object (modeled as SymbolicValue) if pattern matches at start
    - None if no match
    Constraints:
    - If match succeeds, string starts with a substring matching pattern
    """

    name = "match"
    qualname = "re.match"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        pattern = get_pattern_string(args[0]) if args else None
        if pattern is None and args:
            pattern = concrete_string_literal(args[0])
        string = get_symbolic_string(args[1]) if len(args) > 1 else None
        name = f"match_{state.pc}"
        matches = z3.Bool(f"{name}_matches")
        if pattern is not None and string is not None:
            try:
                z3_pattern = compile_pattern(pattern)
                matches = z3.InRe(
                    string.z3_str,
                    z3.Concat(z3_pattern, z3.Star(z3.AllChar(z3.ReSort(z3.StringSort())))),
                )
            except z3.Z3Exception:
                logger.debug("re.match Z3 regex encoding unavailable", exc_info=True)
        return ModelResult(value=_match_or_none_value(name, matches))


class ReSearchModel(FunctionModel):
    """Model for re.search() - search anywhere in string.
    Returns:
    - Match object if pattern found anywhere
    - None if no match
    Constraints:
    - If match succeeds, string contains a substring matching pattern
    """

    name = "search"
    qualname = "re.search"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        pattern = get_pattern_string(args[0]) if args else None
        if pattern is None and args:
            pattern = concrete_string_literal(args[0])
        string = get_symbolic_string(args[1]) if len(args) > 1 else None
        name = f"search_{state.pc}"
        matches = z3.Bool(f"{name}_matches")
        if pattern is not None and string is not None:
            try:
                z3_pattern = compile_pattern(pattern)
                any_prefix = z3.Star(z3.AllChar(z3.ReSort(z3.StringSort())))
                any_suffix = z3.Star(z3.AllChar(z3.ReSort(z3.StringSort())))
                full_pattern = z3.Concat(any_prefix, z3.Concat(z3_pattern, any_suffix))
                matches = z3.InRe(string.z3_str, full_pattern)
            except z3.Z3Exception:
                logger.debug("re.search Z3 regex encoding unavailable", exc_info=True)
        return ModelResult(value=_match_or_none_value(name, matches))


class ReFullmatchModel(FunctionModel):
    """Model for re.fullmatch() - match entire string.
    Constraints:
    - String must match pattern completely
    """

    name = "fullmatch"
    qualname = "re.fullmatch"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        pattern = get_pattern_string(args[0]) if args else None
        if pattern is None and args:
            pattern = concrete_string_literal(args[0])
        string = get_symbolic_string(args[1]) if len(args) > 1 else None
        name = f"fullmatch_{state.pc}"
        matches = z3.Bool(f"{name}_matches")
        if pattern is not None and string is not None:
            try:
                z3_pattern = compile_pattern(pattern)
                matches = z3.InRe(string.z3_str, z3_pattern)
            except z3.Z3Exception:
                logger.debug("re.fullmatch Z3 regex encoding unavailable", exc_info=True)
        return ModelResult(
            value=_match_or_none_value(name, matches),
        )


__all__ = ["ReMatchModel", "ReSearchModel", "ReFullmatchModel"]
