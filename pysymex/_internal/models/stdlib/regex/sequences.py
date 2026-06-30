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

"""Regex list/string transformation models."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.logging.root import get_logger

logger = get_logger(__name__)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult
from pysymex._internal.models.stdlib.regex.compiler import compile_pattern
from pysymex._internal.models.stdlib.regex.shared import get_pattern_string

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class ReFindallModel(FunctionModel):
    """Model for re.findall() - find all matches.

    Returns:
    - List of all non-overlapping matches
    Constraints:
    - Result list length >= 0
    - If string matches pattern, result length >= 1.

    """

    name = "findall"
    qualname = "re.findall"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        pattern = get_pattern_string(args[0]) if args else None
        string = SymbolicString.resolve(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicList.symbolic(f"findall_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        if pattern is not None and string is not None:
            try:
                z3_pattern = compile_pattern(pattern)
                any_prefix = z3.Star(z3.AllChar(z3.StringSort()))
                any_suffix = z3.Star(z3.AllChar(z3.StringSort()))
                contains_pattern = z3.InRe(
                    string.z3_str,
                    z3.Concat(any_prefix, z3.Concat(z3_pattern, any_suffix)),
                )
                constraints.append(z3.Implies(contains_pattern, result.z3_len >= 1))
                constraints.append(result.z3_len <= string.z3_len)
            except z3.Z3Exception:
                logger.debug("re.findall Z3 regex encoding unavailable", exc_info=True)
        return ModelResult(
            value=result,
            constraints=constraints,
        )


class ReSubModel(FunctionModel):
    """Model for re.sub() - substitute matches.

    Returns:
    - String with matches replaced
    Constraints:
    - If no matches, result == original
    - Result length relationship depends on replacement length.

    """

    name = "sub"
    qualname = "re.sub"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        pattern = get_pattern_string(args[0]) if args else None
        args[1] if len(args) > 1 else None
        string = SymbolicString.resolve(args[2]) if len(args) > 2 else None
        result, constraint = SymbolicString.symbolic(f"sub_{state.pc}")
        constraints = [constraint]
        if pattern is not None and string is not None:
            try:
                z3_pattern = compile_pattern(pattern)
                any_prefix = z3.Star(z3.AllChar(z3.StringSort()))
                any_suffix = z3.Star(z3.AllChar(z3.StringSort()))
                contains_pattern = z3.InRe(
                    string.z3_str,
                    z3.Concat(any_prefix, z3.Concat(z3_pattern, any_suffix)),
                )
                constraints.append(
                    z3.Implies(z3.Not(contains_pattern), result.z3_str == string.z3_str),
                )
            except z3.Z3Exception:
                logger.debug("re.sub Z3 regex encoding unavailable", exc_info=True)
        return ModelResult(
            value=result,
            constraints=constraints,
        )


class ReSplitModel(FunctionModel):
    """Model for re.split() - split by pattern.

    Returns:
    - List of strings
    Constraints:
    - Result length >= 1 (always at least one element)
    - If no matches, result length == 1.

    """

    name = "split"
    qualname = "re.split"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        pattern = get_pattern_string(args[0]) if args else None
        string = SymbolicString.resolve(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicList.symbolic(f"split_{state.pc}")
        constraints = [constraint, result.z3_len >= 1]
        if pattern is not None and string is not None:
            try:
                z3_pattern = compile_pattern(pattern)
                constraints.append(result.z3_len <= string.z3_len + 1)
                any_prefix = z3.Star(z3.AllChar(z3.StringSort()))
                any_suffix = z3.Star(z3.AllChar(z3.StringSort()))
                contains_pattern = z3.InRe(
                    string.z3_str,
                    z3.Concat(any_prefix, z3.Concat(z3_pattern, any_suffix)),
                )
                constraints.append(z3.Implies(z3.Not(contains_pattern), result.z3_len == 1))
            except z3.Z3Exception:
                logger.debug("re.split Z3 regex encoding unavailable", exc_info=True)
        return ModelResult(
            value=result,
            constraints=constraints,
        )
