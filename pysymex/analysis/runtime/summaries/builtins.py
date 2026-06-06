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

"""Pre-computed summaries for Python built-in functions."""

from __future__ import annotations

import z3

from pysymex.analysis.runtime.summaries.builder import SummaryBuilder
from pysymex.analysis.runtime.summaries.registry import register_summary
from pysymex.analysis.runtime.summaries.types import FunctionSummary


def create_builtin_summaries() -> list[FunctionSummary]:
    """Create summaries for built-in functions."""
    summaries: list[FunctionSummary] = []
    len_summary = (
        SummaryBuilder("len")
        .set_qualname("builtins.len")
        .add_parameter("obj", "object")
        .set_return_type("int")
        .mark_pure()
        .build()
    )
    if not isinstance(len_summary.return_var, z3.ArithRef):
        raise TypeError("len summary return variable must be arithmetic")
    len_summary.return_constraint = len_summary.return_var >= 0
    summaries.append(len_summary)
    abs_summary = (
        SummaryBuilder("abs")
        .set_qualname("builtins.abs")
        .add_parameter("x", "int")
        .set_return_type("int")
        .mark_pure()
        .build()
    )
    x = abs_summary.parameters[0].to_z3()
    if not isinstance(abs_summary.return_var, z3.ArithRef):
        raise TypeError("abs summary return variable must be arithmetic")
    result = abs_summary.return_var
    abs_summary.postconditions.append(result >= 0)
    abs_summary.postconditions.append(z3.Or(result == x, result == -x))
    summaries.append(abs_summary)
    min_summary = (
        SummaryBuilder("min")
        .set_qualname("builtins.min")
        .add_parameter("args", "iterable")
        .set_return_type("int")
        .mark_pure()
        .build()
    )
    summaries.append(min_summary)
    max_summary = (
        SummaryBuilder("max")
        .set_qualname("builtins.max")
        .add_parameter("args", "iterable")
        .set_return_type("int")
        .mark_pure()
        .build()
    )
    summaries.append(max_summary)
    sum_summary = (
        SummaryBuilder("sum")
        .set_qualname("builtins.sum")
        .add_parameter("iterable", "iterable")
        .add_parameter("start", "int", default=0)
        .set_return_type("int")
        .mark_pure()
        .build()
    )
    summaries.append(sum_summary)
    print_summary = (
        SummaryBuilder("print")
        .set_qualname("builtins.print")
        .add_parameter("args", "object")
        .set_return_type("None")
        .modifies("stdout", scope="global")
        .build()
    )
    print_summary.is_pure = False
    summaries.append(print_summary)
    input_summary = (
        SummaryBuilder("input")
        .set_qualname("builtins.input")
        .add_parameter("prompt", "str", default="")
        .set_return_type("str")
        .reads_var("stdin", scope="global")
        .build()
    )
    input_summary.is_pure = False
    input_summary.is_deterministic = False
    summaries.append(input_summary)
    return summaries


def register_builtin_summaries() -> None:
    """Register built-in function summaries."""
    for summary in create_builtin_summaries():
        register_summary(summary)
