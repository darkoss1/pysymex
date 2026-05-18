# pysymex: Python Symbolic Execution & Formal Verification
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

from pysymex.analysis.detectors.logical.base import LogicRule, ContradictionContext
from pysymex.analysis.detectors.logical.utils import extract_bounds, extract_sum_const_comparisons


def _lower_bound(bounds: dict[str, int | None]) -> tuple[int, bool] | None:
    min_val = bounds.get("min")
    min_strict = bounds.get("min_strict")
    candidates: list[tuple[int, bool]] = []
    if min_val is not None:
        candidates.append((int(min_val), False))
    if min_strict is not None:
        candidates.append((int(min_strict), True))
    if not candidates:
        return None
    return max(candidates, key=lambda item: (item[0], item[1]))


def _upper_bound(bounds: dict[str, int | None]) -> tuple[int, bool] | None:
    max_val = bounds.get("max")
    max_strict = bounds.get("max_strict")
    candidates: list[tuple[int, bool]] = []
    if max_val is not None:
        candidates.append((int(max_val), False))
    if max_strict is not None:
        candidates.append((int(max_strict), True))
    if not candidates:
        return None
    return min(candidates, key=lambda item: (item[0], not item[1]))


class SumImpossibilityRule(LogicRule):
    name = "Sum Impossibility"
    tier = 2

    def matches(self, ctx: ContradictionContext) -> bool:
        bounds = extract_bounds(ctx.core)
        for names, op, value in extract_sum_const_comparisons(ctx.core):
            if op in ("<", "<="):
                lower_parts = [_lower_bound(bounds[name]) for name in names if name in bounds]
                if len(lower_parts) != len(names) or any(part is None for part in lower_parts):
                    continue
                lower_sum = sum(part[0] for part in lower_parts if part is not None)
                strict = any(part[1] for part in lower_parts if part is not None)
                if lower_sum > value or (op == "<" and lower_sum == value):
                    return True
                if op == "<=" and lower_sum == value and strict:
                    return True
            elif op in (">", ">="):
                upper_parts = [_upper_bound(bounds[name]) for name in names if name in bounds]
                if len(upper_parts) != len(names) or any(part is None for part in upper_parts):
                    continue
                upper_sum = sum(part[0] for part in upper_parts if part is not None)
                strict = any(part[1] for part in upper_parts if part is not None)
                if upper_sum < value or (op == ">" and upper_sum == value):
                    return True
                if op == ">=" and upper_sum == value and strict:
                    return True

        return False
