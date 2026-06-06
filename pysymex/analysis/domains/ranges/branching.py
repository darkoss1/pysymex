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

"""Branch-condition refinement narrowing value ranges on each path."""

from __future__ import annotations

from pysymex.analysis.static.control.models import EdgeKind
from pysymex.analysis.static.control.models import BasicBlock
from pysymex.analysis.domains.ranges.domain import Range
from pysymex.analysis.domains.ranges.state import RangeState


class RangeBranchingMixin:
    def _refine_successor_state(
        self,
        block: BasicBlock,
        out_state: RangeState,
        edge_kind: EdgeKind | None,
    ) -> RangeState:
        if edge_kind not in {EdgeKind.BRANCH_TRUE, EdgeKind.BRANCH_FALSE}:
            return out_state
        comparison = self._simple_numeric_branch_comparison(block)
        if comparison is None:
            return out_state
        variable, op, constant = comparison
        return self._refine_variable_comparison(
            out_state,
            variable,
            op,
            constant,
            assume_true=edge_kind == EdgeKind.BRANCH_TRUE,
        )

    def _simple_numeric_branch_comparison(self, block: BasicBlock) -> tuple[str, str, int] | None:
        instructions = block.instructions
        if len(instructions) < 4:
            return None
        load_left, load_right, compare, jump = instructions[-4:]
        if not self._is_conditional_jump(jump.opname) or compare.opname != "COMPARE_OP":
            return None
        op = str(compare.argval)
        left_is_var = load_left.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_DEREF"}
        right_is_var = load_right.opname in {"LOAD_FAST", "LOAD_NAME", "LOAD_DEREF"}
        left_is_const = load_left.opname == "LOAD_CONST" and isinstance(load_left.argval, int)
        right_is_const = load_right.opname == "LOAD_CONST" and isinstance(load_right.argval, int)
        if left_is_var and right_is_const:
            return str(load_left.argval), op, int(load_right.argval)
        if left_is_const and right_is_var:
            reversed_op = self._reverse_comparison_op(op)
            if reversed_op is None:
                return None
            return str(load_right.argval), reversed_op, int(load_left.argval)
        return None

    @staticmethod
    def _is_conditional_jump(opname: str) -> bool:
        return (
            opname.startswith("POP_JUMP_")
            or opname.startswith("JUMP_IF_")
            or opname in {"FOR_ITER", "SEND"}
        )

    @staticmethod
    def _reverse_comparison_op(op: str) -> str | None:
        return {
            "<": ">",
            "<=": ">=",
            ">": "<",
            ">=": "<=",
            "==": "==",
            "!=": "!=",
        }.get(op)

    def _refine_variable_comparison(
        self,
        state: RangeState,
        variable: str,
        op: str,
        constant: int,
        *,
        assume_true: bool,
    ) -> RangeState:
        refined_range = self._comparison_range(op, constant, assume_true=assume_true)
        if refined_range is None:
            current = state.get(variable)
            if self._comparison_excludes_singleton(current, op, constant, assume_true=assume_true):
                return RangeState.bottom()
            return state
        result = state.copy()
        refined_value = result.get(variable).intersect(refined_range)
        if refined_value.is_empty:
            return RangeState.bottom()
        result.set(variable, refined_value)
        return result

    @staticmethod
    def _comparison_range(op: str, constant: int, *, assume_true: bool) -> Range | None:
        if not assume_true:
            inverted = {
                "<": ">=",
                "<=": ">",
                ">": "<=",
                ">=": "<",
                "==": "!=",
                "!=": "==",
            }.get(op)
            if inverted is None:
                return None
            return RangeBranchingMixin._comparison_range(inverted, constant, assume_true=True)
        if op == "<":
            return Range.at_most(constant - 1)
        if op == "<=":
            return Range.at_most(constant)
        if op == ">":
            return Range.at_least(constant + 1)
        if op == ">=":
            return Range.at_least(constant)
        if op == "==":
            return Range.exact(constant)
        return None

    @staticmethod
    def _comparison_excludes_singleton(
        current: Range,
        op: str,
        constant: int,
        *,
        assume_true: bool,
    ) -> bool:
        if not current.is_exact or current.exact_value != constant:
            return False
        return (op == "==" and not assume_true) or (op == "!=" and assume_true)


__all__ = ["RangeBranchingMixin"]
