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

from __future__ import annotations
import dis
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING
import z3
from pysymex.analysis.detectors.base import Detector, Issue
from pysymex.analysis.detectors.base import IssueKind, IsSatFn
from pysymex.core.solver.unsat import extract_unsat_core

if TYPE_CHECKING:
    from pysymex.core.state import VMState


@dataclass
class ContradictionContext:
    core: list[z3.BoolRef]
    branch_cond: z3.BoolRef
    path_constraints: list[z3.BoolRef]


class LogicRule(ABC):
    name: str = "logical-rule"
    tier: int = 0

    @abstractmethod
    def matches(self, ctx: ContradictionContext) -> bool: ...


class LogicalContradictionDetector(Detector):
    name = "logical-contradiction"
    description = "Detects mathematically impossible paths indicating a flawed mental model."
    issue_kind = IssueKind.LOGICAL_CONTRADICTION
    relevant_opcodes = frozenset(
        {
            "POP_JUMP_IF_TRUE",
            "POP_JUMP_IF_FALSE",
            "POP_JUMP_FORWARD_IF_TRUE",
            "POP_JUMP_FORWARD_IF_FALSE",
            "POP_JUMP_BACKWARD_IF_TRUE",
            "POP_JUMP_BACKWARD_IF_FALSE",
            "JUMP_IF_TRUE_OR_POP",
            "JUMP_IF_FALSE_OR_POP",
        }
    )

    def __init__(self) -> None:
        self.rules: list[LogicRule] = []

    def register_rule(self, rule: LogicRule) -> None:
        self.rules.append(rule)

    def select_rule(self, ctx: ContradictionContext) -> LogicRule | None:
        """Pick the most specific matching rule.

        Policy: prefer higher tiers first (more contextual detectors),
        preserve registration order as tie-breaker within the same tier.
        """
        matches: list[LogicRule] = []
        for rule in self.rules:
            if rule.matches(ctx):
                matches.append(rule)
        if not matches:
            return None
        return max(matches, key=lambda r: r.tier)

    def check(
        self, state: VMState, instruction: dis.Instruction, _solver_check: IsSatFn
    ) -> Issue | None:
        if not state.stack:
            return None

        from pysymex.execution.opcodes import py_version

        control_module = getattr(py_version, "control")
        get_truthy_expr = getattr(control_module, "get_truthy_expr")
        cond = state.peek()
        cond_expr = get_truthy_expr(cond)

        if "FALSE" in instruction.opname:
            branch_cond_true = z3.Not(cond_expr)
            branch_cond_false = cond_expr
        else:
            branch_cond_true = cond_expr
            branch_cond_false = z3.Not(cond_expr)

        path_constraints = state.path_constraints.to_list()

        for branch_cond in (branch_cond_true, branch_cond_false):
            branch_path = path_constraints + [branch_cond]

            if not _solver_check(branch_path):
                core_result = extract_unsat_core(branch_path)

                if not core_result or not core_result.core:
                    core = [branch_cond]
                else:
                    core = core_result.core

                ctx = ContradictionContext(core, branch_cond, path_constraints)

                classification = "Unknown Logical Contradiction"
                chosen = self.select_rule(ctx)
                if chosen is not None:
                    classification = f"Tier {chosen.tier}: {chosen.name}"

                return Issue(
                    kind=self.issue_kind,
                    message=f"Logical Contradiction ({classification}): Path condition is mathematically impossible.",
                    constraints=core,
                    model=None,
                    pc=state.pc,
                )

        return None
