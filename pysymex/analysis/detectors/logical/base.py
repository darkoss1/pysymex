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

"""Base interfaces and context for logical-contradiction detectors.

Defines :class:`ContradictionContext`, the :class:`LogicRule` ABC, and
:class:`LogicalContradictionDetector` which checks conditional jumps for
infeasible branches and classifies them via tiered rules.
"""

from __future__ import annotations

import dis
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

import z3

from pysymex.analysis.detectors.detector.types import IssueKind, IsSatFn
from pysymex.analysis.detectors.detector.types import DetectorFn, DetectorInfo, Issue
from pysymex.core.solver.unsat import extract_unsat_core
from pysymex.core.types.truthiness import get_truthy_expr
from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState

logger = get_logger(__name__)
_SOLVER_FAILURES = (z3.Z3Exception, OSError, RuntimeError, ValueError)


@dataclass
class ContradictionContext:
    """Data bundle passed to :class:`LogicRule` matchers.

    Attributes:
        core: The unsatisfiable core extracted from the solver.
        branch_cond: The branch condition that was shown infeasible.
        path_constraints: The full path constraint list at the time of detection.
    """

    core: list[z3.BoolRef]
    branch_cond: z3.BoolRef
    path_constraints: list[z3.BoolRef]


class LogicRule(ABC):
    """Abstract base for contradiction classification rules.

    Subclasses classify a contradiction by pattern-matching the unsat
    core.  Higher ``tier`` values indicate more specific rules and take
    priority when multiple rules match.
    """

    name: str = "logical-rule"
    tier: int = 0

    @abstractmethod
    def matches(self, ctx: ContradictionContext) -> bool:
        """Return ``True`` if this rule matches the contradiction in *ctx*.

        Args:
            ctx: The contradiction context containing unsat core and constraints.

        Returns:
            ``True`` if the rule applies, ``False`` otherwise.
        """
        ...


class LogicalContradictionDetector:
    """Detect mathematically impossible branches via unsatisfiable-core analysis.

    Bug class:
        Logical contradiction — a conditional branch whose condition is
        always ``False`` (or always ``True``) under the current path
        constraints, indicating a flawed mental model.

    Evidence:
        Branch-extended path constraints are unsatisfiable; an unsat
        core is extracted and matched against registered :class:`LogicRule`
        instances.

    Issue kind:
        ``IssueKind.LOGICAL_CONTRADICTION``.

    Known false-positive conditions:
        Disabled by default (``report_infeasible_branches=False``) because
        overly aggressive loop-invariant or abstract constraints can produce
        spurious infeasibility.  Enable only after reviewing false-positive
        rates on the target codebase.
    """

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

    def __init__(self, *, report_infeasible_branches: bool = False) -> None:
        """Initialise the detector.

        Args:
            report_infeasible_branches: When ``True``, analyse and report
                logical contradictions at conditional jumps.  Defaults to
                ``False`` to avoid false positives from abstract constraints.
        """
        self.rules: list[LogicRule] = []
        self.report_infeasible_branches = report_infeasible_branches

    def register_rule(self, rule: LogicRule) -> None:
        """Append *rule* to the ordered rule list."""
        self.rules.append(rule)

    def to_info(self) -> DetectorInfo:
        """Return immutable metadata for function-registry registration."""
        return DetectorInfo(
            name=self.name,
            description=self.description,
            issue_kind=self.issue_kind,
            relevant_opcodes=self.relevant_opcodes,
        )

    def as_fn(self) -> DetectorFn:
        """Return this detector's check method as a function detector."""
        return self.check

    def select_rule(self, ctx: ContradictionContext) -> LogicRule | None:
        """Return the highest-tier rule matching *ctx*, or ``None`` if none match."""
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
        """Inspect *instruction* for an infeasible conditional branch.

        If ``report_infeasible_branches`` is disabled, returns ``None``
        immediately.  Otherwise, extracts the truthy expression from TOS,
        checks satisfiability for both branch directions, and for any
        infeasible direction extracts the unsat core and selects the
        highest-tier matching rule.

        Returns:
            An :class:`Issue` if a contradiction rule matches, else ``None``.
        """
        if not self.report_infeasible_branches:
            return None
        if not state.stack:
            return None

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

            if not _branch_is_satisfiable(branch_path, _solver_check):
                core_result = extract_unsat_core(branch_path)

                if not core_result or not core_result.core:
                    continue
                core = core_result.core

                ctx = ContradictionContext(core, branch_cond, path_constraints)

                classification = "Unknown Logical Contradiction"
                chosen = self.select_rule(ctx)
                if chosen is None:
                    continue
                classification = f"Tier {chosen.tier}: {chosen.name}"

                return Issue(
                    kind=self.issue_kind,
                    message=f"Logical Contradiction ({classification}): Path condition is mathematically impossible.",
                    constraints=core,
                    model=None,
                    pc=state.pc,
                )

        return None


def _branch_is_satisfiable(branch_path: list[z3.BoolRef], solver_check: IsSatFn) -> bool:
    """Return branch SAT evidence, treating solver callback failures as inconclusive."""
    try:
        return solver_check(branch_path)
    except _SOLVER_FAILURES:
        logger.debug(
            "Logical contradiction branch feasibility check failed; treating as inconclusive"
        )
        return True
