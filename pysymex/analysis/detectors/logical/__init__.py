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

"""Detectors for logical contradictions, tautologies, and impossible conditions."""

from __future__ import annotations

from pysymex.analysis.detectors.logical.base import LogicalContradictionDetector
from pysymex.analysis.detectors.logical.t1_local import (
    ArithmeticImpossibilityRule,
    ComplementContradictionRule,
    EqualityContradictionRule,
    ModularContradictionRule,
    ParityContradictionRule,
    RangeContradictionRule,
    SelfContradictionRule,
)
from pysymex.analysis.detectors.logical.t2_multivar import (
    AntisymmetryRule,
    GcdImpossibilityRule,
    ProductSignContradictionRule,
    SumImpossibilityRule,
    TriangleImpossibilityRule,
)
from pysymex.analysis.detectors.logical.t3_path import (
    LoopInvariantViolationRule,
    NarrowingContradictionRule,
    PostAssignmentContradictionRule,
    ReturnTypeContradictionRule,
    SequentialModularRule,
)
from pysymex.analysis.detectors.logical.t4_interprocedural import (
    ApiContractViolationRule,
    NumericRangePropagationRule,
    PostconditionContradictionRule,
    PreconditionImpossibilityRule,
)
from pysymex.analysis.detectors.logical.t5_temporal import (
    ConcurrencyContradictionRule,
    ResourceStateContradictionRule,
    StateImpossibilityRule,
)


def create_logic_detector(
    *, report_infeasible_branches: bool = False
) -> LogicalContradictionDetector:
    """Create a standard logical detector with all tiers registered.

    Infeasible branch alternatives are normal symbolic-execution pruning facts.
    They are exposed only for targeted audit runs to avoid user-facing false positives.
    """
    detector = LogicalContradictionDetector(report_infeasible_branches=report_infeasible_branches)

    detector.register_rule(RangeContradictionRule())
    detector.register_rule(ParityContradictionRule())
    detector.register_rule(ModularContradictionRule())
    detector.register_rule(SelfContradictionRule())
    detector.register_rule(ArithmeticImpossibilityRule())
    detector.register_rule(EqualityContradictionRule())
    detector.register_rule(ComplementContradictionRule())

    detector.register_rule(AntisymmetryRule())
    detector.register_rule(TriangleImpossibilityRule())
    detector.register_rule(SumImpossibilityRule())
    detector.register_rule(ProductSignContradictionRule())
    detector.register_rule(GcdImpossibilityRule())

    detector.register_rule(SequentialModularRule())
    detector.register_rule(PostAssignmentContradictionRule())
    detector.register_rule(LoopInvariantViolationRule())
    detector.register_rule(NarrowingContradictionRule())
    detector.register_rule(ReturnTypeContradictionRule())

    detector.register_rule(PostconditionContradictionRule())
    detector.register_rule(PreconditionImpossibilityRule())
    detector.register_rule(ApiContractViolationRule())
    detector.register_rule(NumericRangePropagationRule())

    detector.register_rule(StateImpossibilityRule())
    detector.register_rule(ResourceStateContradictionRule())
    detector.register_rule(ConcurrencyContradictionRule())

    return detector


__all__ = ["LogicalContradictionDetector", "create_logic_detector"]
