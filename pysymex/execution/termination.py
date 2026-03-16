"""Termination analysis using ranking functions.

Provides:
- TerminationStatus: Enum of possible termination outcomes
- RankingFunction: A function mapping state to a well-ordered value
- TerminationProof: Result of a termination analysis attempt
- TerminationAnalyzer: Synthesises/verifies ranking functions via Z3
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import cast

import z3

from pysymex.analysis.contracts import ContractCompiler

logger = logging.getLogger(__name__)


class TerminationStatus(Enum):
    """Result of termination analysis."""

    TERMINATES = auto()
    NON_TERMINATING = auto()
    UNKNOWN = auto()
    BOUNDED = auto()


@dataclass
class RankingFunction:
    """A mathematical ranking function used to candidate termination proofs.

    In symbolic execution, a loop is proven to terminate if we can synthesize
    or verify a function `r(state)` that satisfies the following properties:
    1. Boundedness: `r(state) >= 0` for all states satisfying the loop condition.
    2. Strict Monotonicity: `r(state') < r(state)` where `state'` is the state
       after exactly one iteration of the loop body.

    If such a function exists, the loop cannot execute infinitely because the
    well-ordered nature of the ranking prevents an infinite descending chain.
    """

    name: str
    expression: str
    z3_expr: z3.ExprRef | None = None
    variables: list[str] = field(default_factory=list[str])

    def compile(self, symbols: dict[str, z3.ExprRef]) -> z3.ArithRef:
        """Compile to Z3 expression."""
        if self.z3_expr is not None:
            return cast("z3.ArithRef", self.z3_expr)
        self.z3_expr = ContractCompiler.compile_expression(self.expression, symbols)
        return cast("z3.ArithRef", self.z3_expr)


@dataclass
class TerminationProof:
    """Result of termination analysis."""

    status: TerminationStatus
    ranking_function: RankingFunction | None = None
    bound: int | None = None
    counterexample: dict[str, object] | None = None
    message: str = ""


class TerminationAnalyzer:
    """Formal verification engine for loop termination and ranking synthesis.

    This analyzer uses Z3 to either verify a user-provided ranking function
    or attempt to automatically synthesize one from the symbolic effects of
    a loop body. It handles linear arithmetic ranking functions and supports
    interrogation of counterexamples when a proof attempt fails.
    """

    def __init__(self, timeout_ms: int = 5000):
        self.timeout_ms = timeout_ms
        self._solver = z3.Solver()
        self._solver.set("timeout", timeout_ms)

    def check_termination(
        self,
        loop_condition: z3.BoolRef,
        loop_body_effect: dict[str, z3.ExprRef],
        symbols: dict[str, z3.ExprRef],
        ranking: RankingFunction | None = None,
    ) -> TerminationProof:
        """Check if a loop terminates.

        Args:
            loop_condition: Z3 expression for loop condition
            loop_body_effect: Mapping of variables to their values after one iteration
            symbols: Current symbolic variables
            ranking: Optional ranking function to try

        Returns:
            TerminationProof with status and details
        """
        self._solver.reset()
        if ranking is not None:
            return self._verify_ranking_function(loop_condition, loop_body_effect, symbols, ranking)
        return self._synthesize_ranking(loop_condition, loop_body_effect, symbols)

    def _verify_ranking_function(
        self,
        loop_condition: z3.BoolRef,
        loop_body_effect: dict[str, z3.ExprRef],
        symbols: dict[str, z3.ExprRef],
        ranking: RankingFunction,
    ) -> TerminationProof:
        """Verify that a ranking function proves termination."""
        self._solver.reset()
        r = ranking.z3_expr if ranking.z3_expr is not None else ranking.compile(symbols)
        substitutions: list[tuple[z3.ExprRef, z3.ExprRef]] = []
        for name, var in symbols.items():
            if name in loop_body_effect:
                substitutions.append((var, loop_body_effect[name]))
        if substitutions:
            r_prime = z3.substitute(r, substitutions)
        else:
            r_prime = r
        self._solver.push()
        self._solver.add(loop_condition)
        self._solver.add(r < 0)
        result = self._solver.check()
        if result == z3.sat:
            model = self._solver.model()
            counterexample = self._extract_values(model, symbols)
            self._solver.pop()
            return TerminationProof(
                status=TerminationStatus.UNKNOWN,
                ranking_function=ranking,
                counterexample=counterexample,
                message=f"Ranking function can be negative: {ranking .expression }",
            )
        self._solver.pop()
        check1_proved = result == z3.unsat
        self._solver.push()
        self._solver.add(loop_condition)
        self._solver.add(r_prime >= r)
        result = self._solver.check()
        if result == z3.sat:
            model = self._solver.model()
            counterexample = self._extract_values(model, symbols)
            self._solver.pop()
            return TerminationProof(
                status=TerminationStatus.UNKNOWN,
                ranking_function=ranking,
                counterexample=counterexample,
                message="Ranking function not strictly decreasing",
            )
        self._solver.pop()
        if result == z3.unsat and check1_proved:
            return TerminationProof(
                status=TerminationStatus.TERMINATES,
                ranking_function=ranking,
                message=f"Termination proven with ranking function: {ranking .expression }",
            )
        return TerminationProof(
            status=TerminationStatus.UNKNOWN,
            ranking_function=ranking,
            message="Could not verify ranking function (timeout)",
        )

    def _synthesize_ranking(
        self,
        loop_condition: z3.BoolRef,
        loop_body_effect: dict[str, z3.ExprRef],
        symbols: dict[str, z3.ExprRef],
    ) -> TerminationProof:
        """Try to synthesize a simple ranking function."""
        for name, var in symbols.items():
            if not isinstance(var, z3.ArithRef):
                continue
            if name in loop_body_effect:
                new_val = loop_body_effect[name]
                self._solver.reset()
                self._solver.add(loop_condition)
                self._solver.add(new_val >= var)
                if self._solver.check() == z3.unsat:
                    self._solver.reset()
                    self._solver.add(loop_condition)
                    self._solver.add(var < 0)
                    if self._solver.check() == z3.unsat:
                        ranking = RankingFunction(
                            name=f"rank_{name }",
                            expression=name,
                            z3_expr=var,
                            variables=[name],
                        )
                        return TerminationProof(
                            status=TerminationStatus.TERMINATES,
                            ranking_function=ranking,
                            message=f"Termination proven: {name } decreases and is bounded",
                        )
        return TerminationProof(
            status=TerminationStatus.UNKNOWN, message="Could not synthesize ranking function"
        )

    def _extract_values(
        self,
        model: z3.ModelRef,
        symbols: dict[str, z3.ExprRef],
    ) -> dict[str, object]:
        """Extract variable values from Z3 model."""
        result: dict[str, object] = {}
        for name, var in symbols.items():
            try:
                val = model.eval(var, model_completion=True)
                if z3.is_int_value(val):
                    result[name] = val.as_long()
                else:
                    result[name] = str(val)
            except z3.Z3Exception:
                logger.debug("Failed to evaluate model variable %s", name, exc_info=True)
        return result
