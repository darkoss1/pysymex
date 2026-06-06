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

"""Ranking-function checks over caller-supplied symbolic loop transitions."""

from __future__ import annotations

import ast
from pysymex.logger import get_logger
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import cast

import z3

from pysymex.core.solver.constraints.hashing import get_int_val, get_real_val
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.solver.engine.models import z3_value_to_python

logger = get_logger(__name__)


class _RankingExpressionTranslator(ast.NodeVisitor):
    """Translate a small arithmetic AST subset into Z3 without host evaluation.

    Limitations:
        ``//`` is encoded using Z3 arithmetic division and is not an explicit
        model of Python floor-division behavior for every numeric domain.
    """

    def __init__(self, symbols: dict[str, z3.ExprRef]) -> None:
        self._symbols = symbols

    def translate(self, expression: str) -> z3.ArithRef:
        try:
            tree = ast.parse(expression, mode="eval")
        except SyntaxError as exc:
            raise ValueError(f"Invalid ranking expression syntax: {expression!r}") from exc
        translated = self.visit(tree.body)
        if not isinstance(translated, z3.ArithRef):
            raise ValueError("Ranking expression must produce an arithmetic Z3 expression")
        return translated

    def visit_Name(self, node: ast.Name) -> z3.ExprRef:
        try:
            return self._symbols[node.id]
        except KeyError as exc:
            raise ValueError(f"Unknown ranking variable: {node.id}") from exc

    def visit_Constant(self, node: ast.Constant) -> z3.ExprRef:
        value = node.value
        if isinstance(value, bool):
            raise ValueError("Boolean constants are not valid ranking expressions")
        if isinstance(value, int):
            return get_int_val(value)
        if isinstance(value, float):
            return get_real_val(value)
        raise ValueError(f"Unsupported ranking constant type: {type(value).__name__}")

    def visit_UnaryOp(self, node: ast.UnaryOp) -> z3.ExprRef:
        operand = self._arith(node.operand)
        if isinstance(node.op, ast.USub):
            return -operand
        if isinstance(node.op, ast.UAdd):
            return operand
        raise ValueError(f"Unsupported ranking unary operator: {type(node.op).__name__}")

    def visit_BinOp(self, node: ast.BinOp) -> z3.ExprRef:
        left = self._arith(node.left)
        right = self._arith(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Div):
            return left / right
        if isinstance(node.op, ast.FloorDiv):
            return left / right
        if isinstance(node.op, ast.Mod):
            return left % right
        raise ValueError(f"Unsupported ranking binary operator: {type(node.op).__name__}")

    def generic_visit(self, node: ast.AST) -> z3.ExprRef:
        raise ValueError(f"Unsupported ranking expression node: {type(node).__name__}")

    def _arith(self, node: ast.AST) -> z3.ArithRef:
        value = self.visit(node)
        if not isinstance(value, z3.ArithRef):
            raise ValueError("Ranking expression operand must be arithmetic")
        return value


class TerminationStatus(Enum):
    """Recorded result category for a ranking-function analysis attempt."""

    TERMINATES = auto()
    NON_TERMINATING = auto()
    UNKNOWN = auto()
    BOUNDED = auto()


@dataclass
class RankingFunction:
    """Candidate arithmetic measure for a supplied symbolic loop transition.

    The analyzer attempts to prove non-negativity under the loop condition and
    strict decrease under the supplied one-iteration substitutions.
    """

    name: str
    expression: str
    z3_expr: z3.ExprRef | None = None
    variables: list[str] = field(default_factory=list[str])

    def compile(self, symbols: dict[str, z3.ExprRef]) -> z3.ArithRef:
        """Compile and cache this expression using the supplied symbol mapping.

        Args:
            symbols: Symbol dictionary mapping variable names to Z3 expressions.

        Returns:
            The compiled Z3 arithmetic expression.

        Raises:
            ValueError: If compilation fails due to unknown variables or syntax errors.

        Limitations:
            Once cached, subsequent calls reuse ``z3_expr`` without rebinding
            it to a different ``symbols`` mapping.
        """
        if self.z3_expr is not None:
            return cast("z3.ArithRef", self.z3_expr)
        compiled = _RankingExpressionTranslator(symbols).translate(self.expression)
        self.z3_expr = compiled
        return compiled


@dataclass
class TerminationProof:
    """Recorded proof attempt, optional witness, bound, and explanation."""

    status: TerminationStatus
    ranking_function: RankingFunction | None = None
    bound: int | None = None
    counterexample: dict[str, object] | None = None
    message: str = ""


class TerminationAnalyzer:
    """Check simple ranking candidates for a supplied symbolic transition.

    The analyzer uses Z3 over ``loop_condition`` and ``loop_body_effect`` as
    supplied by its caller. Automatic synthesis tries only single arithmetic
    symbols that are strictly decreasing and bounded below.

    Limitations:
        It does not independently extract or validate loop-body semantics from
        Python bytecode, and failed or inconclusive proof attempts are reported
        as ``UNKNOWN`` rather than non-termination.
    """

    def __init__(self, timeout_ms: int = 5000) -> None:
        self.timeout_ms = timeout_ms
        self.solver = IncrementalSolver(timeout_ms=timeout_ms)

    def check_termination(
        self,
        loop_condition: z3.BoolRef,
        loop_body_effect: dict[str, z3.ExprRef],
        symbols: dict[str, z3.ExprRef],
        ranking: RankingFunction | None = None,
    ) -> TerminationProof:
        """Attempt a supplied or synthesized ranking proof for one loop model.

        If a specific ranking function is supplied, the analyzer will attempt to verify
        its boundedness and strict decrease. Otherwise, it will try to automatically
        synthesize a ranking function.

        Args:
            loop_condition: Encoded condition under which iteration continues.
            loop_body_effect: Caller-supplied post-iteration expressions.
            symbols: Current symbolic variables referenced by candidates.
            ranking: Optional candidate ranking function to verify.

        Returns:
            A proof attempt result; ``TERMINATES`` concerns the supplied
            transition encoding, while inconclusive cases return ``UNKNOWN``.

        Limitations:
            It does not independently extract or validate loop-body semantics from
            Python bytecode. Inconclusive proof attempts return UNKNOWN.
        """
        self.solver.reset()
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
        """Check boundedness and strict decrease of ``ranking`` in the encoding.

        Args:
            loop_condition: The loop continuation condition.
            loop_body_effect: Dictionary representing updates to loop variables.
            symbols: Symbolic variables available in the scope.
            ranking: The candidate ranking function to check.

        Returns:
            A TerminationProof indicating success or failure with counterexample.
        """
        self.solver.reset()
        try:
            r = ranking.z3_expr if ranking.z3_expr is not None else ranking.compile(symbols)
        except (TypeError, ValueError, z3.Z3Exception) as exc:
            return TerminationProof(
                status=TerminationStatus.UNKNOWN,
                ranking_function=ranking,
                message=f"Ranking function could not be compiled: {exc}",
            )
        substitutions: list[tuple[z3.ExprRef, z3.ExprRef]] = []
        for name, var in symbols.items():
            if name in loop_body_effect:
                substitutions.append((var, loop_body_effect[name]))
        if substitutions:
            r_prime = z3.substitute(r, substitutions)
        else:
            r_prime = r
        self.solver.push()
        self.solver.add(loop_condition)
        self.solver.add(r < 0)
        result = self.solver.check(need_model=True)
        if result.is_sat and result.model is not None:
            model = result.model
            counterexample = self._extract_values(model, symbols)
            self.solver.pop()
            return TerminationProof(
                status=TerminationStatus.UNKNOWN,
                ranking_function=ranking,
                counterexample=counterexample,
                message=f"Ranking function can be negative: {ranking.expression}",
            )
        self.solver.pop()
        check1_proved = result.is_unsat
        self.solver.push()
        self.solver.add(loop_condition)
        self.solver.add(r_prime >= r)
        result = self.solver.check(need_model=True)
        if result.is_sat and result.model is not None:
            model = result.model
            counterexample = self._extract_values(model, symbols)
            self.solver.pop()
            return TerminationProof(
                status=TerminationStatus.UNKNOWN,
                ranking_function=ranking,
                counterexample=counterexample,
                message="Ranking function not strictly decreasing",
            )
        self.solver.pop()
        if result.is_unsat and check1_proved:
            return TerminationProof(
                status=TerminationStatus.TERMINATES,
                ranking_function=ranking,
                message=f"Termination proven with ranking function: {ranking.expression}",
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
        """Try each arithmetic symbol as a one-variable decreasing ranking.

        Args:
            loop_condition: The loop continuation condition.
            loop_body_effect: Dictionary of updates to loop variables.
            symbols: Available symbolic variables to test as ranking functions.

        Returns:
            A TerminationProof with status TERMINATES if a decreasing and bounded symbol is found.
        """
        for name, var in symbols.items():
            if not isinstance(var, z3.ArithRef):
                continue
            if name in loop_body_effect:
                new_val = loop_body_effect[name]
                self.solver.reset()
                self.solver.add(loop_condition)
                self.solver.add(new_val >= var)
                if self.solver.check().is_unsat:
                    self.solver.reset()
                    self.solver.add(loop_condition)
                    self.solver.add(var < 0)
                    if self.solver.check().is_unsat:
                        ranking = RankingFunction(
                            name=f"rank_{name}",
                            expression=name,
                            z3_expr=var,
                            variables=[name],
                        )
                        return TerminationProof(
                            status=TerminationStatus.TERMINATES,
                            ranking_function=ranking,
                            message=f"Termination proven: {name} decreases and is bounded",
                        )
        return TerminationProof(
            status=TerminationStatus.UNKNOWN, message="Could not synthesize ranking function"
        )

    def _extract_values(
        self,
        model: z3.ModelRef,
        symbols: dict[str, z3.ExprRef],
    ) -> dict[str, object]:
        """Format available model values for counterexample diagnostics.

        Args:
            model: The Z3 model to evaluate variables against.
            symbols: Dictionary of symbolic variables to extract values for.

        Returns:
            A dictionary mapping variable names to their Python-equivalent values.
        """
        result: dict[str, object] = {}
        for name, var in symbols.items():
            try:
                val = model.eval(var, model_completion=True)
                result[name] = z3_value_to_python(val)
            except z3.Z3Exception:
                logger.debug("Failed to evaluate model variable %s", name, exc_info=True)
        return result
