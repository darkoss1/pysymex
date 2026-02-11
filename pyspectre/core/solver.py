"""Z3 Solver wrapper for PySpectre.
This module provides a high-level interface to the Z3 theorem prover,
with caching, incremental solving, and model extraction utilities.
"""

from __future__ import annotations
from dataclasses import dataclass
from functools import lru_cache
from typing import Any
import z3


@dataclass
class SolverResult:
    """Result of a satisfiability check."""

    is_sat: bool
    is_unsat: bool
    is_unknown: bool
    model: z3.ModelRef | None = None

    @staticmethod
    def sat(model: z3.ModelRef) -> SolverResult:
        return SolverResult(is_sat=True, is_unsat=False, is_unknown=False, model=model)

    @staticmethod
    def unsat() -> SolverResult:
        return SolverResult(is_sat=False, is_unsat=True, is_unknown=False)

    @staticmethod
    def unknown() -> SolverResult:
        return SolverResult(is_sat=False, is_unsat=False, is_unknown=True)


class ShadowSolver:
    """High-level Z3 solver wrapper with caching and utilities.
    This class provides:
    - Incremental constraint solving with push/pop
    - Result caching for repeated queries
    - Model extraction and formatting
    - Timeout handling
    """

    def __init__(self, timeout_ms: int = 10000) -> None:
        """Initialize the solver.
        Args:
            timeout_ms: Solver timeout in milliseconds (default: 10s).
        """
        self._solver = z3.Solver()
        self._solver.set("timeout", timeout_ms)
        self._cache: dict[int, SolverResult] = {}
        self._query_count = 0
        self._cache_hits = 0

    def reset(self) -> None:
        """Reset the solver state."""
        self._solver.reset()
        self._cache.clear()

    def push(self) -> None:
        """Push a new constraint scope."""
        self._solver.push()

    def pop(self) -> None:
        """Pop the current constraint scope."""
        self._solver.pop()

    def add(self, *constraints: z3.BoolRef) -> None:
        """Add constraints to the solver."""
        self._solver.add(*constraints)

    def check(self, *assumptions: z3.BoolRef) -> SolverResult:
        """Check satisfiability.
        Args:
            assumptions: Additional assumptions for this check only.
        Returns:
            SolverResult indicating sat/unsat/unknown with optional model.
        """
        self._query_count += 1
        result = self._solver.check(*assumptions)
        if result == z3.sat:
            return SolverResult.sat(self._solver.model())
        elif result == z3.unsat:
            return SolverResult.unsat()
        else:
            return SolverResult.unknown()

    def is_sat(self, constraints: list[z3.BoolRef]) -> bool:
        """Check if constraints are satisfiable.
        Args:
            constraints: List of Z3 boolean constraints.
        Returns:
            True if satisfiable, False otherwise.
        """
        cache_key = hash(tuple(str(c) for c in constraints))
        if cache_key in self._cache:
            self._cache_hits += 1
            return self._cache[cache_key].is_sat
        self._solver.push()
        self._solver.add(constraints)
        result = self._solver.check()
        self._solver.pop()
        is_sat = result == z3.sat
        if is_sat:
            self._cache[cache_key] = SolverResult(is_sat=True, is_unsat=False, is_unknown=False)
        else:
            self._cache[cache_key] = SolverResult.unsat()
        return is_sat

    def get_model(self, constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
        """Get a satisfying model for the constraints.
        Args:
            constraints: List of Z3 boolean constraints.
        Returns:
            A Z3 model if satisfiable, None otherwise.
        """
        self._solver.push()
        self._solver.add(constraints)
        result = self._solver.check()
        model = None
        if result == z3.sat:
            model = self._solver.model()
        self._solver.pop()
        return model

    def get_model_string(self, constraints: list[z3.BoolRef]) -> str | None:
        """Get a string representation of a satisfying model.
        Args:
            constraints: List of Z3 boolean constraints.
        Returns:
            String representation of the model, or None if unsatisfiable.
        """
        model = self.get_model(constraints)
        if model is not None:
            return str(model)
        return None

    def extract_counterexample(
        self,
        constraints: list[z3.BoolRef],
        variables: list[str] | None = None,
    ) -> dict[str, Any]:
        """Extract a counterexample as a dictionary.
        Args:
            constraints: List of Z3 boolean constraints.
            variables: Optional list of variable names to extract.
        Returns:
            Dictionary mapping variable names to concrete values.
        """
        model = self.get_model(constraints)
        if model is None:
            return {}
        result: dict[str, Any] = {}
        for decl in model.decls():
            name = decl.name()
            value = model[decl]
            if name.endswith("_int"):
                base = name[:-4]
                result.setdefault(base, {})["int"] = value
            elif name.endswith("_bool"):
                base = name[:-5]
                result.setdefault(base, {})["bool"] = value
            elif name.endswith("_is_int"):
                base = name[:-7]
                result.setdefault(base, {})["is_int"] = value
            elif name.endswith("_is_bool"):
                base = name[:-8]
                result.setdefault(base, {})["is_bool"] = value
            elif name.endswith("_str"):
                base = name[:-4]
                result.setdefault(base, {})["str"] = value
            elif name.endswith("_len"):
                base = name[:-4]
                result.setdefault(base, {})["len"] = value
            else:
                result[name] = {"value": value}
        formatted: dict[str, Any] = {}
        for var, info in result.items():
            if isinstance(info, dict):
                if info.get("is_int") == z3.BoolVal(True) or str(info.get("is_int")) == "True":
                    formatted[var] = {"type": "int", "value": info.get("int")}
                elif info.get("is_bool") == z3.BoolVal(True) or str(info.get("is_bool")) == "True":
                    formatted[var] = {"type": "bool", "value": info.get("bool")}
                elif "str" in info:
                    formatted[var] = {"type": "str", "value": info.get("str")}
                elif "int" in info:
                    formatted[var] = {"type": "int", "value": info.get("int")}
                else:
                    formatted[var] = {"type": "unknown", "value": info}
            else:
                formatted[var] = {"type": "unknown", "value": info}
        return formatted

    def implies(self, antecedent: z3.BoolRef, consequent: z3.BoolRef) -> bool:
        """Check if antecedent implies consequent.
        Args:
            antecedent: The assumption.
            consequent: The conclusion.
        Returns:
            True if antecedent => consequent is valid.
        """
        solver = z3.Solver()
        solver.add(antecedent, z3.Not(consequent))
        return solver.check() == z3.unsat

    def simplify(self, expr: z3.ExprRef) -> z3.ExprRef:
        """Simplify a Z3 expression."""
        return z3.simplify(expr)

    def get_stats(self) -> dict[str, int]:
        """Get solver statistics."""
        return {
            "queries": self._query_count,
            "cache_hits": self._cache_hits,
            "cache_size": len(self._cache),
        }

    def __repr__(self) -> str:
        return f"ShadowSolver(queries={self._query_count}, cache_hits={self._cache_hits})"


def is_satisfiable(constraints: tuple[z3.BoolRef, ...] | list[z3.BoolRef]) -> bool:
    """Check if a list of constraints is satisfiable."""
    if isinstance(constraints, list):
        constraints = tuple(constraints)
    return _is_satisfiable_cached(constraints)


@lru_cache(maxsize=128)
def _is_satisfiable_cached(constraints: tuple[z3.BoolRef, ...]) -> bool:
    """Cached implementation of satisfiability check."""
    solver = z3.Solver()
    solver.add(constraints)
    return solver.check() == z3.sat


def get_model(constraints: tuple[z3.BoolRef, ...] | list[z3.BoolRef]) -> z3.ModelRef | None:
    """Get a Z3 model for satisfiable constraints."""
    if isinstance(constraints, list):
        constraints = tuple(constraints)
    return _get_model_cached(constraints)


@lru_cache(maxsize=128)
def _get_model_cached(constraints: tuple[z3.BoolRef, ...]) -> z3.ModelRef | None:
    """Cached implementation of get_model."""
    solver = z3.Solver()
    solver.add(constraints)
    if solver.check() == z3.sat:
        return solver.model()
    return None


def get_model_string(constraints: list[z3.BoolRef]) -> str | None:
    """Get a model string for satisfiable constraints."""
    model = get_model(constraints)
    return str(model) if model else None


@lru_cache(maxsize=128)
def prove(claim: z3.BoolRef) -> bool:
    """Prove that a claim is always true."""
    solver = z3.Solver()
    solver.add(z3.Not(claim))
    return solver.check() == z3.unsat
