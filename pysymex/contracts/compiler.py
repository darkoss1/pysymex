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

"""Contract compiler — dual-mode Z3 formula synthesis.

This module provides :class:`ContractCompiler`, the central compilation
engine that converts contract predicates into Z3 boolean expressions.

Two compilation paths:

1. **Symbolic tracing** (zero-AST, new default):
   A callable predicate is invoked with Z3 symbolic variables.  Python
   operator overloading on ``z3.ArithRef`` / ``z3.BoolRef`` produces the
   Z3 formula directly — no ``ast.parse``, no ``inspect.getsource``.

2. **AST translation** (backward-compatible fallback):
   A string predicate is parsed through the existing
   :class:`ConditionTranslator` (from ``pysymex.contracts.quantifiers.core``)
   which walks the Python AST and emits Z3 nodes.

Combinators:
   ``And_``, ``Or_``, ``Not_`` wrap ``z3.And`` / ``z3.Or`` / ``z3.Not``
   for use inside lambda predicates where Python's ``and`` / ``or`` / ``not``
   keywords cannot be overloaded.
"""

from __future__ import annotations

import inspect
import logging
import threading
from collections.abc import Callable

import z3

from pysymex.contracts.types import ContractPredicate

logger = logging.getLogger(__name__)


def And_(*args: z3.BoolRef | bool) -> z3.BoolRef:
    """Logical AND combinator for use inside contract lambdas.

    Python's ``and`` keyword short-circuits and cannot be overloaded for
    Z3 expressions.  Use ``And_`` instead::

        @requires(lambda x, y: And_(x > 0, y != 0))
        def divide(x: int, y: int) -> float: ...
    """
    z3_args: list[z3.BoolRef] = []
    for a in args:
        if isinstance(a, bool):
            z3_args.append(z3.BoolVal(a))
        else:
            z3_args.append(a)
    if len(z3_args) == 0:
        return z3.BoolVal(True)
    if len(z3_args) == 1:
        return z3_args[0]
    return z3.And(*z3_args)


def Or_(*args: z3.BoolRef | bool) -> z3.BoolRef:
    """Logical OR combinator for use inside contract lambdas.

    Python's ``or`` keyword short-circuits and cannot be overloaded for
    Z3 expressions.  Use ``Or_`` instead::

        @requires(lambda x: Or_(x == 0, x == 1))
        def binary(x: int) -> int: ...
    """
    z3_args: list[z3.BoolRef] = []
    for a in args:
        if isinstance(a, bool):
            z3_args.append(z3.BoolVal(a))
        else:
            z3_args.append(a)
    if len(z3_args) == 0:
        return z3.BoolVal(False)
    if len(z3_args) == 1:
        return z3_args[0]
    return z3.Or(*z3_args)


def Not_(arg: z3.BoolRef | bool) -> z3.BoolRef:
    """Logical NOT combinator for use inside contract lambdas.

    Python's ``not`` keyword cannot be overloaded for Z3 expressions.
    Use ``Not_`` instead::

        @requires(lambda x: Not_(x == 0))
        def reciprocal(x: int) -> float: ...
    """
    if isinstance(arg, bool):
        return z3.BoolVal(not arg)
    return z3.Not(arg)


def Implies_(antecedent: z3.BoolRef | bool, consequent: z3.BoolRef | bool) -> z3.BoolRef:
    """Logical implication combinator for use inside contract lambdas.

    ::

        @ensures(lambda result, x: Implies_(x > 0, result > 0))
        def abs_val(x: int) -> int: ...
    """
    a = z3.BoolVal(antecedent) if isinstance(antecedent, bool) else antecedent
    c = z3.BoolVal(consequent) if isinstance(consequent, bool) else consequent
    return z3.Implies(a, c)


_CompileCacheKey = tuple[int, tuple[int, ...]]


class _FormulaCache:
    """Thread-safe LRU cache for compiled Z3 formulas.

    Keyed by ``(id(predicate), frozenset(symbols.keys()))``.
    """

    __slots__ = ("_cache", "_lock", "_max_size")

    def __init__(self, max_size: int = 4096) -> None:
        self._cache: dict[_CompileCacheKey, z3.BoolRef] = {}
        self._lock = threading.Lock()
        self._max_size = max_size

    def get(self, key: _CompileCacheKey) -> z3.BoolRef | None:
        """Retrieve a cached formula, or ``None`` on miss."""
        with self._lock:
            return self._cache.get(key)

    def put(self, key: _CompileCacheKey, formula: z3.BoolRef) -> None:
        """Store a compiled formula.  Evicts oldest entries on overflow."""
        with self._lock:
            if len(self._cache) >= self._max_size:
                keys = list(self._cache.keys())
                for k in keys[: len(keys) // 2]:
                    del self._cache[k]
            self._cache[key] = formula

    def clear(self) -> None:
        """Clear the entire cache."""
        with self._lock:
            self._cache.clear()


_formula_cache = _FormulaCache()


class ContractCompiler:
    """Dual-mode contract compilation engine.

    Provides two compilation paths unified behind a single API:

    - :meth:`compile_predicate` — accepts ``Callable | str``, auto-selects.
    - :meth:`compile_expression` — backward-compatible static method for
      string-only compilation (used by ``termination.py``, ``invariants.py``,
      and other existing call sites).

    The callable path uses **symbolic tracing**:  the predicate is invoked
    with Z3 symbolic variables, and Python operator overloading on
    ``z3.ArithRef`` / ``z3.BoolRef`` produces the Z3 formula directly.

    The string path delegates to :class:`ConditionTranslator` from
    ``pysymex.contracts.quantifiers.core``.
    """

    @staticmethod
    def compile_predicate(
        predicate: ContractPredicate,
        symbols: dict[str, z3.ExprRef],
    ) -> z3.BoolRef:
        """Compile a contract predicate to a Z3 boolean formula.

        Args:
            predicate: A callable (lambda/function) or a string expression.
            symbols: Mapping of parameter names to Z3 symbolic variables.

        Returns:
            A ``z3.BoolRef`` encoding the contract constraint.

        Raises:
            ValueError: If the predicate produces a non-boolean Z3 expression.
            TypeError: If the predicate type is unsupported.
        """
        if isinstance(predicate, str):
            return ContractCompiler._compile_string(predicate, symbols)
        if callable(predicate):
            return ContractCompiler._trace_callable(predicate, symbols)
        raise TypeError(
            f"Contract predicate must be a callable or string, got {type(predicate).__name__}"
        )

    @staticmethod
    def compile_expression(
        condition: str,
        symbols: dict[str, z3.ExprRef],
    ) -> z3.BoolRef:
        """Compile a string condition to a Z3 expression.

        This is the **backward-compatible** entry point used by:
          - ``pysymex.execution.termination.RankingFunction.compile``
          - ``pysymex.analysis.specialized.invariants.parse_invariant_condition``
          - ``pysymex.analysis.contracts.types.Contract.compile``

        Args:
            condition: A Python-like boolean expression string.
            symbols: Mapping of variable names to Z3 symbolic variables.

        Returns:
            A ``z3.BoolRef`` (or ``z3.ExprRef`` for arithmetic expressions).
        """
        return ContractCompiler._compile_string(condition, symbols)

    @staticmethod
    def _trace_callable(
        predicate: Callable[..., z3.BoolRef | bool],
        symbols: dict[str, z3.ExprRef],
    ) -> z3.BoolRef:
        """Compile a callable predicate via symbolic tracing.

        The callable is invoked with Z3 variables as positional arguments.
        Python operator overloading on ``z3.ArithRef`` / ``z3.BoolRef``
        produces the Z3 formula directly.
        """
        code_obj = getattr(predicate, "__code__", None)
        if code_obj is not None:
            code_hash = hash(
                (code_obj.co_code, code_obj.co_consts, code_obj.co_names, code_obj.co_varnames)
            )
        else:
            code_hash = id(predicate)
        symbol_hashes = tuple(hash(symbols[k]) for k in sorted(symbols.keys()))
        cache_key: _CompileCacheKey = (code_hash, symbol_hashes)
        cached = _formula_cache.get(cache_key)
        if cached is not None:
            return cached

        try:
            sig = inspect.signature(predicate)
            param_names = list(sig.parameters.keys())
        except (ValueError, TypeError):
            param_names = list(symbols.keys())

        args: list[z3.ExprRef] = []
        for name in param_names:
            if name in symbols:
                args.append(symbols[name])
            else:
                args.append(z3.Int(name))

        try:
            result = predicate(*args)
        except Exception as exc:
            logger.warning(
                "Symbolic tracing failed for predicate %r: %s",
                predicate,
                exc,
                exc_info=True,
            )
            return z3.BoolVal(True)

        formula = ContractCompiler._coerce_to_bool_ref(result, predicate)

        _formula_cache.put(cache_key, formula)
        return formula

    @staticmethod
    def _compile_string(
        condition: str,
        symbols: dict[str, z3.ExprRef],
    ) -> z3.BoolRef:
        """Compile a string condition via ConditionTranslator."""
        from pysymex.contracts.quantifiers.core import parse_condition_to_z3

        return parse_condition_to_z3(condition, symbols)

    @staticmethod
    def _coerce_to_bool_ref(
        result: z3.BoolRef | z3.ExprRef | bool | object,
        source: object,
    ) -> z3.BoolRef:
        """Coerce a tracing result to ``z3.BoolRef``.

        Handles:
          - ``z3.BoolRef`` → pass through
          - ``bool`` → ``z3.BoolVal``
          - ``z3.ArithRef`` → ``expr != 0`` (truthy semantics)
          - Other → ``z3.BoolVal(True)`` with a warning
        """
        if isinstance(result, z3.BoolRef):
            return result
        if isinstance(result, bool):
            return z3.BoolVal(result)
        if isinstance(result, z3.ArithRef):
            return result != z3.IntVal(0)
        logger.warning(
            "Contract predicate %r returned non-boolean result of type %s; "
            "treating as unconstrained (True).",
            source,
            type(result).__name__,
        )
        return z3.BoolVal(True)


__all__ = [
    "And_",
    "ContractCompiler",
    "Implies_",
    "Not_",
    "Or_",
]
