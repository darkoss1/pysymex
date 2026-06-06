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

"""Path-feasibility helpers shared by all detector pure functions.

Provides :func:`get_model_if_satisfiable` which is the common pattern:
check SAT, obtain a model, and optionally use a cheap float-witness fast
path to avoid timeouts on IEEE-754 constraints.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterator, Sequence
import itertools
from dataclasses import dataclass
from enum import Enum, auto
from typing import cast
import weakref

import z3

from pysymex.analysis.detectors.detector.types import GetModelFn, IsSatFn
from pysymex.core.cache.control import (
    is_process_cache_disabled,
    register_process_cache_clearer,
)
from pysymex.core.constants import Z3_FALSE, Z3_TRUE
from pysymex.core.solver.constraints.hashing import get_int_val, get_string_val
from pysymex.core.solver.constraints.literals import exact_bool_literal
from pysymex.core.solver.engine.context import active_incremental_solver
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.solver.engine.queries import (
    get_model,
    get_model_result,
)
from pysymex.core.solver.engine.results import SolverResult
from pysymex.logger import get_logger

logger = get_logger(__name__)
_SOLVER_FAILURES = (z3.Z3Exception, OSError, RuntimeError, ValueError)

__all__ = [
    "detector_witness_model",
    "FeasibilityModelResult",
    "FeasibilityModelStatus",
    "get_model_if_satisfiable",
    "get_model_if_satisfiable_result",
    "hard_theory_witness_model",
    "integer_witness_model",
    "string_integer_context_truth_value",
    "string_integer_witness_model",
    "zero_float_witness_model",
]

_SMALL_INTEGER_WITNESS_CANDIDATES: tuple[int, ...] = (
    0,
    -1,
    1,
    -2,
    2,
    -3,
    3,
    -4,
    4,
    -5,
    5,
    -6,
    6,
    -7,
    7,
    -8,
    8,
)
_COMMON_INTEGER_BOUNDARIES: tuple[int, ...] = (
    -256,
    -255,
    -128,
    -127,
    127,
    128,
    255,
    256,
    -(2**31),
    -(2**31) + 1,
    2**31 - 1,
    2**31,
)
_INTEGER_WITNESS_CANDIDATES: tuple[int, ...] = tuple(
    dict.fromkeys((*_SMALL_INTEGER_WITNESS_CANDIDATES, *_COMMON_INTEGER_BOUNDARIES))
)
_INTEGER_WITNESS_PATTERN_BASE_VALUES: tuple[int, ...] = (0, 1, -1)
_MAX_INTEGER_WITNESS_SEED_VARS = 6
_MAX_INTEGER_WITNESS_PRODUCT_VARS = 3
_MAX_INTEGER_WITNESS_PRODUCT_ASSIGNMENTS = 512
_MAX_INTEGER_WITNESS_MIXED_RADIX_ASSIGNMENTS = 1024
_MAX_INTEGER_WITNESS_BOOL_VARS = 8
_MAX_INTEGER_LITERAL_CANDIDATES = 32
_MAX_INTEGER_LITERAL_ABS_VALUE = 4096
_MAX_STRING_LITERAL_CANDIDATES = 32
_MAX_STRING_WITNESS_LENGTH = 32
_BASE_STRING_WITNESS_CANDIDATES: tuple[str, ...] = (
    "0",
    "1",
    "",
    "a",
    "b",
    "ab",
    "abc",
    "z",
)
_MAX_STRING_WITNESS_STRINGS = 2
_MAX_STRING_WITNESS_PRODUCT_INTS = 3
_MAX_STRING_WITNESS_SEED_INTS = 8
_WITNESS_CONSTANTS_CACHE_MAX_ENTRIES = 128
_MAX_DETACHED_MODEL_RETRY_TIMEOUT_MS = 50


@dataclass(frozen=True, slots=True)
class _WitnessConstants:
    fp_variables: list[z3.FPRef]
    integer_variables: list[z3.ArithRef]
    string_variables: list[z3.SeqRef]
    bool_variables: list[z3.BoolRef]


_WITNESS_CONSTANTS_CACHE: OrderedDict[
    int,
    tuple[weakref.ReferenceType[z3.ExprRef], _WitnessConstants],
] = OrderedDict()
_BoolTypeSlot = tuple[z3.BoolRef, str, str]


class FeasibilityModelStatus(Enum):
    """Structured detector model-evidence outcomes."""

    SAT = auto()
    NO_SAT_EVIDENCE = auto()
    INCONCLUSIVE = auto()


@dataclass(frozen=True, slots=True)
class FeasibilityModelResult:
    """Model-backed detector feasibility evidence.

    ``NO_SAT_EVIDENCE`` means the supplied boolean callback did not establish
    a satisfiable path. It must not be presented as a proof of UNSAT unless
    the callback contract is known to make that stronger claim.
    """

    status: FeasibilityModelStatus
    model: z3.ModelRef | dict[str, object] | None = None
    reason: str | None = None

    @property
    def is_sat(self) -> bool:
        """Return whether a SAT model or witness is present."""
        return self.status is FeasibilityModelStatus.SAT

    @property
    def is_inconclusive(self) -> bool:
        """Return whether feasibility or model extraction was inconclusive."""
        return self.status is FeasibilityModelStatus.INCONCLUSIVE

    @staticmethod
    def sat(model: z3.ModelRef | dict[str, object]) -> FeasibilityModelResult:
        """Create a SAT model or concrete-witness result."""
        return FeasibilityModelResult(FeasibilityModelStatus.SAT, model)

    @staticmethod
    def no_sat_evidence(reason: str) -> FeasibilityModelResult:
        """Create a result for absent SAT evidence from the callback."""
        return FeasibilityModelResult(FeasibilityModelStatus.NO_SAT_EVIDENCE, reason=reason)

    @staticmethod
    def inconclusive(reason: str) -> FeasibilityModelResult:
        """Create an inconclusive detector feasibility result."""
        return FeasibilityModelResult(FeasibilityModelStatus.INCONCLUSIVE, reason=reason)


def zero_float_witness_model(constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
    """Return a concrete ``+0.0`` witness when it proves the full constraint SAT.

    Fast path for IEEE-754 detector formulas that may time out in the
    general solver: substitutes every uninterpreted floating-point
    constant with ``+0.0`` and checks whether the simplified formula is
    ``True``.  Returns a tiny witness model if so, ``None`` otherwise.

    Args:
        constraints: Z3 boolean constraints to probe.

    Returns:
        A minimal :class:`z3.ModelRef` assigning ``+0.0`` to all FP
        constants, or ``None`` if the fast path does not apply.
    """
    try:
        formula = z3.And(*constraints)
        return _zero_float_witness_model_from_formula(
            formula,
            _floating_point_constants(formula),
        )
    except _SOLVER_FAILURES:
        logger.debug("Float witness feasibility check failed; treating as inconclusive")
        return None


def integer_witness_model(constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
    """Return a concrete small-integer witness when substitution proves SAT.

    This is a detector-only fallback for solver-unknown queries. It does not
    infer satisfiability from ``unknown``; it enumerates a small deterministic
    set of integer assignments and accepts one only when every supplied
    constraint simplifies to ``True`` after substitution.
    """
    try:
        formula = z3.simplify(z3.And(*constraints))
        if z3.is_false(formula):
            return None
        variables = _integer_constants(formula, limit=_MAX_INTEGER_WITNESS_SEED_VARS + 1)
        return _integer_witness_model_from_formula(formula, variables)
    except _SOLVER_FAILURES:
        logger.debug("Integer witness feasibility check failed; treating as inconclusive")
    return None


def string_integer_witness_model(constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
    """Return a mixed string/int witness when concrete substitution proves SAT."""
    try:
        formula = z3.And(*constraints)
        string_variables = _string_constants(formula, limit=_MAX_STRING_WITNESS_STRINGS + 1)
        if not string_variables or len(string_variables) > _MAX_STRING_WITNESS_STRINGS:
            return None
        integer_variables = _integer_constants(formula)
        bool_variables = _bool_constants(formula)
        return _string_integer_witness_model_from_formula(
            formula,
            string_variables=string_variables,
            integer_variables=integer_variables,
            bool_variables=bool_variables,
        )
    except _SOLVER_FAILURES:
        logger.debug("String/integer witness feasibility check failed; treating as inconclusive")
    return None


def string_integer_context_truth_value(
    context_constraints: Sequence[z3.BoolRef],
    query: z3.BoolRef,
) -> bool | None:
    """Return the first deterministic string/int witness truth value for ``query``.

    This helper is for scheduling only. It uses context constraints to collect
    generated string/``ord``/``count`` variables, then substitutes deterministic
    concrete witness candidates into ``query`` alone. It does not prove branch
    feasibility and must never be used to prune a branch.
    """
    try:
        constants = _witness_constants_from_expressions((*context_constraints, query))
        if not constants.string_variables and not constants.integer_variables:
            return None
        if not constants.string_variables and not _has_string_context_integer_variables(
            constants.integer_variables
        ):
            return None
        for substitutions in _string_integer_context_substitutions(constants, query):
            simplified = z3.simplify(z3.substitute(query, *substitutions))
            if z3.is_true(simplified):
                return True
            if z3.is_false(simplified):
                return False
    except _SOLVER_FAILURES:
        logger.debug("String/integer context truth probe failed; skipping branch hint")
    return None


def detector_witness_model(constraints: list[z3.BoolRef]) -> z3.ModelRef | None:
    """Return any supported concrete detector witness for *constraints*.

    This combines the detector witness pre-checks used before general Z3
    solving so cache misses do not traverse the same formula once per witness
    family. Each returned model is still accepted only after concrete
    substitution simplifies the complete formula to ``True``.
    """
    try:
        formula = z3.simplify(z3.And(*constraints))
        if z3.is_false(formula):
            return None
        constants = _witness_constants(formula)
        witness = _zero_float_witness_model_from_formula(formula, constants.fp_variables)
        if witness is not None:
            return witness
        witness = _integer_witness_model_from_formula(
            formula,
            constants.integer_variables,
            bool_variables=constants.bool_variables,
        )
        if witness is not None:
            return witness
        return _string_integer_witness_model_from_formula(
            formula,
            string_variables=constants.string_variables,
            integer_variables=constants.integer_variables,
            bool_variables=constants.bool_variables,
        )
    except _SOLVER_FAILURES:
        logger.debug("Detector witness feasibility check failed; treating as inconclusive")
    return None


def hard_theory_witness_model(
    constraints: list[z3.BoolRef],
    *,
    include_bitvector: bool = True,
) -> z3.ModelRef | None:
    """Return a verified witness only for formulas likely to stress the solver."""
    if _constraints_include_exact_false(constraints):
        return None
    if not _constraints_include_hard_witness_theory(
        constraints,
        include_bitvector=include_bitvector,
    ):
        return None
    return detector_witness_model(constraints)


def get_model_if_satisfiable(
    constraints: list[z3.BoolRef],
    is_satisfiable_fn: IsSatFn,
    get_model_fn: GetModelFn = get_model,
    *,
    allow_witness_model: bool = True,
) -> z3.ModelRef | dict[str, object] | None:
    """Return a model if *constraints* are satisfiable, else ``None``.

    First tries the fast-path float witness; falls back to the general
    solver via *get_model_fn*. This is the compatibility wrapper around
    :func:`get_model_if_satisfiable_result`.

    Args:
        constraints: The constraint list to check.
        is_satisfiable_fn: SAT oracle callback.
        get_model_fn: Model-extraction callback.

    Returns:
        A :class:`z3.ModelRef` (or witness) on SAT, ``None`` when SAT evidence
        or model extraction is unavailable.
    """
    return get_model_if_satisfiable_result(
        constraints,
        is_satisfiable_fn,
        get_model_fn,
        allow_witness_model=allow_witness_model,
    ).model


def get_model_if_satisfiable_result(
    constraints: list[z3.BoolRef],
    is_satisfiable_fn: IsSatFn,
    get_model_fn: GetModelFn = get_model,
    *,
    allow_witness_model: bool = True,
) -> FeasibilityModelResult:
    """Return structured model evidence for satisfiable detector constraints.

    Args:
        constraints: The constraint list to check.
        is_satisfiable_fn: SAT oracle callback.
        get_model_fn: Model-extraction callback.

    Returns:
        Structured model evidence. ``SAT`` always contains a model; callback
        failures, model callback failures, and SAT-without-model results are
        ``INCONCLUSIVE``.
    """
    try:
        is_satisfiable = is_satisfiable_fn(constraints)
    except _SOLVER_FAILURES:
        logger.debug("Detector SAT callback failed; treating feasibility as inconclusive")
        return FeasibilityModelResult.inconclusive("sat_callback_failed")

    if not is_satisfiable:
        if allow_witness_model:
            witness = hard_theory_witness_model(constraints, include_bitvector=False)
            if witness is not None:
                return FeasibilityModelResult.sat(witness)
        return FeasibilityModelResult.no_sat_evidence("sat_callback_returned_false")
    if _constraints_are_exactly_true(constraints):
        return FeasibilityModelResult.sat({})
    if allow_witness_model:
        witness = zero_float_witness_model(constraints)
        if witness is not None:
            return FeasibilityModelResult.sat(witness)
    if get_model_fn is get_model and active_incremental_solver.get() is not None:
        result = _model_result_to_feasibility(get_model_result(constraints))
        if result.is_inconclusive and allow_witness_model:
            witness = hard_theory_witness_model(constraints)
            if witness is not None:
                return FeasibilityModelResult.sat(witness)
            detached_result = _model_result_to_feasibility(
                _detached_model_result_for_active_solver(constraints)
            )
            if not detached_result.is_inconclusive:
                return detached_result
        return result
    if allow_witness_model:
        witness = integer_witness_model(constraints)
        if witness is not None:
            return FeasibilityModelResult.sat(witness)
        witness = string_integer_witness_model(constraints)
        if witness is not None:
            return FeasibilityModelResult.sat(witness)
    if get_model_fn is get_model:
        result = _model_result_to_feasibility(get_model_result(constraints))
        if result.is_inconclusive and allow_witness_model:
            witness = hard_theory_witness_model(constraints)
            if witness is not None:
                return FeasibilityModelResult.sat(witness)
        return result
    try:
        model = get_model_fn(constraints)
    except _SOLVER_FAILURES:
        logger.debug("Detector model callback failed; treating feasibility as inconclusive")
        return FeasibilityModelResult.inconclusive("model_callback_failed")
    if model is None:
        logger.debug(
            "Detector SAT evidence produced no model; treating feasibility as inconclusive"
        )
        return FeasibilityModelResult.inconclusive("sat_without_model")
    return FeasibilityModelResult.sat(model)


def _model_result_to_feasibility(result: SolverResult) -> FeasibilityModelResult:
    """Convert core structured model evidence to detector feasibility evidence."""
    if result.is_sat:
        if result.model is not None:
            return FeasibilityModelResult.sat(result.model)
        logger.debug("Detector SAT model result did not include a model")
        return FeasibilityModelResult.inconclusive("sat_without_model")
    if result.is_unsat:
        return FeasibilityModelResult.no_sat_evidence("model_result_unsat")
    if result.is_unknown:
        return FeasibilityModelResult.inconclusive("model_result_unknown")
    logger.debug("Detector model result was not a recognized solver outcome")
    return FeasibilityModelResult.inconclusive("model_result_invalid")


def _detached_model_result_for_active_solver(constraints: list[z3.BoolRef]) -> SolverResult:
    """Return model evidence from a fresh solver when the active context is inconclusive."""
    if not _constraints_include_string_model_retry_context(constraints):
        return SolverResult.unknown()
    solver = active_incremental_solver.get()
    if solver is None:
        return SolverResult.unknown()
    timeout_ms = _active_solver_retry_timeout_ms(solver)
    if timeout_ms is None:
        return SolverResult.unknown()
    try:
        return IncrementalSolver(timeout_ms=timeout_ms, use_cache=False).check_sat_cached(
            constraints
        )
    except _SOLVER_FAILURES:
        logger.debug("Detached detector model retry failed; treating as inconclusive")
    return SolverResult.unknown()


def _active_solver_retry_timeout_ms(solver: object) -> int | None:
    """Return a bounded timeout for detached detector model extraction."""
    effective_timeout = getattr(solver, "_effective_timeout_ms", None)
    if not callable(effective_timeout):
        return None
    try:
        timeout_ms = effective_timeout()
    except _SOLVER_FAILURES:
        logger.debug("Could not resolve active solver timeout for detached model retry")
        return None
    if not isinstance(timeout_ms, int) or timeout_ms <= 0:
        return None
    return min(timeout_ms, _MAX_DETACHED_MODEL_RETRY_TIMEOUT_MS)


def _constraints_include_string_model_retry_context(constraints: list[z3.BoolRef]) -> bool:
    """Return whether detached retry is justified by string-model-derived slots."""
    pending: list[z3.ExprRef] = list(constraints)
    visited: set[int] = set()
    while pending:
        expression = pending.pop()
        expression_id = expression.get_id()
        if expression_id in visited:
            continue
        visited.add(expression_id)
        try:
            if expression.decl().kind() == z3.Z3_OP_UNINTERPRETED and _retry_name_matches(
                expression.decl().name()
            ):
                return True
            pending.extend(expression.children())
        except _SOLVER_FAILURES:
            logger.debug("Detached model retry context probe failed", exc_info=True)
            return False
    return False


def _retry_name_matches(name: str) -> bool:
    """Return whether a Z3 symbol name belongs to string-derived model precision."""
    if "count" in name:
        return True
    return name.startswith(
        (
            "bin_",
            "find_",
            "rfind_",
            "index_",
            "rindex_",
            "ord_",
        )
    )


def _constraints_are_exactly_true(constraints: list[z3.BoolRef]) -> bool:
    """Return whether every detector constraint is locally proved true."""
    return all(exact_bool_literal(constraint) is True for constraint in constraints)


def _constraints_include_exact_false(constraints: list[z3.BoolRef]) -> bool:
    """Return whether a conjunction is already disproved by a literal falsehood."""
    return any(exact_bool_literal(constraint) is False for constraint in constraints)


def _constraints_include_hard_witness_theory(
    constraints: list[z3.BoolRef],
    *,
    include_bitvector: bool,
) -> bool:
    """Return whether a constraint set contains theories suited for witness prechecks."""
    pending: list[z3.ExprRef] = list(constraints)
    visited: set[int] = set()
    while pending:
        expression = pending.pop()
        expression_hash = expression.hash()
        if expression_hash in visited:
            continue
        visited.add(expression_hash)
        if isinstance(expression, (z3.SeqRef, z3.FPRef, z3.ArrayRef)):
            return True
        if include_bitvector and isinstance(expression, z3.BitVecRef):
            return True
        try:
            pending.extend(expression.children())
        except _SOLVER_FAILURES:
            logger.debug("Detector hard-theory witness probe failed", exc_info=True)
            return False
    return False


def _floating_point_constants(formula: z3.ExprRef) -> list[z3.FPRef]:
    """Collect uninterpreted floating-point constant leaves from *formula*.

    Uses a non-recursive iterative traversal to avoid stack depth issues
    on large formulas.
    """
    pending: list[z3.ExprRef] = [formula]
    visited: set[int] = set()
    constants: list[z3.FPRef] = []
    while pending:
        expression = pending.pop()
        expression_hash = expression.hash()
        if expression_hash in visited:
            continue
        visited.add(expression_hash)
        if isinstance(expression, z3.FPRef) and expression.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            constants.append(expression)
            continue
        pending.extend(expression.children())
    return constants


def _witness_constants(formula: z3.ExprRef) -> _WitnessConstants:
    """Return detector witness variables, reusing collection for the same live formula."""
    if is_process_cache_disabled():
        return _collect_witness_constants(formula)

    cache_key = id(formula)
    cached_entry = _WITNESS_CONSTANTS_CACHE.get(cache_key)
    if cached_entry is not None:
        cached_formula = cached_entry[0]()
        if cached_formula is formula:
            _WITNESS_CONSTANTS_CACHE.move_to_end(cache_key)
            return cached_entry[1]
        _WITNESS_CONSTANTS_CACHE.pop(cache_key, None)

    constants = _collect_witness_constants(formula)
    _WITNESS_CONSTANTS_CACHE[cache_key] = (weakref.ref(formula), constants)
    _WITNESS_CONSTANTS_CACHE.move_to_end(cache_key)
    _prune_dead_witness_constant_entries()
    if len(_WITNESS_CONSTANTS_CACHE) > _WITNESS_CONSTANTS_CACHE_MAX_ENTRIES:
        _WITNESS_CONSTANTS_CACHE.popitem(last=False)
    return constants


def _witness_constants_from_expressions(
    expressions: Sequence[z3.ExprRef],
) -> _WitnessConstants:
    """Collect witness variables from a bounded expression sequence."""
    pending: list[z3.ExprRef] = list(expressions)
    visited: set[int] = set()
    fp_variables: list[z3.FPRef] = []
    integer_by_name: dict[str, z3.ArithRef] = {}
    string_by_name: dict[str, z3.SeqRef] = {}
    bool_by_name: dict[str, z3.BoolRef] = {}
    while pending:
        expression = pending.pop()
        expression_hash = expression.hash()
        if expression_hash in visited:
            continue
        visited.add(expression_hash)
        decl_kind = expression.decl().kind()
        if decl_kind == z3.Z3_OP_UNINTERPRETED:
            if isinstance(expression, z3.FPRef):
                fp_variables.append(expression)
                continue
            if isinstance(expression, z3.ArithRef) and expression.sort().kind() == z3.Z3_INT_SORT:
                integer_by_name[expression.decl().name()] = expression
                continue
            if isinstance(expression, z3.SeqRef) and expression.sort().kind() == z3.Z3_SEQ_SORT:
                string_by_name[expression.decl().name()] = expression
                continue
            if isinstance(expression, z3.BoolRef) and z3.is_const(expression):
                bool_by_name[expression.decl().name()] = expression
                continue
        pending.extend(expression.children())
    return _WitnessConstants(
        fp_variables=fp_variables,
        integer_variables=[integer_by_name[name] for name in sorted(integer_by_name)],
        string_variables=[string_by_name[name] for name in sorted(string_by_name)],
        bool_variables=[bool_by_name[name] for name in sorted(bool_by_name)],
    )


def _prune_dead_witness_constant_entries() -> None:
    """Drop witness-cache entries whose formula object is no longer alive."""
    dead_keys = [
        cache_key
        for cache_key, (formula_ref, _constants) in _WITNESS_CONSTANTS_CACHE.items()
        if formula_ref() is None
    ]
    for cache_key in dead_keys:
        _WITNESS_CONSTANTS_CACHE.pop(cache_key, None)


def clear_witness_constants_cache() -> None:
    """Clear process-local detector witness-variable cache entries."""
    _WITNESS_CONSTANTS_CACHE.clear()


register_process_cache_clearer(
    "analysis.detectors.witness_constants_cache",
    clear_witness_constants_cache,
)


def _collect_witness_constants(formula: z3.ExprRef) -> _WitnessConstants:
    """Collect detector witness variables from *formula* in one traversal."""
    return _witness_constants_from_expressions((formula,))


def _integer_constants(
    formula: z3.ExprRef,
    *,
    limit: int | None = None,
) -> list[z3.ArithRef]:
    """Collect uninterpreted integer constants from *formula* in stable order."""
    pending: list[z3.ExprRef] = [formula]
    visited: set[int] = set()
    constants_by_name: dict[str, z3.ArithRef] = {}
    while pending:
        expression = pending.pop()
        expression_hash = expression.hash()
        if expression_hash in visited:
            continue
        visited.add(expression_hash)
        if (
            isinstance(expression, z3.ArithRef)
            and expression.sort().kind() == z3.Z3_INT_SORT
            and expression.decl().kind() == z3.Z3_OP_UNINTERPRETED
        ):
            constants_by_name[expression.decl().name()] = expression
            if limit is not None and len(constants_by_name) >= limit:
                return [constants_by_name[name] for name in sorted(constants_by_name)]
            continue
        pending.extend(expression.children())
    return [constants_by_name[name] for name in sorted(constants_by_name)]


def _string_constants(
    formula: z3.ExprRef,
    *,
    limit: int | None = None,
) -> list[z3.SeqRef]:
    """Collect uninterpreted string constants from *formula* in stable order."""
    pending: list[z3.ExprRef] = [formula]
    visited: set[int] = set()
    constants_by_name: dict[str, z3.SeqRef] = {}
    while pending:
        expression = pending.pop()
        expression_hash = expression.hash()
        if expression_hash in visited:
            continue
        visited.add(expression_hash)
        if (
            isinstance(expression, z3.SeqRef)
            and expression.sort().kind() == z3.Z3_SEQ_SORT
            and expression.decl().kind() == z3.Z3_OP_UNINTERPRETED
        ):
            constants_by_name[expression.decl().name()] = expression
            if limit is not None and len(constants_by_name) >= limit:
                return [constants_by_name[name] for name in sorted(constants_by_name)]
            continue
        pending.extend(expression.children())
    return [constants_by_name[name] for name in sorted(constants_by_name)]


def _bool_constants(formula: z3.ExprRef) -> list[z3.BoolRef]:
    """Collect uninterpreted Boolean constants from *formula* in stable order."""
    pending: list[z3.ExprRef] = [formula]
    visited: set[int] = set()
    constants_by_name: dict[str, z3.BoolRef] = {}
    while pending:
        expression = pending.pop()
        expression_hash = expression.hash()
        if expression_hash in visited:
            continue
        visited.add(expression_hash)
        if (
            isinstance(expression, z3.BoolRef)
            and z3.is_const(expression)
            and expression.decl().kind() == z3.Z3_OP_UNINTERPRETED
        ):
            constants_by_name[expression.decl().name()] = expression
            continue
        pending.extend(expression.children())
    return [constants_by_name[name] for name in sorted(constants_by_name)]


def _integer_literal_candidates(formula: z3.ExprRef) -> tuple[int, ...]:
    """Collect bounded integer literals from a detector formula as witness candidates."""
    pending: list[z3.ExprRef] = [formula]
    visited: set[int] = set()
    values: list[int] = []
    while pending and len(values) < _MAX_INTEGER_LITERAL_CANDIDATES:
        expression = pending.pop()
        expression_hash = expression.hash()
        if expression_hash in visited:
            continue
        visited.add(expression_hash)
        if z3.is_int_value(expression):
            value = expression.as_long()
            if abs(value) > _MAX_INTEGER_LITERAL_ABS_VALUE:
                continue
            values.extend((value, -value, value - 1, value + 1))
            continue
        pending.extend(expression.children())
    return tuple(dict.fromkeys(values))


def _string_witness_candidates(formula: z3.ExprRef) -> tuple[str, ...]:
    """Return bounded string candidates derived from the detector formula."""
    candidates = [
        *_BASE_STRING_WITNESS_CANDIDATES,
        *_string_literal_candidates(formula),
        *_substring_literal_candidates(formula),
    ]
    candidates.extend(_length_shaped_string_candidates(formula, candidates))
    return tuple(
        dict.fromkeys(
            candidate for candidate in candidates if len(candidate) <= _MAX_STRING_WITNESS_LENGTH
        )
    )


def _bin_string_witness_candidates(formula: z3.ExprRef) -> tuple[str, ...]:
    """Return formula-derived ``bin(...)`` text candidates for count bridges."""
    return tuple(
        candidate
        for candidate in _string_witness_candidates(formula)
        if candidate.startswith("0b")
        and len(candidate) > 2
        and all(character in {"0", "1"} for character in candidate[2:])
    )


def _string_literal_candidates(formula: z3.ExprRef) -> tuple[str, ...]:
    """Collect concrete string literals that already appear in a formula."""
    pending: list[z3.ExprRef] = [formula]
    visited: set[int] = set()
    values: list[str] = []
    while pending and len(values) < _MAX_STRING_LITERAL_CANDIDATES:
        expression = pending.pop()
        expression_hash = expression.hash()
        if expression_hash in visited:
            continue
        visited.add(expression_hash)
        try:
            value = _z3_string_literal_value(expression)
            if value is not None:
                values.append(value)
                continue
            pending.extend(expression.children())
        except _SOLVER_FAILURES:
            logger.debug("String literal witness collection failed; skipping expression")
    return tuple(dict.fromkeys(values))


def _substring_literal_candidates(formula: z3.ExprRef) -> tuple[str, ...]:
    """Reconstruct concrete strings from contiguous ``SubString`` equalities."""
    characters_by_source: dict[str, dict[int, str]] = {}
    for constraint in _iter_conjuncts(cast("z3.BoolRef", z3.simplify(formula))):
        if not z3.is_eq(constraint):
            continue
        left, right = constraint.children()
        for source_name, offset, value in _substring_literal_assignments(left, right):
            characters = characters_by_source.setdefault(source_name, {})
            for index, character in enumerate(value, start=offset):
                characters[index] = character
        for source_name, offset, value in _substring_literal_assignments(right, left):
            characters = characters_by_source.setdefault(source_name, {})
            for index, character in enumerate(value, start=offset):
                characters[index] = character

    candidates: list[str] = []
    for characters in characters_by_source.values():
        if not characters:
            continue
        width = max(characters) + 1
        if width > _MAX_STRING_WITNESS_LENGTH:
            continue
        if set(characters) != set(range(width)):
            continue
        candidates.append("".join(characters[index] for index in range(width)))
    return tuple(dict.fromkeys(candidates))


def _substring_literal_assignments(
    left: z3.ExprRef,
    right: z3.ExprRef,
) -> Iterator[tuple[str, int, str]]:
    """Yield ``(source_name, offset, literal)`` for ``SubString(source, i, n) == text``."""
    try:
        literal = _z3_string_literal_value(right)
        if literal is None:
            return
        if left.decl().name() == "str.substr":
            source, offset_expr, length_expr = left.children()
            if not z3.is_int_value(length_expr):
                return
            length = length_expr.as_long()
        elif left.decl().name() == "str.at":
            source, offset_expr = left.children()
            length = 1
        else:
            return
        if source.decl().kind() != z3.Z3_OP_UNINTERPRETED:
            return
        if not z3.is_int_value(offset_expr):
            return
        offset = offset_expr.as_long()
    except _SOLVER_FAILURES:
        logger.debug("Substring literal witness extraction failed; skipping expression")
        return
    if offset < 0 or length < 0 or len(literal) != length:
        return
    yield (source.decl().name(), offset, literal)


def _z3_string_literal_value(expression: z3.ExprRef) -> str | None:
    try:
        if not z3.is_string_value(expression):
            return None
        return _decode_z3_string_escapes(expression.as_string())
    except _SOLVER_FAILURES:
        logger.debug("Z3 string literal decoding failed; skipping expression")
    return None


def _decode_z3_string_escapes(value: str) -> str:
    """Decode Z3 ``\\u{...}`` escapes from ``SeqRef.as_string()`` output."""
    parts: list[str] = []
    index = 0
    while index < len(value):
        if value.startswith("\\u{", index):
            end = value.find("}", index + 3)
            if end != -1:
                try:
                    parts.append(chr(int(value[index + 3 : end], 16)))
                except ValueError:
                    parts.append(value[index])
                    index += 1
                    continue
                index = end + 1
                continue
        parts.append(value[index])
        index += 1
    return "".join(parts)


def _length_shaped_string_candidates(
    formula: z3.ExprRef,
    known_candidates: list[str],
) -> tuple[str, ...]:
    """Generate small length-compatible candidates from visible length constraints."""
    lengths = _string_length_literals(formula)
    if not lengths:
        return ()
    atoms = ["a", "b", "0", "1"]
    atoms.extend(candidate[:1] for candidate in known_candidates if candidate)
    shaped: list[str] = []
    for length in lengths:
        if length < 0 or length > _MAX_STRING_WITNESS_LENGTH:
            continue
        if length == 0:
            shaped.append("")
            continue
        shaped.extend(atom * length for atom in atoms if atom)
    return tuple(dict.fromkeys(shaped))


def _string_length_literals(formula: z3.ExprRef) -> tuple[int, ...]:
    """Collect small integer literals from ``Length(text) == n`` constraints."""
    lengths: list[int] = []
    for constraint in _iter_conjuncts(cast("z3.BoolRef", z3.simplify(formula))):
        if not z3.is_eq(constraint):
            continue
        left, right = constraint.children()
        length = _string_length_literal(left, right)
        if length is not None:
            lengths.append(length)
        length = _string_length_literal(right, left)
        if length is not None:
            lengths.append(length)
    return tuple(dict.fromkeys(lengths))


def _string_length_literal(left: z3.ExprRef, right: z3.ExprRef) -> int | None:
    try:
        if left.decl().name() == "str.len" and z3.is_int_value(right):
            return right.as_long()
    except _SOLVER_FAILURES:
        logger.debug("String length witness extraction failed; skipping expression")
    return None


def _integer_witness_candidates(formula: z3.BoolRef) -> tuple[int, ...]:
    """Return deterministic bounded candidates for concrete integer witness probes."""
    return tuple(
        dict.fromkeys(
            (
                *_SMALL_INTEGER_WITNESS_CANDIDATES,
                *_integer_literal_candidates(formula),
                *_COMMON_INTEGER_BOUNDARIES,
            )
        )
    )


def _integer_pattern_assignments(variable_count: int) -> Iterator[tuple[int, ...]]:
    """Yield shape-generic low-cost assignments before bounded enumeration."""
    for value in _INTEGER_WITNESS_PATTERN_BASE_VALUES:
        yield (value,) * variable_count

    for index in range(variable_count):
        for value in _INTEGER_WITNESS_PATTERN_BASE_VALUES[1:]:
            values = [0] * variable_count
            values[index] = value
            yield tuple(values)

    if variable_count < 2:
        return

    yield tuple(0 if index % 2 == 0 else 1 for index in range(variable_count))
    yield tuple(0 if index % 2 == 0 else -1 for index in range(variable_count))
    yield tuple(0 if index % 2 == 0 else 2 for index in range(variable_count))
    yield tuple(2 if index % 2 == 0 else 0 for index in range(variable_count))
    yield tuple(0 if index % 2 == 0 else -2 for index in range(variable_count))
    yield tuple(-2 if index % 2 == 0 else 0 for index in range(variable_count))
    yield tuple(0 if index % 2 == 0 else 3 for index in range(variable_count))
    yield tuple(3 if index % 2 == 0 else 0 for index in range(variable_count))
    yield tuple(0 if index % 2 == 0 else -3 for index in range(variable_count))
    yield tuple(-3 if index % 2 == 0 else 0 for index in range(variable_count))

    if variable_count >= 4:
        for first_odd in (2, -2, 3, -3):
            for later_odd in (2, -2, 3, -3):
                values = [0] * variable_count
                for index in range(1, variable_count, 2):
                    values[index] = later_odd
                values[1] = first_odd
                yield tuple(values)

    yield tuple(range(variable_count))
    yield tuple(-index for index in range(variable_count))

    center = variable_count // 2
    yield tuple(index - center for index in range(variable_count))
    yield tuple(center - index for index in range(variable_count))


def _mixed_radix_integer_assignments(
    variable_count: int,
    candidates: tuple[int, ...],
) -> Iterator[tuple[int, ...]]:
    """Yield a deterministic prefix of the bounded candidate product."""
    if not candidates:
        return
    for seed in range(_MAX_INTEGER_WITNESS_MIXED_RADIX_ASSIGNMENTS):
        remainder = seed
        values: list[int] = []
        for _index in range(variable_count):
            values.append(candidates[remainder % len(candidates)])
            remainder //= len(candidates)
        yield tuple(values)


def _integer_witness_assignments(
    variable_count: int,
    formula: z3.BoolRef,
) -> list[tuple[int, ...]]:
    candidates = _integer_witness_candidates(formula)
    assignments = list(_integer_pattern_assignments(variable_count))
    if variable_count <= _MAX_INTEGER_WITNESS_PRODUCT_VARS:
        product_assignments = sorted(
            itertools.product(candidates, repeat=variable_count),
            key=_integer_assignment_priority,
        )
        assignments.extend(product_assignments[:_MAX_INTEGER_WITNESS_PRODUCT_ASSIGNMENTS])
    else:
        assignments.extend(_mixed_radix_integer_assignments(variable_count, candidates))
    return list(dict.fromkeys(assignments))


def _integer_assignment_priority(values: tuple[int, ...]) -> tuple[int, int, tuple[int, ...]]:
    """Prefer compact signed witnesses before wide integer combinations."""
    magnitudes = tuple(abs(value) for value in values)
    return (max(magnitudes, default=0), sum(magnitudes), values)


def _zero_float_witness_model_from_formula(
    formula: z3.ExprRef,
    variables: list[z3.FPRef],
) -> z3.ModelRef | None:
    substitutions = [(variable, z3.FPVal(0.0, variable.sort())) for variable in variables]
    if not substitutions or not z3.is_true(z3.simplify(z3.substitute(formula, *substitutions))):
        return None
    witness_solver = z3.Solver()
    witness_solver.add(*(variable == value for variable, value in substitutions))
    if witness_solver.check() != z3.sat:
        return None
    return witness_solver.model()


def _integer_witness_model_from_formula(
    formula: z3.BoolRef,
    variables: list[z3.ArithRef],
    *,
    bool_variables: list[z3.BoolRef] | None = None,
) -> z3.ModelRef | None:
    if not variables or len(variables) > _MAX_INTEGER_WITNESS_SEED_VARS:
        return None
    direct_values = _integer_assignment_from_equalities(formula, variables)
    if direct_values is not None:
        if bool_variables:
            direct_model = _verified_integer_bool_assignment_model(
                formula,
                integer_variables=variables,
                bool_variables=bool_variables,
                integer_values=direct_values,
            )
        else:
            direct_model = _verified_integer_assignment_model(formula, variables, direct_values)
        if direct_model is not None:
            return direct_model
    for values in _integer_witness_assignments(len(variables), formula):
        if bool_variables:
            model = _verified_integer_bool_assignment_model(
                formula,
                integer_variables=variables,
                bool_variables=bool_variables,
                integer_values=values,
            )
        else:
            model = _verified_integer_assignment_model(formula, variables, values)
        if model is not None:
            return model
    return None


def _integer_assignment_from_equalities(
    formula: z3.BoolRef,
    variables: list[z3.ArithRef],
) -> tuple[int, ...] | None:
    """Return a complete assignment from direct ``x == literal`` constraints."""
    values_by_name: dict[str, int] = {}
    variables_by_name = {variable.decl().name(): variable for variable in variables}
    allowed_names = frozenset(variables_by_name)
    for constraint in _iter_conjuncts(formula):
        simplified = z3.simplify(constraint)
        if not z3.is_eq(simplified):
            continue
        left, right = simplified.children()
        _assign_integer_value_from_equality(
            left=z3.simplify(left),
            right=z3.simplify(right),
            allowed_names=allowed_names,
            values_by_name=values_by_name,
        )
        _assign_integer_value_from_equality(
            left=z3.simplify(right),
            right=z3.simplify(left),
            allowed_names=allowed_names,
            values_by_name=values_by_name,
        )
    if any(variable.decl().name() not in values_by_name for variable in variables):
        return None
    return tuple(values_by_name[variable.decl().name()] for variable in variables)


def _string_integer_witness_model_from_formula(
    formula: z3.BoolRef,
    *,
    string_variables: list[z3.SeqRef],
    integer_variables: list[z3.ArithRef],
    bool_variables: list[z3.BoolRef],
) -> z3.ModelRef | None:
    if not string_variables or len(string_variables) > _MAX_STRING_WITNESS_STRINGS:
        return None
    integer_prefixes = _integer_slot_prefixes(integer_variables)
    bool_type_slots = _bool_type_slots(bool_variables)
    for string_values, active_string_prefixes in _string_witness_value_sets(
        string_variables,
        integer_variables,
        formula,
    ):
        for integer_values in _string_integer_assignments(
            integer_variables,
            string_values,
            formula,
        ):
            substitutions = _string_integer_substitutions(
                string_variables=string_variables,
                integer_variables=integer_variables,
                string_values=string_values,
                active_string_prefixes=active_string_prefixes,
                integer_values=integer_values,
                integer_prefixes=integer_prefixes,
                bool_type_slots=bool_type_slots,
            )
            if not z3.is_true(z3.simplify(z3.substitute(formula, *substitutions))):
                continue
            return _substitution_model(substitutions)
    return None


def _verified_integer_assignment_model(
    formula: z3.BoolRef,
    variables: list[z3.ArithRef],
    values: tuple[int, ...],
) -> z3.ModelRef | None:
    substitutions = [(variable, get_int_val(value)) for variable, value in zip(variables, values)]
    if not z3.is_true(z3.simplify(z3.substitute(formula, *substitutions))):
        return None
    return _assignment_model(variables, values)


def _verified_integer_bool_assignment_model(
    formula: z3.BoolRef,
    *,
    integer_variables: list[z3.ArithRef],
    bool_variables: list[z3.BoolRef],
    integer_values: tuple[int, ...],
) -> z3.ModelRef | None:
    """Verify an integer witness when only Boolean aggregate variables remain."""
    integer_substitutions: list[tuple[z3.ExprRef, z3.ExprRef]] = [
        (variable, get_int_val(value))
        for variable, value in zip(integer_variables, integer_values, strict=True)
    ]
    simplified = z3.simplify(z3.substitute(formula, *integer_substitutions))
    if z3.is_true(simplified):
        return _substitution_model(integer_substitutions)
    if z3.is_false(simplified) or _contains_non_bool_uninterpreted_constant(simplified):
        return None
    constants = _collect_witness_constants(simplified)
    if (
        constants.integer_variables
        or constants.string_variables
        or constants.fp_variables
        or not constants.bool_variables
        or len(constants.bool_variables) > _MAX_INTEGER_WITNESS_BOOL_VARS
    ):
        return None
    bool_model = _boolean_residue_model(simplified, constants.bool_variables)
    if bool_model is None:
        return None
    return _substitution_model([*integer_substitutions, *bool_model])


def _contains_non_bool_uninterpreted_constant(formula: z3.ExprRef) -> bool:
    """Return whether *formula* still has non-Boolean unassigned constants."""
    pending: list[z3.ExprRef] = [formula]
    visited: set[int] = set()
    while pending:
        expression = pending.pop()
        expression_hash = expression.hash()
        if expression_hash in visited:
            continue
        visited.add(expression_hash)
        if expression.decl().kind() == z3.Z3_OP_UNINTERPRETED and not isinstance(
            expression,
            z3.BoolRef,
        ):
            return True
        pending.extend(expression.children())
    return False


def _boolean_residue_model(
    formula: z3.BoolRef,
    variables: list[z3.BoolRef],
) -> list[tuple[z3.ExprRef, z3.ExprRef]] | None:
    """Return Boolean assignments that satisfy a post-integer residue."""
    solver = z3.Solver()
    solver.add(formula)
    try:
        if solver.check() != z3.sat:
            return None
        model = solver.model()
    except _SOLVER_FAILURES:
        logger.debug("Boolean residue witness check failed; treating as inconclusive")
        return None
    return [
        (variable, Z3_TRUE if z3.is_true(model.eval(variable, model_completion=True)) else Z3_FALSE)
        for variable in variables
    ]


def _string_integer_assignments(
    integer_variables: list[z3.ArithRef],
    string_values: tuple[str, ...],
    formula: z3.BoolRef,
) -> list[tuple[int, ...]]:
    assignments: list[tuple[int, ...]] = []
    source_text = _source_string_witness(string_values)
    bin_text = _bin_string_witness(string_values)
    ord_seed = _string_context_integer_assignment(
        integer_variables,
        formula=formula,
        source_text=source_text,
        bin_text=bin_text,
    )
    if ord_seed is not None:
        assignments.append(ord_seed)
    if len(integer_variables) > _MAX_STRING_WITNESS_PRODUCT_INTS:
        return assignments
    candidate_groups = [
        _integer_candidates_for_string_context(
            variable.decl().name(),
            source_text=source_text,
            bin_text=bin_text,
        )
        for variable in integer_variables
    ]
    assignments.extend(itertools.product(*candidate_groups))
    return list(dict.fromkeys(assignments))


def _string_integer_context_substitutions(
    constants: _WitnessConstants,
    query: z3.BoolRef,
) -> Iterator[list[tuple[z3.ExprRef, z3.ExprRef]]]:
    """Yield deterministic substitutions for scheduling-only branch truth probes."""
    integer_prefixes = _integer_slot_prefixes(constants.integer_variables)
    bool_type_slots = _bool_type_slots(constants.bool_variables)
    if constants.string_variables:
        for string_values, active_string_prefixes in _string_witness_value_sets(
            constants.string_variables,
            constants.integer_variables,
            query,
        ):
            for integer_values in _string_integer_assignments(
                constants.integer_variables,
                string_values,
                query,
            ):
                yield _string_integer_substitutions(
                    string_variables=constants.string_variables,
                    integer_variables=constants.integer_variables,
                    string_values=string_values,
                    active_string_prefixes=active_string_prefixes,
                    integer_values=integer_values,
                    integer_prefixes=integer_prefixes,
                    bool_type_slots=bool_type_slots,
                )
        return

    for source_text in _string_witness_candidates(query):
        bin_values = (None, *_bin_string_witness_candidates(query))
        for bin_text in bin_values:
            integer_values = _string_context_integer_assignment(
                constants.integer_variables,
                formula=query,
                source_text=source_text,
                bin_text=bin_text,
            )
            if integer_values is None:
                continue
            yield _string_integer_substitutions(
                string_variables=[],
                integer_variables=constants.integer_variables,
                string_values=(),
                active_string_prefixes=frozenset(),
                integer_values=integer_values,
                integer_prefixes=integer_prefixes,
                bool_type_slots=bool_type_slots,
            )


def _has_string_context_integer_variables(integer_variables: list[z3.ArithRef]) -> bool:
    """Return whether integer names look derived from string modeling."""
    for variable in integer_variables:
        name = variable.decl().name()
        if name.startswith("ord_") and name.endswith("_int"):
            return True
        if name.startswith("len_") and name.endswith("_int"):
            return True
        if "count" in name and name.endswith("_int"):
            return True
        if _is_missing_string_search_index(name) or _is_neutral_salt(name):
            return True
    return False


def _string_context_integer_assignment(
    integer_variables: list[z3.ArithRef],
    *,
    formula: z3.BoolRef,
    source_text: str,
    bin_text: str | None,
) -> tuple[int, ...] | None:
    ord_variables = _ordered_ord_integer_variables(integer_variables)
    if len(ord_variables) > len(source_text):
        return None
    values_by_name: dict[str, int] = {}
    for variable in integer_variables:
        name = variable.decl().name()
        if name.startswith("len_") and name.endswith("_int"):
            values_by_name[name] = len(source_text)
        elif "count" in name and name.endswith("_int") and bin_text is not None:
            values_by_name[name] = bin_text.count("1")
        elif _is_missing_string_search_index(name):
            values_by_name[name] = -1
        elif _is_neutral_salt(name):
            values_by_name[name] = 0
    for index, variable in enumerate(ord_variables):
        values_by_name[variable.decl().name()] = ord(source_text[index])
    _derive_integer_values_from_equalities(
        formula=formula,
        integer_variables=integer_variables,
        values_by_name=values_by_name,
    )
    if any(variable.decl().name() not in values_by_name for variable in integer_variables):
        return None
    return tuple(values_by_name[variable.decl().name()] for variable in integer_variables)


def _derive_integer_values_from_equalities(
    *,
    formula: z3.BoolRef,
    integer_variables: list[z3.ArithRef],
    values_by_name: dict[str, int],
) -> None:
    variables_by_name = {variable.decl().name(): variable for variable in integer_variables}
    allowed_names = frozenset(variables_by_name)
    for _ in range(len(integer_variables) + 1):
        substitutions = [
            (variable, get_int_val(values_by_name[name]))
            for name, variable in variables_by_name.items()
            if name in values_by_name
        ]
        changed = False
        for constraint in _iter_conjuncts(formula):
            if substitutions:
                constraint = z3.simplify(z3.substitute(constraint, *substitutions))
            else:
                constraint = z3.simplify(constraint)
            if not z3.is_eq(constraint):
                continue
            left, right = constraint.children()
            left_simplified = z3.simplify(left)
            right_simplified = z3.simplify(right)
            changed |= _assign_integer_value_from_equality(
                left=left_simplified,
                right=right_simplified,
                allowed_names=allowed_names,
                values_by_name=values_by_name,
            )
            changed |= _assign_integer_value_from_equality(
                left=right_simplified,
                right=left_simplified,
                allowed_names=allowed_names,
                values_by_name=values_by_name,
            )
        if not changed:
            return


def _assign_integer_value_from_equality(
    *,
    left: z3.ExprRef,
    right: z3.ExprRef,
    allowed_names: frozenset[str],
    values_by_name: dict[str, int],
) -> bool:
    if (
        not isinstance(left, z3.ArithRef)
        or left.sort().kind() != z3.Z3_INT_SORT
        or left.decl().kind() != z3.Z3_OP_UNINTERPRETED
        or not z3.is_int_value(right)
    ):
        return False
    name = left.decl().name()
    if name not in allowed_names or name in values_by_name:
        return False
    values_by_name[name] = right.as_long()
    return True


def _iter_conjuncts(formula: z3.BoolRef) -> Iterator[z3.BoolRef]:
    pending: list[z3.BoolRef] = [formula]
    while pending:
        constraint = pending.pop()
        if z3.is_and(constraint):
            pending.extend(cast("list[z3.BoolRef]", constraint.children()))
            continue
        yield constraint


def _ordered_ord_integer_variables(
    integer_variables: list[z3.ArithRef],
) -> list[z3.ArithRef]:
    return sorted(
        [
            variable
            for variable in integer_variables
            if variable.decl().name().startswith("ord_") and variable.decl().name().endswith("_int")
        ],
        key=_ord_integer_variable_key,
    )


def _ord_integer_variable_key(variable: z3.ArithRef) -> tuple[int, str]:
    name = variable.decl().name()
    stem = name.removesuffix("_int")
    address_text = stem.rsplit("_", 1)[-1]
    try:
        address = int(address_text)
    except ValueError:
        address = -1
    return (address, name)


def _integer_candidates_for_string_context(
    name: str,
    *,
    source_text: str,
    bin_text: str | None,
) -> tuple[int, ...]:
    if name.startswith("len_") and name.endswith("_int"):
        return (len(source_text),)
    if "count" in name and name.endswith("_int") and bin_text is not None:
        return (bin_text.count("1"),)
    return _INTEGER_WITNESS_CANDIDATES


def _is_missing_string_search_index(name: str) -> bool:
    return name.endswith("_int") and (
        name.startswith("find_")
        or name.startswith("rfind_")
        or name.startswith("index_")
        or name.startswith("rindex_")
    )


def _is_neutral_salt(name: str) -> bool:
    return name == "salt_int" or name.endswith("_salt_int")


def _string_witness_value_sets(
    string_variables: list[z3.SeqRef],
    integer_variables: list[z3.ArithRef],
    formula: z3.BoolRef,
) -> tuple[tuple[tuple[str, ...], frozenset[str]], ...]:
    string_count = len(string_variables)
    string_prefixes = tuple(
        variable.decl().name().removesuffix("_str") for variable in string_variables
    )
    string_candidates = _string_witness_candidates(formula)
    if string_count == 1:
        prefix = string_prefixes[0]
        return tuple(((text,), frozenset((prefix,))) for text in string_candidates)
    if string_count != 2:
        return ()
    values: list[tuple[tuple[str, ...], frozenset[str]]] = []
    integer_prefixes = _integer_slot_prefixes(integer_variables)
    for inactive_index, inactive_prefix in enumerate(string_prefixes):
        if inactive_prefix not in integer_prefixes:
            continue
        active_index = 1 - inactive_index
        active_prefix = string_prefixes[active_index]
        for source_text in string_candidates:
            string_values = ["", ""]
            string_values[inactive_index] = ""
            string_values[active_index] = source_text
            values.append((tuple(string_values), frozenset((active_prefix,))))
    if _has_bin_count_shape(string_prefixes, integer_variables):
        for source_text in string_candidates:
            for bin_text in _bin_string_witness_candidates(formula):
                values.append(((source_text, bin_text), frozenset(string_prefixes)))
                values.append(((bin_text, source_text), frozenset(string_prefixes)))
    return tuple(dict.fromkeys(values))


def _has_bin_count_shape(
    string_prefixes: tuple[str, ...],
    integer_variables: list[z3.ArithRef],
) -> bool:
    return any(prefix.startswith("bin_") for prefix in string_prefixes) or any(
        "count" in variable.decl().name() for variable in integer_variables
    )


def _source_string_witness(string_values: tuple[str, ...]) -> str:
    for value in string_values:
        if not value.startswith("0b"):
            return value
    return string_values[0]


def _bin_string_witness(string_values: tuple[str, ...]) -> str | None:
    for value in string_values:
        if value.startswith("0b") and all(character in {"0", "1"} for character in value[2:]):
            return value
    return None


def _string_integer_substitutions(
    *,
    string_variables: list[z3.SeqRef],
    integer_variables: list[z3.ArithRef],
    string_values: tuple[str, ...],
    active_string_prefixes: frozenset[str],
    integer_values: tuple[int, ...],
    integer_prefixes: frozenset[str],
    bool_type_slots: tuple[_BoolTypeSlot, ...],
) -> list[tuple[z3.ExprRef, z3.ExprRef]]:
    substitutions: list[tuple[z3.ExprRef, z3.ExprRef]] = [
        (variable, get_string_val(value))
        for variable, value in zip(string_variables, string_values, strict=True)
    ]
    substitutions.extend(
        (variable, get_int_val(value)) for variable, value in zip(integer_variables, integer_values)
    )
    for variable, prefix, suffix in bool_type_slots:
        if prefix in active_string_prefixes:
            substitutions.append((variable, Z3_TRUE if suffix == "str" else Z3_FALSE))
        elif prefix in integer_prefixes:
            substitutions.append((variable, Z3_TRUE if suffix == "int" else Z3_FALSE))
    return substitutions


def _bool_type_slots(bool_variables: list[z3.BoolRef]) -> tuple[_BoolTypeSlot, ...]:
    slots: list[_BoolTypeSlot] = []
    for variable in bool_variables:
        prefix, separator, suffix = variable.decl().name().rpartition("_is_")
        if separator:
            slots.append((variable, prefix, suffix))
    return tuple(slots)


def _integer_slot_prefixes(integer_variables: list[z3.ArithRef]) -> frozenset[str]:
    return frozenset(variable.decl().name().removesuffix("_int") for variable in integer_variables)


def _substitution_model(
    substitutions: list[tuple[z3.ExprRef, z3.ExprRef]],
) -> z3.ModelRef | None:
    solver = z3.Solver()
    solver.add(*(left == right for left, right in substitutions))
    try:
        if solver.check() != z3.sat:
            return None
        return solver.model()
    except _SOLVER_FAILURES:
        logger.debug("Substitution witness model extraction failed; treating as inconclusive")
        return None


def _assignment_model(
    variables: list[z3.ArithRef],
    values: tuple[int, ...],
) -> z3.ModelRef | None:
    solver = z3.Solver()
    solver.add(*(variable == get_int_val(value) for variable, value in zip(variables, values)))
    try:
        if solver.check() != z3.sat:
            return None
        return solver.model()
    except _SOLVER_FAILURES:
        logger.debug("Integer witness model extraction failed; treating as inconclusive")
        return None
