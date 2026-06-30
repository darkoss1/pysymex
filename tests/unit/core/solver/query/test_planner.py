from __future__ import annotations

import z3

from pysymex._internal.core.solver.query.planner import (
    clear_symbolic_query_caches,
    query_cache_stats,
    symbolic_query,
)


def test_symbolic_query_reuses_conjunction_and_simplification() -> None:
    clear_symbolic_query_caches()
    x = z3.Int("query_cache_x")
    constraints = [x == 1, x > 0]

    first = symbolic_query(constraints)
    assert first.simplified_conjunction() is not None
    second = symbolic_query(constraints)
    assert second.simplified_conjunction() is not None

    stats = query_cache_stats()
    assert stats.query_hits >= 1
    assert stats.simplify_hits >= 1


def test_literal_substitution_uses_top_level_assignments_without_solver() -> None:
    clear_symbolic_query_caches()
    x = z3.Int("query_cache_literal_x")
    query = symbolic_query([x == 0, x % 2 != 0])

    assert query.literal_substitution_yields(False) is True
    assert query.literal_assignment_substitutions()


def test_query_meta_detects_hard_theory_once() -> None:
    clear_symbolic_query_caches()
    bits = z3.BitVec("query_cache_bits", 8)
    query = symbolic_query([z3.BV2Int(bits & z3.BitVecVal(1, 8), is_signed=False) == 1])

    assert query.contains_hard_witness_theory(include_bitvector=True) is True
    assert query.contains_complex_theory() is True
    first = query_cache_stats()
    assert first.formula_meta_misses >= 1

    assert query.contains_complex_theory() is True
    second = query_cache_stats()
    assert second.formula_meta_hits >= first.formula_meta_hits + 1
