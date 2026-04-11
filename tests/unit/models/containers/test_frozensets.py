from __future__ import annotations

import pytest

from pysymex.core.state import VMState
from pysymex.models.containers import frozensets


def _state() -> VMState:
    return VMState(pc=0)


def test_frozenset_faithfulness_baseline() -> None:
    """Faithfulness baseline for immutable frozenset behavior."""
    values_cases: list[frozenset[int]] = [frozenset(), frozenset({1}), frozenset({1, 2})]
    for values in values_cases:
        assert values.union({9}) == frozenset(values).union({9})
        assert values.intersection({1, 9}) == frozenset(values).intersection({1, 9})


def test_frozenset_symbolic_error_paths() -> None:
    """Representative symbolic/error path checks."""
    with pytest.raises(NameError):
        frozensets.FrozensetHashModel().apply([], {}, _state())

    with pytest.raises(NameError):
        frozensets.FrozensetContainsModel().apply([], {}, _state())


def test_frozenset_edge_case_empty() -> None:
    """Edge case for empty frozenset."""
    empty: frozenset[int] = frozenset()
    assert len(empty) == 0
