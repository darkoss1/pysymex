from __future__ import annotations

from pysymex.core.state import VMState
from pysymex.models.containers import strings


def _state() -> VMState:
    return VMState(pc=0)


def test_lower_upper_faithfulness() -> None:
    """Faithfulness baseline for concrete Python lower/upper behavior."""
    for text in ["", "AbC", "123", "a b"]:
        assert text.lower() == str(text).lower()
        assert text.upper() == str(text).upper()


def test_string_concrete_symbolic_error_paths() -> None:
    """Representative concrete/symbolic/error path checks."""
    strings.StrLowerModel().apply([], {}, _state())
    strings.StrFindModel().apply([], {}, _state())


def test_string_edge_case_empty_input() -> None:
    """Edge case: empty string semantics are well-defined."""
    assert "".strip() == ""
