"""Thread-Local SAT Worker for pure Boolean evaluation."""

import threading
from typing import Any, Literal, Protocol

from pysymex.contracts.decorators import ensures, requires
from pysymex.accel.types import AtomId, SelectorLit


def _is_none(value: object) -> bool:
    return value is None


def _is_non_empty_string(value: object) -> bool:
    return isinstance(value, str) and value != ""


def _is_positive_int(value: object) -> bool:
    return isinstance(value, int) and value > 0


def _is_non_negative_int(value: object) -> bool:
    return isinstance(value, int) and value >= 0


def _is_clause_list(value: object) -> bool:
    return isinstance(value, list)


def _is_clause_list_or_none(value: object) -> bool:
    return value is None or isinstance(value, list)


class CadicalLikeSolver(Protocol):
    """Protocol for a fast, thread-local IPASIR-compatible SAT solver."""

    def add_clause(self, literals: list[int]) -> None: ...

    def solve(self, assumptions: list[int]) -> Literal["sat", "unsat", "unknown"]:  # type: ignore
        ...

    def get_failed_assumptions(self) -> list[int]: ...

    def release_gil_and_solve(self, assumptions: list[int]) -> str:
        """Native method that must release the Python GIL during solve."""
        ...


class LiteralPool:
    @ensures(_is_none)
    def __init__(self):
        self._next_var = 1
        self._mapping: dict[str, int] = {}

    @requires(_is_non_empty_string)
    @ensures(_is_positive_int)
    def get_var(self, name: str) -> int:
        if name not in self._mapping:
            self._mapping[name] = self._next_var
            self._next_var += 1
        return self._mapping[name]

    @ensures(_is_non_negative_int)
    def size(self) -> int:
        return self._next_var - 1


class CnfCache:
    @ensures(_is_none)
    def __init__(self):
        self._cache: dict[Any, list[list[int]]] = {}

    @ensures(_is_clause_list_or_none)
    def get(self, expr_hash: Any) -> list[list[int]] | None:
        return self._cache.get(expr_hash)

    @requires(_is_clause_list)
    def put(self, expr_hash: Any, clauses: list[list[int]]) -> None:
        self._cache[expr_hash] = clauses


class ThreadLocalSatWorker(threading.local):
    """A thread-local long-lived SAT solver instance."""

    @ensures(_is_none)
    def __init__(self):
        super().__init__()
        # In a real implementation, this would instantiate the native PyO3/Cython solver bindings.
        self.solver: Any = None
        self.var_pool = LiteralPool()
        self.cnf_cache = CnfCache()
        self.selector_map: dict[SelectorLit, AtomId] = {}
        self._clause_count = 0

    @requires(_is_positive_int)
    def reset_if_needed(self, clause_budget: int = 100_000) -> None:
        """Reset the solver instance if it exceeds the budget."""
        if self._clause_count > clause_budget:
            self.solver = None  # Re-instantiate
            self.var_pool = LiteralPool()
            self.cnf_cache = CnfCache()
            self.selector_map.clear()
            self._clause_count = 0
