"""Local Hypothesis strategy stub for PySyMex tests."""

from __future__ import annotations

from typing import Generic, TypeVar

T = TypeVar("T")

class SearchStrategy(Generic[T]): ...

def integers(
    min_value: int | None = None,
    max_value: int | None = None,
) -> SearchStrategy[int]: ...
def lists(
    elements: SearchStrategy[T],
    *,
    min_size: int = ...,
    max_size: int | None = None,
    unique: bool = ...,
) -> SearchStrategy[list[T]]: ...
