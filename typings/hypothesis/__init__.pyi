from __future__ import annotations

from collections.abc import Callable
from typing import ParamSpec, TypeVar

from . import strategies
from .strategies import SearchStrategy

_P = ParamSpec("_P")
_R = TypeVar("_R")


def assume(condition: bool) -> None: ...
def given(
    *given_args: SearchStrategy[object],
    **given_kwargs: SearchStrategy[object],
) -> Callable[[Callable[_P, _R]], Callable[_P, _R]]: ...
def settings(
    *,
    max_examples: int = ...,
    deadline: float | int | None = ...,
    derandomize: bool = ...,
    stateful_step_count: int = ...,
) -> Callable[[Callable[_P, _R]], Callable[_P, _R]]: ...


__all__ = ["assume", "given", "settings", "strategies"]
