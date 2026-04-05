from __future__ import annotations

from collections.abc import Callable
from typing import ClassVar, ParamSpec, TypeVar

from hypothesis.strategies import SearchStrategy

_P = ParamSpec("_P")
_R = TypeVar("_R")


class Bundle:
    name: str

    def __init__(self, name: str) -> None: ...


class RuleBasedStateMachine:
    TestCase: ClassVar[type[object]]

    def __init__(self) -> None: ...


def invariant() -> Callable[[Callable[_P, _R]], Callable[_P, _R]]: ...
def rule(
    *,
    target: Bundle | None = ...,
    **kwargs: SearchStrategy[object] | Bundle,
) -> Callable[[Callable[_P, _R]], Callable[_P, _R]]: ...
