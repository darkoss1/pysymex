"""Local Hypothesis stub for the repository's property-test decorators."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from enum import Enum
from typing import ParamSpec, TypeVar

from . import strategies as strategies

P = ParamSpec("P")
R = TypeVar("R")


class HealthCheck(Enum):
    too_slow = "too_slow"


def given(*given_arguments: object, **given_keywords: object) -> Callable[[Callable[P, R]], Callable[P, R]]: ...


def settings(
    *,
    suppress_health_check: Sequence[HealthCheck] = ...,
    **kwargs: object,
) -> Callable[[Callable[P, R]], Callable[P, R]]: ...


__all__ = ["HealthCheck", "given", "settings", "strategies"]
