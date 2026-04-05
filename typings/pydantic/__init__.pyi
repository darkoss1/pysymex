from __future__ import annotations

from collections.abc import Callable
from typing import ClassVar, Generic, TypeVar, TypedDict, overload

_T = TypeVar("_T")


class ConfigDict(TypedDict, total=False):
    frozen: bool
    extra: str
    validate_assignment: bool
    populate_by_name: bool


class BaseModel:
    model_config: ClassVar[ConfigDict]

    def __init__(self, **data: object) -> None: ...
    def model_dump(self) -> dict[str, object]: ...
    def model_dump_json(self) -> str: ...


@overload
def Field(
    default: _T,
    *,
    default_factory: None = ...,
    gt: float | int | None = ...,
    ge: float | int | None = ...,
    lt: float | int | None = ...,
    le: float | int | None = ...,
    discriminator: str | None = ...,
) -> _T: ...
@overload
def Field(
    *,
    default_factory: Callable[[], _T],
    gt: float | int | None = ...,
    ge: float | int | None = ...,
    lt: float | int | None = ...,
    le: float | int | None = ...,
    discriminator: str | None = ...,
) -> _T: ...
@overload
def Field(
    *,
    discriminator: str,
) -> object: ...


class TypeAdapter(Generic[_T]):
    def __init__(self, annotated_type: object, /) -> None: ...
    def validate_json(self, data: str | bytes) -> _T: ...
