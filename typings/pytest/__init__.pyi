from __future__ import annotations

from types import TracebackType
from typing import Any, Generic, TypeVar

_E = TypeVar("_E", bound=BaseException)


class RaisesContext(Generic[_E]):
    def __enter__(self) -> RaisesContext[_E]: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool | None: ...


def raises(expected_exception: type[_E], match: Any = ...) -> RaisesContext[_E]: ...


def fail(reason: str = ..., pytrace: bool = ...) -> None: ...
def skip(reason: str = ..., *, allow_module_level: bool = ...) -> None: ...
def importorskip(modname: str, minversion: str | None = ..., reason: str | None = ...) -> Any: ...
def main(args: list[str] | None = ..., plugins: list[object] | None = ...) -> int | Any: ...

fixture: Any
mark: Any
approx: Any

