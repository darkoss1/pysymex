from __future__ import annotations

from types import TracebackType
from typing import Generic, TypeVar

_E = TypeVar("_E", bound=BaseException)


class RaisesContext(Generic[_E]):
    def __enter__(self) -> RaisesContext[_E]: ...
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> bool | None: ...


def raises(expected_exception: type[_E]) -> RaisesContext[_E]: ...
