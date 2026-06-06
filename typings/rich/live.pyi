"""Local Rich live-display stub."""

from __future__ import annotations


class Live:
    def __init__(
        self,
        renderable: object,
        *,
        console: object | None = None,
        refresh_per_second: int | float = ...,
        transient: bool = ...,
        **kwargs: object,
    ) -> None: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def update(self, renderable: object, *, refresh: bool = ...) -> None: ...
