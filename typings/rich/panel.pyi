"""Local Rich panel stub."""

from __future__ import annotations


class Panel:
    def __init__(
        self,
        renderable: object,
        *,
        title: object | None = None,
        title_align: str = ...,
        border_style: str | None = None,
        box: object | None = None,
        padding: int | tuple[int, int] | tuple[int, int, int, int] = ...,
        **kwargs: object,
    ) -> None: ...
