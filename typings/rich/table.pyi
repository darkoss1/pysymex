"""Local Rich table stub."""

from __future__ import annotations

from typing import Self

class Table:
    def __init__(
        self,
        *headers: object,
        title: object | None = None,
        box: object | None = None,
        border_style: str | None = None,
        title_style: str | None = None,
        header_style: str | None = None,
        show_lines: bool = ...,
        padding: int | tuple[int, int] | tuple[int, int, int, int] = ...,
        min_width: int | None = None,
        **kwargs: object,
    ) -> None: ...
    @classmethod
    def grid(
        cls,
        *,
        padding: int | tuple[int, int] | tuple[int, int, int, int] = ...,
        **kwargs: object,
    ) -> Self: ...
    def add_column(
        self,
        header: object = ...,
        *,
        style: str | None = None,
        justify: str | None = None,
        min_width: int | None = None,
        **kwargs: object,
    ) -> None: ...
    def add_row(self, *renderables: object, **kwargs: object) -> None: ...
