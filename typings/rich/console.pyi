from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Generic, IO, Literal, TypeVar, overload

_FileT = TypeVar("_FileT", bound=IO[str], default=IO[str])

_ColorSystem = Literal["auto", "standard", "256", "truecolor", "windows"]

class Console(Generic[_FileT]):
    @overload
    def __init__(
        self,
        *,
        file: _FileT,
        color_system: _ColorSystem | None = ...,
        force_terminal: bool | None = ...,
        force_jupyter: bool | None = ...,
        force_interactive: bool | None = ...,
        soft_wrap: bool = ...,
        theme: object | None = ...,
        stderr: bool = ...,
        quiet: bool = ...,
        width: int | None = ...,
        height: int | None = ...,
        style: object | None = ...,
        no_color: bool | None = ...,
        tab_size: int = ...,
        record: bool = ...,
        markup: bool = ...,
        emoji: bool = ...,
        emoji_variant: Literal["emoji", "text"] | None = ...,
        highlight: bool = ...,
        log_time: bool = ...,
        log_path: bool = ...,
        log_time_format: str | Callable[[datetime], object] = ...,
        highlighter: object | None = ...,
        legacy_windows: bool | None = ...,
        safe_box: bool = ...,
        get_datetime: Callable[[], datetime] | None = ...,
        get_time: Callable[[], float] | None = ...,
        _environ: Mapping[str, str] | None = ...,
    ) -> None: ...
    @overload
    def __init__(
        self,
        *,
        file: None = ...,
        color_system: _ColorSystem | None = ...,
        force_terminal: bool | None = ...,
        force_jupyter: bool | None = ...,
        force_interactive: bool | None = ...,
        soft_wrap: bool = ...,
        theme: object | None = ...,
        stderr: bool = ...,
        quiet: bool = ...,
        width: int | None = ...,
        height: int | None = ...,
        style: object | None = ...,
        no_color: bool | None = ...,
        tab_size: int = ...,
        record: bool = ...,
        markup: bool = ...,
        emoji: bool = ...,
        emoji_variant: Literal["emoji", "text"] | None = ...,
        highlight: bool = ...,
        log_time: bool = ...,
        log_path: bool = ...,
        log_time_format: str | Callable[[datetime], object] = ...,
        highlighter: object | None = ...,
        legacy_windows: bool | None = ...,
        safe_box: bool = ...,
        get_datetime: Callable[[], datetime] | None = ...,
        get_time: Callable[[], float] | None = ...,
        _environ: Mapping[str, str] | None = ...,
    ) -> None: ...
    @property
    def file(self) -> _FileT: ...
    def print(self, *objects: object, **kwargs: object) -> None: ...
    def log(self, *objects: object, **kwargs: object) -> None: ...
