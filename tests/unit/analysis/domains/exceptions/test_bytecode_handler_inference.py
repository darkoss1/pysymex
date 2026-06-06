"""Focused tests for bytecode exception-handler type inference."""

from __future__ import annotations

import dis
from collections.abc import Callable
from typing import Protocol, cast

from pysymex.analysis.domains.exceptions.analyzer.bytecode import (
    catches_name,
    infer_caught_at,
)


class _ExceptionEntry(Protocol):
    start: int
    end: int
    target: int


def _first_exception_entry(function: Callable[..., object]) -> _ExceptionEntry:
    entries = cast(
        list[_ExceptionEntry],
        list(getattr(dis.Bytecode(function), "exception_entries", ())),
    )
    assert entries
    return entries[0]


def test_infer_caught_at_handles_local_exception_class_load() -> None:
    def target() -> int:
        class MyError(Exception):
            pass

        try:
            raise MyError
        except MyError:
            return 4

    instructions = list(dis.get_instructions(target))
    caught = infer_caught_at(instructions, _first_exception_entry(target).target)

    assert caught == {"MyError"}
    assert catches_name("MyError", caught) is True


def test_infer_caught_at_keeps_mismatched_local_exception_distinct() -> None:
    def target() -> int:
        class MyError(Exception):
            pass

        class OtherError(Exception):
            pass

        try:
            raise OtherError
        except MyError:
            return 4

    instructions = list(dis.get_instructions(target))
    caught = infer_caught_at(instructions, _first_exception_entry(target).target)

    assert caught == {"MyError"}
    assert catches_name("OtherError", caught) is False
