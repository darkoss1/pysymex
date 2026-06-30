# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Focused tests for bytecode exception-handler type inference."""

from __future__ import annotations

import dis
from collections.abc import Callable
from typing import Protocol, cast

from pysymex._internal.execution.detectors.suppression.bytecode import SuppressionBytecodeOps
from pysymex._internal.execution.detectors.suppression.managers import SuppressionManagerPolicy


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


def test_suppression_ops_exist() -> None:
    assert callable(SuppressionBytecodeOps.catches_name)
    assert callable(SuppressionBytecodeOps.cleanup_replaces_original_at)
    assert callable(SuppressionBytecodeOps.cleanup_reraise_at)
    assert callable(SuppressionBytecodeOps.infer_caught_at)
    assert callable(SuppressionBytecodeOps.infer_with_manager_call_at)
    assert callable(SuppressionManagerPolicy.known_suppresses)


def test_infer_caught_at_handles_local_exception_class_load() -> None:
    def target() -> int:
        class MyError(Exception):
            pass

        try:
            raise MyError
        except MyError:
            return 4

    instructions = list(dis.get_instructions(target))
    caught = SuppressionBytecodeOps.infer_caught_at(
        instructions, _first_exception_entry(target).target
    )

    assert caught == {"MyError"}
    assert SuppressionBytecodeOps.catches_name("MyError", caught) is True


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
    caught = SuppressionBytecodeOps.infer_caught_at(
        instructions, _first_exception_entry(target).target
    )

    assert caught == {"MyError"}
    assert SuppressionBytecodeOps.catches_name("OtherError", caught) is False


def test_infer_caught_at_scans_later_sibling_handlers_after_return() -> None:
    def target(x: int) -> int:
        try:
            if x > 0:
                raise LookupError("bad")
        except ValueError:
            return 1
        except LookupError:
            return 0
        return 0

    instructions = list(dis.get_instructions(target))
    caught = SuppressionBytecodeOps.infer_caught_at(
        instructions, _first_exception_entry(target).target
    )

    assert caught == {"LookupError", "ValueError"}
    assert SuppressionBytecodeOps.catches_name("LookupError", caught) is True


def test_infer_caught_at_handles_tuple_exceptions() -> None:
    def target(x: int) -> int:
        try:
            return 10 // x
        except (ZeroDivisionError, ValueError):
            return 0

    instructions = list(dis.get_instructions(target))
    caught = SuppressionBytecodeOps.infer_caught_at(
        instructions, _first_exception_entry(target).target
    )

    assert "ZeroDivisionError" in caught
    assert "ValueError" in caught


def test_infer_caught_at_does_not_treat_finally_cleanup_as_catch() -> None:
    def target(x: int) -> int:
        value = 0
        try:
            value = 10 // x
        finally:
            value += 1
        return value

    instructions = list(dis.get_instructions(target))
    caught = SuppressionBytecodeOps.infer_caught_at(
        instructions, _first_exception_entry(target).target
    )

    assert caught == set()


def test_infer_caught_at_treats_bare_except_as_catch_all() -> None:
    def target(x: int) -> int:
        try:
            return 10 // x
        except:  # noqa: E722 - fixture intentionally exercises bare-except bytecode.
            return 0

    instructions = list(dis.get_instructions(target))
    caught = SuppressionBytecodeOps.infer_caught_at(
        instructions, _first_exception_entry(target).target
    )

    assert caught == {"BaseException"}


def test_infer_caught_at_does_not_treat_except_cleanup_as_catch() -> None:
    def target(x: int) -> int:
        try:
            raise ValueError("body")
        except ValueError:
            return 10 // x

    instructions = list(dis.get_instructions(target))
    division = next(instr for instr in instructions if instr.opname == "BINARY_OP")
    entries = cast(
        list[_ExceptionEntry],
        list(getattr(dis.Bytecode(target), "exception_entries", ())),
    )
    cleanup_entry = next(entry for entry in entries if entry.start <= division.offset < entry.end)

    assert SuppressionBytecodeOps.infer_caught_at(instructions, cleanup_entry.target) == set()


def test_catches_name_uses_builtin_exception_subclass_relationships() -> None:
    assert SuppressionBytecodeOps.catches_name("KeyError", {"LookupError"}) is True
    assert SuppressionBytecodeOps.catches_name("FileNotFoundError", {"OSError"}) is True
    assert SuppressionBytecodeOps.catches_name("NotImplementedError", {"RuntimeError"}) is True
    assert SuppressionBytecodeOps.catches_name("ValueError", {"LookupError"}) is False


def test_infer_with_manager_call_at_handles_local_manager_call_layout() -> None:
    def target() -> int:
        class SuppressZero:
            def __enter__(self) -> object:
                return self

            def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
                _ = exc, tb
                return exc_type is ZeroDivisionError

        with SuppressZero():
            _ = 1 / 0
        return 5

    instructions = list(dis.get_instructions(target))
    division = next(instr for instr in instructions if instr.opname == "BINARY_OP")
    entries = cast(
        list[_ExceptionEntry],
        list(getattr(dis.Bytecode(target), "exception_entries", ())),
    )
    entry = next(entry for entry in entries if entry.start <= division.offset < entry.end)

    assert SuppressionBytecodeOps.infer_with_manager_call_at(
        instructions, entry.start, entry.target
    ) == (
        "SuppressZero",
        (),
    )
