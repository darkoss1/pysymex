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

"""Detector issue-kind to CPython exception-name mapping."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.outcome import IssueKind

if TYPE_CHECKING:
    import dis

    from pysymex._internal.analysis.detectors.detector.types import Issue


def exception_name_for_issue(issue: Issue, instr: dis.Instruction) -> str | None:
    """Map a reported issue kind/message to a CPython exception name when possible."""
    if issue.kind == IssueKind.DIVISION_BY_ZERO:
        return "ZeroDivisionError"
    if issue.kind == IssueKind.TYPE_ERROR:
        return "TypeError"
    if issue.kind == IssueKind.VALUE_ERROR:
        return "ValueError"
    if issue.kind == IssueKind.OVERFLOW:
        return "OverflowError"
    if issue.kind == IssueKind.ATTRIBUTE_ERROR:
        return "AttributeError"
    if issue.kind == IssueKind.INDEX_ERROR:
        return "IndexError"
    if issue.kind == IssueKind.KEY_ERROR:
        return "KeyError"
    if issue.kind == IssueKind.NAME_ERROR:
        return "NameError"
    if issue.kind == IssueKind.UNBOUND_VARIABLE:
        return "NameError"
    if issue.kind == IssueKind.NULL_DEREFERENCE:
        return null_dereference_exception_name(instr)
    if issue.kind != IssueKind.UNHANDLED_EXCEPTION:
        return None

    prefix = "Path raises unhandled exception: "
    if issue.message.startswith(prefix):
        candidate = issue.message.removeprefix(prefix).split(":", 1)[0].strip()
        if candidate:
            return candidate.split("(", 1)[0].split("[", 1)[0].strip()
    if ": " in issue.message:
        candidate = issue.message.rsplit(": ", 1)[-1].strip()
        if candidate:
            return candidate.split("(", 1)[0].split("[", 1)[0].strip()
    if "] " in issue.message:
        tail = issue.message.split("] ", 1)[1]
        candidate = tail.split(":", 1)[0].strip()
        if candidate:
            return candidate
    return None


def null_dereference_exception_name(instr: dis.Instruction) -> str | None:
    """Return the CPython exception raised by dereferencing ``None`` at *instr*."""
    if instr.opname == "BINARY_SUBSCR":
        return "TypeError"
    if instr.opname in {
        "DELETE_ATTR",
        "LOAD_ATTR",
        "LOAD_METHOD",
        "LOAD_SUPER_ATTR",
        "STORE_ATTR",
    }:
        return "AttributeError"
    return None
