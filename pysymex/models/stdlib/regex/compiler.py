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

"""Python regex-pattern to Z3 regex compiler."""

from __future__ import annotations

import z3

from pysymex.models.stdlib.regex.compiler_atoms import PatternAtomMixin


class PatternCompiler(PatternAtomMixin):
    """Compiles Python regex patterns to Z3 regex expressions.
    Supports a subset of Python regex syntax that maps to Z3's regex theory.
    """

    CHAR_CLASSES: dict[str, tuple[str, str] | None] = {
        r"\d": ("0", "9"),
        r"\w": None,
        r"\s": None,
    }

    pos: int
    pattern: str

    def __init__(self) -> None:
        self.pos = 0
        self.pattern = ""

    def compile(self, pattern: str) -> z3.ReRef:
        """Compile a Python regex pattern to Z3 regex.
        Args:
            pattern: Python regex pattern string
        Returns:
            Z3 regex expression
        """
        self.pattern = pattern
        self.pos = 0
        if not pattern:
            return z3.Re("")
        return self._parse_union()

    def _parse_union(self) -> z3.ReRef:
        """Parse alternation (|)."""
        left = self._parse_concat()
        while self.pos < len(self.pattern) and self.pattern[self.pos] == "|":
            self.pos += 1
            right = self._parse_concat()
            left = z3.Union(left, right)
        return left

    def _parse_concat(self) -> z3.ReRef:
        """Parse concatenation."""
        parts: list[z3.ReRef] = []
        while self.pos < len(self.pattern):
            char: str = self.pattern[self.pos]
            if char in "|)":
                break
            part: z3.ReRef | None = self._parse_quantified()
            if part is not None:
                parts.append(part)
        if not parts:
            return z3.Re("")
        if len(parts) == 1:
            return parts[0]
        result: z3.ReRef = parts[0]
        for p in parts[1:]:
            result = z3.Concat(result, p)
        return result

    def _parse_quantified(self) -> z3.ReRef | None:
        """Parse an atom with optional quantifier."""
        atom = self._parse_atom()
        if atom is None:
            return None
        if self.pos < len(self.pattern):
            char = self.pattern[self.pos]
            if char == "*":
                self.pos += 1
                return z3.Star(atom)
            elif char == "+":
                self.pos += 1
                return z3.Plus(atom)
            elif char == "?":
                self.pos += 1
                return z3.Option(atom)
            elif char == "{":
                return self._parse_repeat(atom)
        return atom

    def _parse_repeat(self, atom: z3.ReRef) -> z3.ReRef:
        """Parse {n}, {n,}, {n,m} quantifiers."""
        self.pos += 1
        start: int = self.pos
        while self.pos < len(self.pattern) and self.pattern[self.pos].isdigit():
            self.pos += 1
        if self.pos == start:
            return atom
        n: int = int(self.pattern[start : self.pos])
        if self.pos >= len(self.pattern):
            return atom
        if self.pattern[self.pos] == "}":
            self.pos += 1
            return z3.Loop(atom, n, n)
        if self.pattern[self.pos] == ",":
            self.pos += 1
            if self.pos < len(self.pattern) and self.pattern[self.pos] == "}":
                self.pos += 1
                if n == 0:
                    return z3.Star(atom)
                elif n == 1:
                    return z3.Plus(atom)
                else:
                    return z3.Concat(z3.Loop(atom, n, n), z3.Star(atom))
            start = self.pos
            while self.pos < len(self.pattern) and self.pattern[self.pos].isdigit():
                self.pos += 1
            if self.pos > start:
                m: int = int(self.pattern[start : self.pos])
                if self.pos < len(self.pattern) and self.pattern[self.pos] == "}":
                    self.pos += 1
                    return z3.Loop(atom, n, m)
        return atom


_compiler = PatternCompiler()


def compile_pattern(pattern: str) -> z3.ReRef:
    """Compile a Python regex pattern to Z3 regex."""
    return _compiler.compile(pattern)


__all__ = ["PatternCompiler", "compile_pattern"]
