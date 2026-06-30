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

"""Regex compiler atom parsing helpers."""

from __future__ import annotations

import z3


class PatternAtomMixin:
    """Atom parsing methods for PatternCompiler."""

    pos: int
    pattern: str

    def _parse_union(self) -> z3.ReRef:
        raise NotImplementedError

    def _parse_atom(self) -> z3.ReRef | None:
        """Parse a single atom (char, class, group, etc.)."""
        if self.pos >= len(self.pattern):
            return None
        char = self.pattern[self.pos]
        if char == "[":
            return self._parse_char_class()
        if char == "(":
            return self._parse_group()
        if char == "\\":
            return self._parse_escape()
        if char == ".":
            self.pos += 1
            return z3.AllChar(z3.StringSort())
        if char == "^":
            self.pos += 1
            return z3.Re("")
        if char == "$":
            self.pos += 1
            return z3.Re("")
        if char not in "*+?{|)":
            self.pos += 1
            return z3.Re(char)
        return None

    def _parse_char_class(self) -> z3.ReRef:
        """Parse character class [...]."""
        self.pos += 1
        negated = False
        if self.pos < len(self.pattern) and self.pattern[self.pos] == "^":
            negated = True
            self.pos += 1
        parts: list[z3.ReRef] = []
        while self.pos < len(self.pattern) and self.pattern[self.pos] != "]":
            if self.pattern[self.pos] == "\\":
                self.pos += 1
                if self.pos < len(self.pattern):
                    esc: str = self.pattern[self.pos]
                    if esc == "d":
                        parts.append(z3.Range("0", "9"))
                    elif esc == "s":
                        parts.append(self._whitespace_class())
                    elif esc == "w":
                        parts.append(self._word_class())
                    else:
                        parts.append(z3.Re(esc))
                    self.pos += 1
            elif self.pos + 2 < len(self.pattern) and self.pattern[self.pos + 1] == "-":
                start_char: str = self.pattern[self.pos]
                end_char: str = self.pattern[self.pos + 2]
                parts.append(z3.Range(start_char, end_char))
                self.pos += 3
            else:
                parts.append(z3.Re(self.pattern[self.pos]))
                self.pos += 1
        if self.pos < len(self.pattern):
            self.pos += 1
        if not parts:
            return z3.Re("")
        result: z3.ReRef = parts[0]
        for p in parts[1:]:
            result = z3.Union(result, p)
        if negated:
            result = z3.Complement(result)
        return result

    def _parse_group(self) -> z3.ReRef:
        """Parse group (...)."""
        self.pos += 1
        if (
            self.pos + 1 < len(self.pattern)
            and self.pattern[self.pos] == "?"
            and self.pattern[self.pos + 1] == ":"
        ):
            self.pos += 2
        content = self._parse_union()
        if self.pos < len(self.pattern) and self.pattern[self.pos] == ")":
            self.pos += 1
        return content

    def _parse_escape(self) -> z3.ReRef:
        """Parse escape sequence."""
        self.pos += 1
        if self.pos >= len(self.pattern):
            return z3.Re("\\")
        char = self.pattern[self.pos]
        self.pos += 1
        if char == "d":
            return z3.Range("0", "9")
        if char == "D":
            return z3.Complement(z3.Range("0", "9"))
        if char == "w":
            return self._word_class()
        if char == "W":
            return z3.Complement(self._word_class())
        if char == "s":
            return self._whitespace_class()
        if char == "S":
            return z3.Complement(self._whitespace_class())
        if char == "n":
            return z3.Re("\n")
        if char == "t":
            return z3.Re("\t")
        if char == "r":
            return z3.Re("\r")
        if char in r"\.^$*+?{}[]|()":
            return z3.Re(char)
        return z3.Re(char)

    def _word_class(self) -> z3.ReRef:
        r"""Create \w character class: [a-zA-Z0-9_]."""
        return z3.Union(
            z3.Range("a", "z"),
            z3.Union(z3.Range("A", "Z"), z3.Union(z3.Range("0", "9"), z3.Re("_"))),
        )

    def _whitespace_class(self) -> z3.ReRef:
        r"""Create \s character class: [ \t\n\r\f\v]."""
        return z3.Union(
            z3.Re(" "),
            z3.Union(z3.Re("\t"), z3.Union(z3.Re("\n"), z3.Union(z3.Re("\r"), z3.Re("\f")))),
        )
