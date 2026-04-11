# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Symbolic Models for Python's re module.
Provides symbolic execution support for regular expression operations
using Z3's native regex theory (SMT-LIB theory of strings and sequences).
Supported operations:
- re.match(pattern, string) - Match at beginning
- re.search(pattern, string) - Search anywhere
- re.fullmatch(pattern, string) - Match entire string
- re.findall(pattern, string) - Find all matches
- re.sub(pattern, repl, string) - Substitute matches
- re.split(pattern, string) - Split by pattern
Limitations:
- Complex patterns may time out or return unknown
- Backreferences not supported by Z3
- Some flags (IGNORECASE, MULTILINE) have limited support
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import z3

from pysymex.core.types.scalars import (
    SymbolicList,
    SymbolicString,
    SymbolicValue,
)
from pysymex.models.builtins import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState


class PatternCompiler:
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
        elif char == "D":
            return z3.Complement(z3.Range("0", "9"))
        elif char == "w":
            return self._word_class()
        elif char == "W":
            return z3.Complement(self._word_class())
        elif char == "s":
            return self._whitespace_class()
        elif char == "S":
            return z3.Complement(self._whitespace_class())
        elif char == "n":
            return z3.Re("\n")
        elif char == "t":
            return z3.Re("\t")
        elif char == "r":
            return z3.Re("\r")
        elif char in r"\.^$*+?{}[]|()":
            return z3.Re(char)
        else:
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


_compiler = PatternCompiler()


def compile_pattern(pattern: str) -> z3.ReRef:
    """Compile a Python regex pattern to Z3 regex."""
    return _compiler.compile(pattern)


def _get_symbolic_string(arg: object) -> SymbolicString | None:
    """Extract symbolic string from argument."""
    if isinstance(arg, SymbolicString):
        return arg
    return None


def _get_pattern_string(arg: object) -> str | None:
    """Extract pattern string from argument (concrete or compiled)."""
    if isinstance(arg, str):
        return arg
    if isinstance(arg, re.Pattern):
        return arg.pattern
    if isinstance(arg, SymbolicValue) and isinstance(arg.pattern, str):
        return arg.pattern
    if isinstance(arg, SymbolicString):
        return None
    return None


class ReMatchModel(FunctionModel):
    """Model for re.match() - match at beginning of string.
    Returns:
    - Match object (modeled as SymbolicValue) if pattern matches at start
    - None if no match
    Constraints:
    - If match succeeds, string starts with a substring matching pattern
    """

    name = "match"
    qualname = "re.match"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        pattern = _get_pattern_string(args[0]) if args else None
        string = _get_symbolic_string(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicValue.symbolic(f"match_{state.pc}")
        constraints = [constraint]
        side_effects: dict[str, object] = {}
        if pattern is not None and string is not None:
            try:
                z3_pattern = compile_pattern(pattern)
                prefix = z3.String(f"prefix_{state.pc}")
                match_constraint = z3.And(
                    z3.InRe(prefix, z3_pattern),
                    z3.PrefixOf(prefix, string.z3_str),
                    z3.Length(prefix) >= 0,
                )
                constraints.append(z3.Implies(result.z3_bool, match_constraint))
                no_match = z3.Not(
                    z3.InRe(
                        string.z3_str, z3.Concat(z3_pattern, z3.Star(z3.AllChar(z3.StringSort())))
                    )
                )
                constraints.append(
                    z3.Or(
                        result.z3_bool,
                        no_match,
                    )
                )
                side_effects["regex_operation"] = {
                    "type": "match",
                    "pattern": pattern,
                    "may_fail": True,
                }
            except z3.Z3Exception:
                pass
        return ModelResult(
            value=result,
            constraints=constraints,
            side_effects=side_effects,
        )


class ReSearchModel(FunctionModel):
    """Model for re.search() - search anywhere in string.
    Returns:
    - Match object if pattern found anywhere
    - None if no match
    Constraints:
    - If match succeeds, string contains a substring matching pattern
    """

    name = "search"
    qualname = "re.search"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        pattern = _get_pattern_string(args[0]) if args else None
        string = _get_symbolic_string(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicValue.symbolic(f"search_{state.pc}")
        constraints = [constraint]
        side_effects: dict[str, object] = {}
        if pattern is not None and string is not None:
            try:
                z3_pattern = compile_pattern(pattern)
                any_prefix = z3.Star(z3.AllChar(z3.StringSort()))
                any_suffix = z3.Star(z3.AllChar(z3.StringSort()))
                full_pattern = z3.Concat(any_prefix, z3.Concat(z3_pattern, any_suffix))
                string_matches = z3.InRe(string.z3_str, full_pattern)
                constraints.append(z3.Implies(result.z3_bool, string_matches))
                constraints.append(z3.Implies(z3.Not(string_matches), z3.Not(result.z3_bool)))
                side_effects["regex_operation"] = {
                    "type": "search",
                    "pattern": pattern,
                    "may_fail": True,
                }
            except z3.Z3Exception:
                pass
        return ModelResult(
            value=result,
            constraints=constraints,
            side_effects=side_effects,
        )


class ReFullmatchModel(FunctionModel):
    """Model for re.fullmatch() - match entire string.
    Constraints:
    - String must match pattern completely
    """

    name = "fullmatch"
    qualname = "re.fullmatch"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        pattern = _get_pattern_string(args[0]) if args else None
        string = _get_symbolic_string(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicValue.symbolic(f"fullmatch_{state.pc}")
        constraints = [constraint]
        if pattern is not None and string is not None:
            try:
                z3_pattern = compile_pattern(pattern)
                string_matches = z3.InRe(string.z3_str, z3_pattern)
                constraints.append(result.z3_bool == string_matches)
            except z3.Z3Exception:
                pass
        return ModelResult(
            value=result,
            constraints=constraints,
        )


class ReFindallModel(FunctionModel):
    """Model for re.findall() - find all matches.
    Returns:
    - List of all non-overlapping matches
    Constraints:
    - Result list length >= 0
    - If string matches pattern, result length >= 1
    """

    name = "findall"
    qualname = "re.findall"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        pattern = _get_pattern_string(args[0]) if args else None
        string = _get_symbolic_string(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicList.symbolic(f"findall_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        if pattern is not None and string is not None:
            try:
                z3_pattern = compile_pattern(pattern)
                any_prefix = z3.Star(z3.AllChar(z3.StringSort()))
                any_suffix = z3.Star(z3.AllChar(z3.StringSort()))
                contains_pattern = z3.InRe(
                    string.z3_str, z3.Concat(any_prefix, z3.Concat(z3_pattern, any_suffix))
                )
                constraints.append(z3.Implies(contains_pattern, result.z3_len >= 1))
                constraints.append(result.z3_len <= string.z3_len)
            except z3.Z3Exception:
                pass
        return ModelResult(
            value=result,
            constraints=constraints,
        )


class ReSubModel(FunctionModel):
    """Model for re.sub() - substitute matches.
    Returns:
    - String with matches replaced
    Constraints:
    - If no matches, result == original
    - Result length relationship depends on replacement length
    """

    name = "sub"
    qualname = "re.sub"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        pattern = _get_pattern_string(args[0]) if args else None
        args[1] if len(args) > 1 else None
        string = _get_symbolic_string(args[2]) if len(args) > 2 else None
        result, constraint = SymbolicString.symbolic(f"sub_{state.pc}")
        constraints = [constraint]
        if pattern is not None and string is not None:
            try:
                z3_pattern = compile_pattern(pattern)
                any_prefix = z3.Star(z3.AllChar(z3.StringSort()))
                any_suffix = z3.Star(z3.AllChar(z3.StringSort()))
                contains_pattern = z3.InRe(
                    string.z3_str, z3.Concat(any_prefix, z3.Concat(z3_pattern, any_suffix))
                )
                constraints.append(
                    z3.Implies(z3.Not(contains_pattern), result.z3_str == string.z3_str)
                )
            except z3.Z3Exception:
                pass
        return ModelResult(
            value=result,
            constraints=constraints,
        )


class ReSplitModel(FunctionModel):
    """Model for re.split() - split by pattern.
    Returns:
    - List of strings
    Constraints:
    - Result length >= 1 (always at least one element)
    - If no matches, result length == 1
    """

    name = "split"
    qualname = "re.split"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        pattern = _get_pattern_string(args[0]) if args else None
        string = _get_symbolic_string(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicList.symbolic(f"split_{state.pc}")
        constraints = [constraint, result.z3_len >= 1]
        if pattern is not None and string is not None:
            try:
                z3_pattern = compile_pattern(pattern)
                constraints.append(result.z3_len <= string.z3_len + 1)
                any_prefix = z3.Star(z3.AllChar(z3.StringSort()))
                any_suffix = z3.Star(z3.AllChar(z3.StringSort()))
                contains_pattern = z3.InRe(
                    string.z3_str, z3.Concat(any_prefix, z3.Concat(z3_pattern, any_suffix))
                )
                constraints.append(z3.Implies(z3.Not(contains_pattern), result.z3_len == 1))
            except z3.Z3Exception:
                pass
        return ModelResult(
            value=result,
            constraints=constraints,
        )


class ReCompileModel(FunctionModel):
    """Model for re.compile() - compile pattern.
    Returns a compiled pattern object (modeled symbolically).
    """

    name = "compile"
    qualname = "re.compile"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        pattern = args[0] if args else None
        result, constraint = SymbolicValue.symbolic(f"compiled_{state.pc}")
        if isinstance(pattern, str):
            result.pattern = pattern
        return ModelResult(
            value=result,
            constraints=[constraint],
        )


class ReEscapeModel(FunctionModel):
    """Model for re.escape() - escape special chars.
    Result length >= original length (only adds chars).
    """

    name = "escape"
    qualname = "re.escape"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicString.symbolic(f"escape_{state.pc}")
        constraints = [constraint]
        if original is not None:
            constraints.append(result.z3_len >= original.z3_len)
        return ModelResult(
            value=result,
            constraints=constraints,
        )


REGEX_MODELS: dict[str, FunctionModel] = {
    "re.match": ReMatchModel(),
    "re.search": ReSearchModel(),
    "re.fullmatch": ReFullmatchModel(),
    "re.findall": ReFindallModel(),
    "re.sub": ReSubModel(),
    "re.split": ReSplitModel(),
    "re.compile": ReCompileModel(),
    "re.escape": ReEscapeModel(),
}
__all__ = [
    "REGEX_MODELS",
    "PatternCompiler",
    "ReCompileModel",
    "ReEscapeModel",
    "ReFindallModel",
    "ReFullmatchModel",
    "ReMatchModel",
    "ReSearchModel",
    "ReSplitModel",
    "ReSubModel",
    "compile_pattern",
]
