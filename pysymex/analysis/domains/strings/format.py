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

"""Analyse ``str.format`` and ``%``-style format strings for type/count errors."""

from __future__ import annotations

import re

from pysymex.typing import is_list_of_objects, is_tuple_of_objects
from pysymex.analysis.domains.strings.types import StringWarning, StringWarningKind


PRINTF_FORMAT_SPEC = re.compile(
    r"%"
    r"(?:\((?P<key>\w+)\))?"
    r"(?P<flags>[-+0 #]*)?"
    r"(?P<width>\*|\d+)?"
    r"(?:\.(?P<precision>\*|\d+))?"
    r"(?P<length>[hlL])?"
    r"(?P<type>[diouxXeEfFgGcrsab%])"
)


class PrintfFormatAnalyzer:
    """
    Analyzes printf-style format strings (% operator).
    """

    def analyze(
        self,
        format_string: str,
        args: object,
        line: int,
        file_path: str,
    ) -> list[StringWarning]:
        """Analyze printf-style format string."""
        warnings: list[StringWarning] = []
        specs = list(PRINTF_FORMAT_SPEC.finditer(format_string))
        specs = [s for s in specs if s.group("type") != "%"]
        if not specs:
            return warnings
        has_keys = any(s.group("key") for s in specs)
        if has_keys:
            for spec in specs:
                if not spec.group("key"):
                    warnings.append(
                        StringWarning(
                            kind=StringWarningKind.INVALID_FORMAT_SPEC,
                            file=file_path,
                            line=line,
                            message="Mixed positional and named format specifiers",
                            code_snippet=format_string,
                        )
                    )
                    break
        else:
            expected = 0
            for spec in specs:
                expected += 1
                if spec.group("width") == "*":
                    expected += 1
                if spec.group("precision") == "*":
                    expected += 1
            if is_tuple_of_objects(args):
                actual = len(args)
                if actual < expected:
                    warnings.append(
                        StringWarning(
                            kind=StringWarningKind.MISSING_FORMAT_ARG,
                            file=file_path,
                            line=line,
                            message=f"Format string expects {expected} arguments, got {actual}",
                            code_snippet=format_string,
                            severity="error",
                        )
                    )
                elif actual > expected:
                    warnings.append(
                        StringWarning(
                            kind=StringWarningKind.EXTRA_FORMAT_ARG,
                            file=file_path,
                            line=line,
                            message=f"Format string expects {expected} arguments, got {actual}",
                            code_snippet=format_string,
                        )
                    )
            elif is_list_of_objects(args):
                actual = len(args)
                if actual < expected:
                    warnings.append(
                        StringWarning(
                            kind=StringWarningKind.MISSING_FORMAT_ARG,
                            file=file_path,
                            line=line,
                            message=f"Format string expects {expected} arguments, got {actual}",
                            code_snippet=format_string,
                            severity="error",
                        )
                    )
                elif actual > expected:
                    warnings.append(
                        StringWarning(
                            kind=StringWarningKind.EXTRA_FORMAT_ARG,
                            file=file_path,
                            line=line,
                            message=f"Format string expects {expected} arguments, got {actual}",
                            code_snippet=format_string,
                        )
                    )
        return warnings


STR_FORMAT_FIELD = re.compile(
    r"\{" r"(?P<field>[^{}:!]*)" r"(?:!(?P<conversion>[rsab]))?" r"(?::(?P<spec>[^{}]*))?" r"\}"
)


class StrFormatAnalyzer:
    """
    Analyzes str.format() calls.
    """

    def analyze(
        self,
        format_string: str,
        args: tuple[object, ...],
        kwargs: dict[str, object],
        line: int,
        file_path: str,
    ) -> list[StringWarning]:
        """Analyze str.format() call."""
        warnings: list[StringWarning] = []
        fields = list(STR_FORMAT_FIELD.finditer(format_string))
        if not fields:
            return warnings
        positional_refs: list[int] = []
        named_refs: set[str] = set()
        auto_index = 0
        uses_auto = False
        uses_manual = False
        for match in fields:
            field = match.group("field")
            if not field:
                uses_auto = True
                positional_refs.append(auto_index)
                auto_index += 1
            elif field.isdigit():
                uses_manual = True
                positional_refs.append(int(field))
            else:
                base_name = field.split(".")[0].split("[")[0]
                if base_name.isdigit():
                    uses_manual = True
                    positional_refs.append(int(base_name))
                else:
                    named_refs.add(base_name)
        if uses_auto and uses_manual:
            warnings.append(
                StringWarning(
                    kind=StringWarningKind.INVALID_FORMAT_SPEC,
                    file=file_path,
                    line=line,
                    message="Cannot mix automatic and manual field numbering",
                    code_snippet=format_string,
                    severity="error",
                )
            )
        if positional_refs:
            max_index = max(positional_refs)
            if len(args) <= max_index:
                warnings.append(
                    StringWarning(
                        kind=StringWarningKind.MISSING_FORMAT_ARG,
                        file=file_path,
                        line=line,
                        message=f"Format string references index {max_index}, but only {len(args)} positional arguments",
                        code_snippet=format_string,
                        severity="error",
                    )
                )
        for name in named_refs:
            if name not in kwargs:
                warnings.append(
                    StringWarning(
                        kind=StringWarningKind.MISSING_FORMAT_ARG,
                        file=file_path,
                        line=line,
                        message=f"Format string references '{name}' but it's not in keyword arguments",
                        code_snippet=format_string,
                    )
                )
        return warnings
