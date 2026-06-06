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

from __future__ import annotations

from typing import TYPE_CHECKING

from .shared import (
    FunctionModel,
    ModelResult,
    SymbolicString,
    SymbolicValue,
    bytes_type_error_result,
    concrete_bytes_literal,
    get_symbolic_bytes,
)
from pysymex.models.containers.strings.shared import concrete_string_literal

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

"""Decode symbolic bytes models."""


class BytesDecodeModel(FunctionModel):
    """Model for bytes.decode()."""

    name = "decode"
    qualname = "bytes.decode"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if (
            len(args) not in {1, 2, 3}
            or set(kwargs) - {"encoding", "errors"}
            or (len(args) > 1 and "encoding" in kwargs)
            or (len(args) > 2 and "errors" in kwargs)
        ):
            return bytes_type_error_result(self.name, state)
        exact, invalid_args = _exact_decode_result(args, kwargs)
        if invalid_args:
            return bytes_type_error_result(self.name, state)
        if exact is not None:
            return ModelResult(value=SymbolicString.from_const(exact))
        b = get_symbolic_bytes(args[0], state) if args else None
        result, constraint = SymbolicString.symbolic(f"decode_{state.pc}")
        constraints = [constraint]
        if b is not None:
            constraints.append(result.z3_len <= b.z3_len)
            constraints.append(result.z3_len >= 0)
        return ModelResult(value=result, constraints=constraints)


class BytearrayDecodeModel(BytesDecodeModel):
    """Model for bytearray.decode()."""

    qualname = "bytearray.decode"


_MISSING = object()


def _exact_decode_result(
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> tuple[str | None, bool]:
    source = concrete_bytes_literal(args[0])
    if source is None:
        return None, False
    encoding_arg = args[1] if len(args) > 1 else kwargs.get("encoding", _MISSING)
    errors_arg = args[2] if len(args) > 2 else kwargs.get("errors", _MISSING)
    encoding = "utf-8"
    errors = "strict"
    if encoding_arg is not _MISSING:
        encoding_value, invalid = _required_text_argument(encoding_arg)
        if invalid:
            return None, True
        if encoding_value is None:
            return None, False
        encoding = encoding_value
    if errors_arg is not _MISSING:
        errors_value, invalid = _required_text_argument(errors_arg)
        if invalid:
            return None, True
        if errors_value is None:
            return None, False
        errors = errors_value
    try:
        return source.decode(encoding, errors), False
    except TypeError:
        return None, True
    except (LookupError, UnicodeError):
        return None, False


def _required_text_argument(value: object) -> tuple[str | None, bool]:
    text = concrete_string_literal(value)
    if text is not None:
        return text, False
    if isinstance(value, SymbolicValue):
        return None, value.value is not None
    if isinstance(value, SymbolicString):
        return None, False
    return None, True
