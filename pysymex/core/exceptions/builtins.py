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

"""Built-in exception catalog helpers."""

from __future__ import annotations

import builtins


def _optional_builtin_exceptions() -> frozenset[type[BaseException]]:
    """Return builtin exception types present only on supported runtimes."""
    names = ("PythonFinalizationError",)
    optional: set[type[BaseException]] = set()
    for name in names:
        value = getattr(builtins, name, None)
        if isinstance(value, type) and issubclass(value, BaseException):
            optional.add(value)
    return frozenset(optional)


BUILTIN_EXCEPTIONS: frozenset[type[BaseException]] = (
    frozenset(
        {
            BaseException,
            BaseExceptionGroup,
            Exception,
            ExceptionGroup,
            ArithmeticError,
            AssertionError,
            AttributeError,
            BlockingIOError,
            BrokenPipeError,
            BufferError,
            BytesWarning,
            ChildProcessError,
            ConnectionAbortedError,
            ConnectionError,
            ConnectionRefusedError,
            ConnectionResetError,
            DeprecationWarning,
            EncodingWarning,
            EOFError,
            EnvironmentError,
            FileExistsError,
            FileNotFoundError,
            FloatingPointError,
            FutureWarning,
            GeneratorExit,
            IOError,
            ImportError,
            ImportWarning,
            IndentationError,
            IndexError,
            InterruptedError,
            IsADirectoryError,
            KeyError,
            KeyboardInterrupt,
            LookupError,
            MemoryError,
            ModuleNotFoundError,
            NameError,
            NotADirectoryError,
            NotImplementedError,
            OSError,
            OverflowError,
            PendingDeprecationWarning,
            PermissionError,
            ProcessLookupError,
            RecursionError,
            ReferenceError,
            ResourceWarning,
            RuntimeError,
            RuntimeWarning,
            StopAsyncIteration,
            StopIteration,
            SyntaxError,
            SyntaxWarning,
            SystemError,
            SystemExit,
            TabError,
            TimeoutError,
            TypeError,
            UnboundLocalError,
            UnicodeDecodeError,
            UnicodeEncodeError,
            UnicodeError,
            UnicodeTranslateError,
            UnicodeWarning,
            UserWarning,
            ValueError,
            Warning,
            ZeroDivisionError,
        }
    )
    | _optional_builtin_exceptions()
)
