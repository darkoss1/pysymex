"""Exception type definitions, data classes, and the @raises decorator.

Contains: ExceptionCategory, SymbolicException, ExceptionHandler, FinallyHandler,
TryBlock, ExceptionPath, ExceptionState, RaisesContract, raises().
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

import z3


class ExceptionCategory(Enum):
    """Coarse category for exception types.

    Used by detectors and reporters to group findings and apply
    category-level filtering.
    """

    RUNTIME = auto()
    TYPE = auto()
    VALUE = auto()
    ARITHMETIC = auto()
    LOOKUP = auto()
    ATTRIBUTE = auto()
    NAME = auto()
    IO = auto()
    MEMORY = auto()
    ASSERTION = auto()
    STOP_ITERATION = auto()
    CUSTOM = auto()


EXCEPTION_CATEGORIES: dict[type[BaseException], ExceptionCategory] = {
    RuntimeError: ExceptionCategory.RUNTIME,
    TypeError: ExceptionCategory.TYPE,
    ValueError: ExceptionCategory.VALUE,
    KeyError: ExceptionCategory.LOOKUP,
    IndexError: ExceptionCategory.LOOKUP,
    AttributeError: ExceptionCategory.ATTRIBUTE,
    NameError: ExceptionCategory.NAME,
    UnboundLocalError: ExceptionCategory.NAME,
    ZeroDivisionError: ExceptionCategory.ARITHMETIC,
    OverflowError: ExceptionCategory.ARITHMETIC,
    ArithmeticError: ExceptionCategory.ARITHMETIC,
    IOError: ExceptionCategory.IO,
    FileNotFoundError: ExceptionCategory.IO,
    MemoryError: ExceptionCategory.MEMORY,
    AssertionError: ExceptionCategory.ASSERTION,
    StopIteration: ExceptionCategory.STOP_ITERATION,
}


EXCEPTION_HIERARCHY: dict[type[BaseException], tuple[type[BaseException], ...]] = {
    UnicodeDecodeError: (ValueError, Exception, BaseException),
    UnicodeEncodeError: (ValueError, Exception, BaseException),
    UnicodeTranslateError: (ValueError, Exception, BaseException),
    UnicodeError: (ValueError, Exception, BaseException),
    ValueError: (Exception, BaseException),
    TypeError: (Exception, BaseException),
    KeyError: (LookupError, Exception, BaseException),
    IndexError: (LookupError, Exception, BaseException),
    LookupError: (Exception, BaseException),
    AttributeError: (Exception, BaseException),
    NameError: (Exception, BaseException),
    UnboundLocalError: (NameError, Exception, BaseException),
    ZeroDivisionError: (ArithmeticError, Exception, BaseException),
    OverflowError: (ArithmeticError, Exception, BaseException),
    FloatingPointError: (ArithmeticError, Exception, BaseException),
    ArithmeticError: (Exception, BaseException),
    FileNotFoundError: (OSError, Exception, BaseException),
    PermissionError: (OSError, Exception, BaseException),
    FileExistsError: (OSError, Exception, BaseException),
    IsADirectoryError: (OSError, Exception, BaseException),
    NotADirectoryError: (OSError, Exception, BaseException),
    IOError: (OSError, Exception, BaseException),
    OSError: (Exception, BaseException),
    RuntimeError: (Exception, BaseException),
    NotImplementedError: (RuntimeError, Exception, BaseException),
    RecursionError: (RuntimeError, Exception, BaseException),
    StopIteration: (Exception, BaseException),
    StopAsyncIteration: (Exception, BaseException),
    AssertionError: (Exception, BaseException),
    ImportError: (Exception, BaseException),
    ModuleNotFoundError: (ImportError, Exception, BaseException),
    MemoryError: (Exception, BaseException),
    EOFError: (Exception, BaseException),
    ConnectionError: (OSError, Exception, BaseException),
    ConnectionResetError: (ConnectionError, OSError, Exception, BaseException),
    ConnectionAbortedError: (ConnectionError, OSError, Exception, BaseException),
    ConnectionRefusedError: (ConnectionError, OSError, Exception, BaseException),
    TimeoutError: (OSError, Exception, BaseException),
    Exception: (BaseException,),
    BaseException: (),
}


def exception_matches(
    exc_type: type[BaseException] | str, handler_type: type[BaseException]
) -> bool:
    """Check if exc_type would be caught by a handler catching handler_type.

    Uses the EXCEPTION_HIERARCHY for recognized types, falling back to
    ``issubclass()`` when both are concrete types.
    """
    if isinstance(exc_type, str):
        return True
    try:
        return issubclass(exc_type, handler_type)
    except TypeError:
        return True


def get_exception_category(exc_type: type[BaseException]) -> ExceptionCategory:
    """Get the category for an exception type."""
    if exc_type in EXCEPTION_CATEGORIES:
        return EXCEPTION_CATEGORIES[exc_type]
    for base in exc_type.__mro__:
        if base in EXCEPTION_CATEGORIES:
            return EXCEPTION_CATEGORIES[base]
    return ExceptionCategory.CUSTOM


@dataclass(frozen=True, slots=True)
class SymbolicException:
    """Represents a symbolic exception during execution.

    In symbolic execution, exceptions can be *concrete* (a specific type
    with known arguments) or *symbolic* (may or may not occur depending
    on path constraints).

    Attributes:
        exc_type: The exception class (or name string if symbolic).
        args: Exception constructor arguments (may be symbolic).
        message: Optional human-readable message.
        traceback: Symbolic traceback as a list of PCs.
        raised_at: PC where the exception was raised.
        condition: Z3 condition under which the exception occurs.
        category: :class:`ExceptionCategory` for analysis grouping.
    """

    exc_type: type[BaseException] | str
    args: tuple[object, ...] = ()
    message: str | None = None
    traceback: list[int] | None = None
    raised_at: int = 0
    condition: z3.BoolRef | None = None
    category: ExceptionCategory = ExceptionCategory.RUNTIME

    @classmethod
    def concrete(
        cls,
        exc_type: type[BaseException],
        *args: object,
        raised_at: int = 0,
    ) -> SymbolicException:
        """Create a concrete exception."""
        category = get_exception_category(exc_type)
        message = str(args[0]) if args else None
        return cls(
            exc_type=exc_type,
            args=args,
            message=message,
            raised_at=raised_at,
            condition=z3.BoolVal(True),
            category=category,
        )

    @classmethod
    def symbolic(
        cls,
        name: str,
        exc_type: type[BaseException] | str,
        condition: z3.BoolRef,
        raised_at: int = 0,
    ) -> SymbolicException:
        """Create a symbolic exception that may occur under a condition."""
        if isinstance(exc_type, type):
            category = get_exception_category(exc_type)
        else:
            category = ExceptionCategory.CUSTOM
        return cls(
            exc_type=exc_type,
            condition=condition,
            raised_at=raised_at,
            category=category,
        )

    @property
    def type_name(self) -> str:
        """Get the exception type name."""
        if isinstance(self.exc_type, type):
            return self.exc_type.__name__
        return str(self.exc_type)

    def is_unconditional(self) -> bool:
        """Check if exception always occurs (no symbolic condition)."""
        if self.condition is None:
            return True
        return bool(z3.is_true(self.condition))

    def may_occur(self, solver: z3.Solver) -> bool:
        """Check if exception may occur given current constraints."""
        if self.condition is None:
            return True
        solver.push()
        try:
            solver.add(self.condition)
            result = solver.check() == z3.sat
        finally:
            solver.pop()
        return bool(result)

    def must_occur(self, solver: z3.Solver) -> bool:
        """Check if exception must occur given current constraints."""
        if self.condition is None:
            return True
        solver.push()
        try:
            solver.add(z3.Not(self.condition))
            result = solver.check() == z3.unsat
        finally:
            solver.pop()
        return bool(result)

    def __str__(self) -> str:
        """Str."""
        """Return a human-readable string representation."""
        cond = f" when {self.condition}" if self.condition and not self.is_unconditional() else ""
        return f"{self.type_name}({self.message or ''}){cond}"


@dataclass(frozen=True, slots=True)
class ExceptionHandler:
    """Represents an ``except`` clause in a try/except block.

    Attributes:
        exc_types: Tuple of exception types caught (``None`` = bare ``except:``).
        target_pc: Bytecode PC to jump to when the exception is caught.
        name: Variable name to bind the exception (``as e``), if any.
        condition: Additional Z3 condition guarding the handler.
    """

    exc_types: tuple[type[BaseException], ...] | None
    target_pc: int
    name: str | None = None
    condition: z3.BoolRef | None = None

    def catches(self, exc: SymbolicException) -> bool:
        """Check if this handler catches the given exception."""
        if self.exc_types is None:
            return True
        if isinstance(exc.exc_type, type):
            return issubclass(exc.exc_type, self.exc_types)
        return True

    def catches_type(self, exc_type: type[BaseException]) -> bool:
        """Check if this handler catches the given exception type."""
        if self.exc_types is None:
            return True
        return issubclass(exc_type, self.exc_types)


@dataclass(frozen=True, slots=True)
class FinallyHandler:
    """Represents a ``finally`` block.

    Attributes:
        target_pc: Bytecode PC of the finally block body.
        exit_pc: Bytecode PC to resume after the finally block completes.
    """

    target_pc: int
    exit_pc: int


@dataclass(frozen=True, slots=True)
class TryBlock:
    """Represents a ``try/except/finally`` block.

    Attributes:
        try_start: Bytecode PC where the try block begins.
        try_end: Bytecode PC where the try block ends.
        handlers: Ordered list of exception handlers.
        finally_handler: Optional finally block.
        else_pc: Bytecode PC of the ``else`` clause, if present.
    """

    try_start: int
    try_end: int
    handlers: list[ExceptionHandler] = field(default_factory=list[ExceptionHandler])
    finally_handler: FinallyHandler | None = None
    else_pc: int | None = None

    def in_try_block(self, pc: int) -> bool:
        """Check if PC is within the try block."""
        return self.try_start <= pc < self.try_end

    def find_handler(self, exc: SymbolicException) -> ExceptionHandler | None:
        """Find a handler for the given exception."""
        for handler in self.handlers:
            if handler.catches(exc):
                return handler
        return None


@dataclass
class ExceptionPath:
    """Tracks an exception as it propagates through execution.

    When an exception is raised, this object records the path constraints
    under which it occurs, which handlers were attempted, and whether it
    was ultimately caught or propagated out of the function.

    Attributes:
        exception: The symbolic exception being tracked.
        path_condition: Z3 conjunction of constraints for this path.
        handlers_tried: Exception handlers that were evaluated.
        caught_by: Handler that caught the exception (``None`` if uncaught).
        propagated: ``True`` if the exception escaped the function.
    """

    exception: SymbolicException
    path_condition: z3.BoolRef = field(default_factory=lambda: z3.BoolVal(True))
    handlers_tried: list[ExceptionHandler] = field(default_factory=list[ExceptionHandler])
    caught_by: ExceptionHandler | None = None
    propagated: bool = False

    def add_condition(self, condition: z3.BoolRef) -> None:
        """Add a path condition."""
        self.path_condition = z3.And(self.path_condition, condition)

    def mark_caught(self, handler: ExceptionHandler) -> None:
        """Mark exception as caught by a handler."""
        self.caught_by = handler
        self.propagated = False

    def mark_propagated(self) -> None:
        """Mark exception as propagated out."""
        self.propagated = True


@dataclass
class ExceptionState:
    """Tracks exception handling state during execution.

    Part of the VM state; maintains a stack of active ``try`` blocks,
    the currently propagating exception, and all exception paths
    discovered so far.

    Attributes:
        try_stack: Stack of active try blocks (innermost last).
        current_exception: Currently raised exception, if any.
        exception_paths: All exception paths discovered on this execution.
        suppressed: Exceptions that were suppressed (e.g. by context managers).
    """

    try_stack: list[TryBlock] = field(default_factory=list[TryBlock])
    current_exception: SymbolicException | None = None
    exception_paths: list[ExceptionPath] = field(default_factory=list[ExceptionPath])
    suppressed: list[SymbolicException] = field(default_factory=list[SymbolicException])

    def push_try(self, block: TryBlock) -> None:
        """Push a try block onto the stack."""
        self.try_stack.append(block)

    def pop_try(self) -> TryBlock | None:
        """Pop a try block from the stack."""
        if self.try_stack:
            return self.try_stack.pop()
        return None

    def current_try(self) -> TryBlock | None:
        """Get the current (innermost) try block."""
        if self.try_stack:
            return self.try_stack[-1]
        return None

    def raise_exception(
        self,
        exc: SymbolicException,
        path_condition: z3.BoolRef | None = None,
    ) -> ExceptionPath:
        """Raise an exception and create an exception path."""
        self.current_exception = exc
        path = ExceptionPath(
            exception=exc,
            path_condition=path_condition or z3.BoolVal(True),
        )
        self.exception_paths.append(path)
        return path

    def handle_exception(
        self,
        exc: SymbolicException,
    ) -> tuple[ExceptionHandler | None, int | None]:
        """
        Find a handler for an exception.
        Returns (handler, target_pc) or (None, None) if not caught.
        """
        for block in reversed(self.try_stack):
            handler = block.find_handler(exc)
            if handler:
                return handler, handler.target_pc
        return None, None

    def clear_exception(self) -> None:
        """Clear the current exception (after handling)."""
        self.current_exception = None

    def suppress(self, exc: SymbolicException) -> None:
        """Suppress an exception (e.g., in a context manager)."""
        self.suppressed.append(exc)
        if self.current_exception == exc:
            self.clear_exception()

    def clone(self) -> ExceptionState:
        """Create a copy of this exception state."""
        return ExceptionState(
            try_stack=list(self.try_stack),
            current_exception=self.current_exception,
            exception_paths=list(self.exception_paths),
            suppressed=list(self.suppressed),
        )


@dataclass(frozen=True, slots=True)
class RaisesContract:
    """Annotation for the ``@raises`` contract decorator.

    ``@raises('ValueError', when='x < 0')`` declares that the function
    may raise ``ValueError`` when ``x < 0``.

    Attributes:
        exc_type: Expected exception type (class or name string).
        condition: Optional expression string describing when the exception may occur.
        message: Optional expected message pattern.
    """

    exc_type: type[BaseException] | str
    condition: str | None = None
    message: str | None = None

    @property
    def type_name(self) -> str:
        """Type name."""
        """Property returning the type_name."""
        if isinstance(self.exc_type, type):
            return self.exc_type.__name__
        return str(self.exc_type)

    def matches(self, exc: SymbolicException) -> bool:
        """Check if an exception matches this contract."""
        if isinstance(self.exc_type, type):
            if isinstance(exc.exc_type, type):
                if not issubclass(exc.exc_type, self.exc_type):
                    return False
            else:
                if exc.type_name != self.type_name:
                    return False
        else:
            if exc.type_name != self.exc_type:
                return False
        if self.message and exc.message:
            if self.message not in exc.message:
                return False
        return True


def raises(
    exc_type: type[BaseException] | str,
    when: str | None = None,
    message: str | None = None,
) -> Callable[[Callable[..., object]], Callable[..., object]]:
    """Decorator to declare that a function may raise an exception.

    Args:
        exc_type: Exception type (class or name string).
        when: Optional condition expression.
        message: Optional expected message pattern.

    Returns:
        A decorator that attaches a :class:`RaisesContract` to the function.

    Example::

        @raises(ValueError, when='x < 0')
        def sqrt(x: float) -> float:
            if x < 0:
                raise ValueError("negative")
            return x ** 0.5
    """
    contract = RaisesContract(exc_type, when, message)

    def decorator(func: Callable[..., object]) -> Callable[..., object]:
        """Decorator."""
        func_any: Any = func
        if not hasattr(func_any, "__raises__"):
            func_any.__raises__ = []
        func_any.__raises__.append(contract)
        return func

    return decorator
