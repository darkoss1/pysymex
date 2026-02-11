"""
Exception Modeling for PySpectre.
Phase 18: Exception model for symbolic execution of Python bytecode.
This module provides:
- SymbolicException: Base class for symbolic exceptions
- ExceptionPath: Tracks exception paths through code
- TryExceptHandler: Models try/except/finally blocks
- RaisesContract: @raises decorator support
- ExceptionAnalyzer: Analyzes exception flow
Exceptions create hidden control flow that must be tracked symbolically.
"""

from __future__ import annotations
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
)
import z3


class ExceptionCategory(Enum):
    """Categories of exceptions for analysis."""

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


def get_exception_category(exc_type: type[BaseException]) -> ExceptionCategory:
    """Get the category for an exception type."""
    if exc_type in EXCEPTION_CATEGORIES:
        return EXCEPTION_CATEGORIES[exc_type]
    for base in exc_type.__mro__:
        if base in EXCEPTION_CATEGORIES:
            return EXCEPTION_CATEGORIES[base]
    return ExceptionCategory.CUSTOM


@dataclass
class SymbolicException:
    """
    Represents a symbolic exception.
    In symbolic execution, exceptions can be:
    - Concrete: A specific exception type with known args
    - Symbolic: An exception that may or may not occur based on constraints
    Attributes:
        exc_type: The exception class (or name if symbolic)
        args: Exception arguments (may contain symbolic values)
        message: Optional message
        traceback: Symbolic traceback info
        raised_at: PC where exception was raised
        condition: Z3 condition under which exception is raised
        category: Exception category for analysis
    """

    exc_type: type[BaseException] | str
    args: tuple[Any, ...] = ()
    message: str | None = None
    traceback: list[int] | None = None
    raised_at: int = 0
    condition: z3.BoolRef | None = None
    category: ExceptionCategory = ExceptionCategory.RUNTIME

    @classmethod
    def concrete(
        cls,
        exc_type: type[BaseException],
        *args: Any,
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
        return z3.is_true(self.condition)

    def may_occur(self, solver: z3.Solver) -> bool:
        """Check if exception may occur given current constraints."""
        if self.condition is None:
            return True
        solver.push()
        solver.add(self.condition)
        result = solver.check() == z3.sat
        solver.pop()
        return result

    def must_occur(self, solver: z3.Solver) -> bool:
        """Check if exception must occur given current constraints."""
        if self.condition is None:
            return True
        solver.push()
        solver.add(z3.Not(self.condition))
        result = solver.check() == z3.unsat
        solver.pop()
        return result

    def __str__(self) -> str:
        cond = f" when {self.condition}" if self.condition and not self.is_unconditional() else ""
        return f"{self.type_name}({self.message or ''}){cond}"


@dataclass
class ExceptionHandler:
    """
    Represents an exception handler (except clause).
    Attributes:
        exc_types: Types of exceptions caught (None = catch all)
        target_pc: PC to jump to when caught
        name: Variable name to bind exception (optional)
        condition: Additional condition for handler
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


@dataclass
class FinallyHandler:
    """
    Represents a finally block.
    Attributes:
        target_pc: PC of finally block
        exit_pc: PC after finally completes
    """

    target_pc: int
    exit_pc: int


@dataclass
class TryBlock:
    """
    Represents a try/except/finally block.
    Attributes:
        try_start: PC where try block starts
        try_end: PC where try block ends
        handlers: List of exception handlers
        finally_handler: Optional finally block
        else_pc: Optional else block PC
    """

    try_start: int
    try_end: int
    handlers: list[ExceptionHandler] = field(default_factory=list)
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
    """
    Tracks an exception path through execution.
    When an exception is raised, we need to track:
    - The exception itself
    - The path constraints under which it occurs
    - Where it propagates to
    Attributes:
        exception: The symbolic exception
        path_condition: Z3 condition for this path
        handlers_tried: Handlers that were tried
        caught_by: Handler that caught it (if any)
        propagated: Whether exception propagated out
    """

    exception: SymbolicException
    path_condition: z3.BoolRef = field(default_factory=lambda: z3.BoolVal(True))
    handlers_tried: list[ExceptionHandler] = field(default_factory=list)
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
    """
    Tracks exception state during execution.
    This is part of the VM state and tracks:
    - Active try blocks
    - Current exception being handled
    - Exception paths taken
    Attributes:
        try_stack: Stack of active try blocks
        current_exception: Currently raised exception (if any)
        exception_paths: All exception paths discovered
        suppressed: Exceptions that were suppressed
    """

    try_stack: list[TryBlock] = field(default_factory=list)
    current_exception: SymbolicException | None = None
    exception_paths: list[ExceptionPath] = field(default_factory=list)
    suppressed: list[SymbolicException] = field(default_factory=list)

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
        path_condition: z3.BoolRef = None,
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


@dataclass
class RaisesContract:
    """
    Represents a @raises contract annotation.
    @raises('ValueError', when='x < 0')
    means the function may raise ValueError when x < 0.
    Attributes:
        exc_type: Exception type (or name)
        condition: When the exception may be raised
        message: Expected message pattern (optional)
    """

    exc_type: type[BaseException] | str
    condition: str | None = None
    message: str | None = None

    @property
    def type_name(self) -> str:
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
) -> Callable:
    """
    Decorator to specify that a function may raise an exception.
    Usage:
        @raises(ValueError, when='x < 0')
        def sqrt(x: float) -> float:
            if x < 0:
                raise ValueError("negative")
            return x ** 0.5
    """
    contract = RaisesContract(exc_type, when, message)

    def decorator(func: Callable) -> Callable:
        if not hasattr(func, "__raises__"):
            func.__raises__ = []
        func.__raises__.append(contract)
        return func

    return decorator


class ExceptionAnalyzer:
    """
    Analyzes exception flow in symbolic execution.
    This analyzer helps determine:
    - What exceptions a function may raise
    - Under what conditions they occur
    - Whether exceptions are properly handled
    """

    def __init__(self, solver: z3.Solver | None = None):
        self.solver = solver or z3.Solver()
        self._exception_paths: list[ExceptionPath] = []
        self._potential_exceptions: list[SymbolicException] = []

    def add_potential_exception(
        self,
        exc: SymbolicException,
        path_condition: z3.BoolRef = None,
    ) -> None:
        """Add a potential exception that may be raised."""
        if path_condition:
            exc.condition = z3.And(exc.condition or z3.BoolVal(True), path_condition)
        self._potential_exceptions.append(exc)

    def get_potential_exceptions(self) -> list[SymbolicException]:
        """Get all potential exceptions."""
        return self._potential_exceptions

    def get_exceptions_of_type(
        self,
        exc_type: type[BaseException],
    ) -> list[SymbolicException]:
        """Get potential exceptions of a specific type."""
        result = []
        for exc in self._potential_exceptions:
            if isinstance(exc.exc_type, type):
                if issubclass(exc.exc_type, exc_type):
                    result.append(exc)
            elif exc.type_name == exc_type.__name__:
                result.append(exc)
        return result

    def verify_raises_contract(
        self,
        contract: RaisesContract,
        context_constraints: list[z3.BoolRef] = None,
    ) -> tuple[bool, str | None]:
        """
        Verify that a @raises contract is satisfied.
        Returns (satisfied, error_message).
        """
        matching_exceptions = [exc for exc in self._potential_exceptions if contract.matches(exc)]
        if not matching_exceptions:
            return False, f"No {contract.type_name} exceptions found"
        return True, None

    def check_unhandled_exceptions(
        self,
        exc_state: ExceptionState,
    ) -> list[SymbolicException]:
        """Get list of potentially unhandled exceptions."""
        unhandled = []
        for path in exc_state.exception_paths:
            if path.propagated:
                unhandled.append(path.exception)
        return unhandled

    def analyze_division(
        self,
        divisor: Any,
        pc: int,
    ) -> SymbolicException | None:
        """Analyze division for potential ZeroDivisionError."""
        if isinstance(divisor, (int, float)):
            if divisor == 0:
                return SymbolicException.concrete(
                    ZeroDivisionError,
                    "division by zero",
                    raised_at=pc,
                )
            return None
        if hasattr(divisor, "to_z3"):
            z3_val = divisor.to_z3()
            condition = z3_val == 0
            return SymbolicException.symbolic(
                f"div_zero_{pc}",
                ZeroDivisionError,
                condition,
                pc,
            )
        return SymbolicException.symbolic(
            f"div_zero_{pc}",
            ZeroDivisionError,
            z3.Bool(f"may_zero_{pc}"),
            pc,
        )

    def analyze_index_access(
        self,
        container: Any,
        index: Any,
        pc: int,
    ) -> SymbolicException | None:
        """Analyze index access for potential IndexError."""
        if hasattr(container, "length"):
            length = container.length
            if isinstance(index, int):
                if hasattr(length, "to_z3"):
                    z3_len = length.to_z3()
                    condition = z3.Or(
                        z3.IntVal(index) >= z3_len,
                        z3.IntVal(index) < -z3_len,
                    )
                    return SymbolicException.symbolic(
                        f"index_error_{pc}",
                        IndexError,
                        condition,
                        pc,
                    )
                elif isinstance(length, int):
                    if index >= length or index < -length:
                        return SymbolicException.concrete(
                            IndexError,
                            "index out of range",
                            raised_at=pc,
                        )
                    return None
            if hasattr(index, "to_z3"):
                z3_idx = index.to_z3()
                if hasattr(length, "to_z3"):
                    z3_len = length.to_z3()
                    condition = z3.Or(z3_idx >= z3_len, z3_idx < -z3_len)
                else:
                    condition = z3.Or(
                        z3_idx >= z3.IntVal(length),
                        z3_idx < z3.IntVal(-length),
                    )
                return SymbolicException.symbolic(
                    f"index_error_{pc}",
                    IndexError,
                    condition,
                    pc,
                )
        return None

    def analyze_key_access(
        self,
        container: Any,
        key: Any,
        pc: int,
    ) -> SymbolicException | None:
        """Analyze key access for potential KeyError."""
        if hasattr(container, "contains"):
            if hasattr(container, "contains_key"):
                contains_result = container.contains_key(key)
                if isinstance(contains_result, bool):
                    if not contains_result:
                        return SymbolicException.concrete(
                            KeyError,
                            str(key),
                            raised_at=pc,
                        )
                    return None
        return SymbolicException.symbolic(
            f"key_error_{pc}",
            KeyError,
            z3.Bool(f"key_missing_{pc}"),
            pc,
        )

    def analyze_attribute_access(
        self,
        obj: Any,
        attr: str,
        pc: int,
    ) -> SymbolicException | None:
        """Analyze attribute access for potential AttributeError."""
        if obj is None:
            return SymbolicException.concrete(
                AttributeError,
                f"'NoneType' object has no attribute '{attr}'",
                raised_at=pc,
            )
        if hasattr(obj, "has_attribute"):
            has_attr = obj.has_attribute(attr)
            if isinstance(has_attr, bool):
                if not has_attr:
                    type_name = type(obj).__name__
                    return SymbolicException.concrete(
                        AttributeError,
                        f"'{type_name}' object has no attribute '{attr}'",
                        raised_at=pc,
                    )
                return None
        return None

    def analyze_assertion(
        self,
        condition: Any,
        message: str | None,
        pc: int,
    ) -> SymbolicException | None:
        """Analyze assertion for potential AssertionError."""
        if isinstance(condition, bool):
            if not condition:
                return SymbolicException.concrete(
                    AssertionError,
                    message or "",
                    raised_at=pc,
                )
            return None
        if hasattr(condition, "could_be_falsy"):
            falsy_cond = condition.could_be_falsy()
            return SymbolicException.symbolic(
                f"assertion_{pc}",
                AssertionError,
                falsy_cond,
                pc,
            )
        return SymbolicException.symbolic(
            f"assertion_{pc}",
            AssertionError,
            z3.Bool(f"assert_fail_{pc}"),
            pc,
        )


def create_exception_from_opcode(
    exc_type: type[BaseException],
    args: tuple[Any, ...],
    pc: int,
) -> SymbolicException:
    """Create a SymbolicException from a RAISE_VARARGS opcode."""
    return SymbolicException.concrete(exc_type, *args, raised_at=pc)


def propagate_exception(
    exc_state: ExceptionState,
    exc: SymbolicException,
) -> tuple[bool, int | None]:
    """
    Propagate an exception through try blocks.
    Returns (handled, target_pc) where:
    - handled=True, target_pc=handler PC if caught
    - handled=False, target_pc=None if propagates out
    """
    handler, target_pc = exc_state.handle_exception(exc)
    if handler:
        return True, target_pc
    return False, None


def merge_exception_states(
    states: list[ExceptionState],
) -> ExceptionState:
    """Merge multiple exception states (for path joins)."""
    if not states:
        return ExceptionState()
    if len(states) == 1:
        return states[0].clone()
    result = ExceptionState()
    min_depth = min(len(s.try_stack) for s in states)
    for i in range(min_depth):
        blocks = [s.try_stack[i] for s in states]
        if all(b.try_start == blocks[0].try_start for b in blocks):
            result.try_stack.append(blocks[0])
        else:
            break
    seen_paths = set()
    for state in states:
        for path in state.exception_paths:
            key = (path.exception.type_name, path.exception.raised_at)
            if key not in seen_paths:
                seen_paths.add(key)
                result.exception_paths.append(path)
    for state in states:
        if state.current_exception:
            result.current_exception = state.current_exception
            break
    return result


def check_precondition_violation(
    condition_expr: z3.BoolRef,
    message: str,
    pc: int,
) -> SymbolicException | None:
    """Create exception for precondition violation."""
    return SymbolicException.symbolic(
        f"precondition_{pc}",
        AssertionError,
        z3.Not(condition_expr),
        pc,
    )


def check_postcondition_violation(
    condition_expr: z3.BoolRef,
    message: str,
    pc: int,
) -> SymbolicException | None:
    """Create exception for postcondition violation."""
    return SymbolicException.symbolic(
        f"postcondition_{pc}",
        AssertionError,
        z3.Not(condition_expr),
        pc,
    )


def check_invariant_violation(
    condition_expr: z3.BoolRef,
    message: str,
    pc: int,
) -> SymbolicException | None:
    """Create exception for invariant violation."""
    return SymbolicException.symbolic(
        f"invariant_{pc}",
        AssertionError,
        z3.Not(condition_expr),
        pc,
    )


BUILTIN_EXCEPTIONS: frozenset[type[BaseException]] = frozenset(
    {
        BaseException,
        Exception,
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


def is_builtin_exception(exc_type: type[BaseException]) -> bool:
    """Check if an exception type is a built-in."""
    return exc_type in BUILTIN_EXCEPTIONS


def get_exception_hierarchy(exc_type: type[BaseException]) -> list[type[BaseException]]:
    """Get the exception hierarchy (MRO) for an exception type."""
    return [t for t in exc_type.__mro__ if issubclass(t, BaseException)]
