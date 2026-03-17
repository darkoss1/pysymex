"""Exception analysis: ExceptionAnalyzer, helper functions, and built-in
exception catalog.
"""

from __future__ import annotations

from dataclasses import replace

import z3

from pysymex.core.exceptions_types import (
    ExceptionPath,
    ExceptionState,
    RaisesContract,
    SymbolicException,
)
from pysymex.core.solver import create_solver


class ExceptionAnalyzer:
    """
    Analyzes exception flow in symbolic execution.
    This analyzer helps determine:
    - What exceptions a function may raise
    - Under what conditions they occur
    - Whether exceptions are properly handled
    """

    def __init__(self, solver: z3.Solver | None = None):
        self.solver = solver or create_solver()
        self._exception_paths: list[ExceptionPath] = []
        self._potential_exceptions: list[SymbolicException] = []

    def add_potential_exception(
        self,
        exc: SymbolicException,
        path_condition: z3.BoolRef | None = None,
    ) -> None:
        """Add a potential exception that may be raised."""
        if path_condition is not None:
            exc = replace(exc, condition=z3.And(exc.condition or z3.BoolVal(True), path_condition))
        self._potential_exceptions.append(exc)

    def get_potential_exceptions(self) -> list[SymbolicException]:
        """Get all potential exceptions."""
        return self._potential_exceptions

    def get_exceptions_of_type(
        self,
        exc_type: type[BaseException],
    ) -> list[SymbolicException]:
        """Get potential exceptions of a specific type."""
        result: list[SymbolicException] = []
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
        context_constraints: list[z3.BoolRef] | None = None,
    ) -> tuple[bool, str | None]:
        """
        Verify that a @raises contract is satisfied.

        Args:
            contract: The raises contract to verify.
            context_constraints: Optional path constraints under which to check
                feasibility. When provided, only exceptions whose Z3 condition is
                satisfiable together with these constraints are counted as matching.
                This prevents false positives from infeasible exception paths.

        Returns:
            (satisfied, error_message) — satisfied is True when at least one
            matching exception is feasible under the given constraints.
        """
        matching_exceptions = [exc for exc in self._potential_exceptions if contract.matches(exc)]
        if not matching_exceptions:
            return False, f"No {contract.type_name} exceptions found"

        if not context_constraints:
            return True, None

        # Filter to exceptions that are feasible under the given path constraints.
        feasible: list[SymbolicException] = []
        for exc in matching_exceptions:
            if exc.condition is None or z3.is_true(exc.condition):
                # Unconditional exception — always feasible.
                feasible.append(exc)
                continue
            # Check satisfiability of exc.condition ∧ context_constraints.
            self.solver.push()
            try:
                for c in context_constraints:
                    self.solver.add(c)
                self.solver.add(exc.condition)
                if self.solver.check() == z3.sat:
                    feasible.append(exc)
            finally:
                self.solver.pop()

        if not feasible:
            return (
                False,
                f"No {contract.type_name} exceptions are feasible under the given path constraints",
            )
        return True, None

    def check_unhandled_exceptions(
        self,
        exc_state: ExceptionState,
    ) -> list[SymbolicException]:
        """Get list of potentially unhandled exceptions."""
        unhandled: list[SymbolicException] = []
        for path in exc_state.exception_paths:
            if path.propagated:
                unhandled.append(path.exception)
        return unhandled

    def analyze_division(
        self,
        divisor: object,
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
            z3_val: z3.ExprRef = divisor.to_z3()  # type: ignore[union-attr]
            condition: z3.BoolRef = z3_val == 0
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
        container: object,
        index: object,
        pc: int,
    ) -> SymbolicException | None:
        """Analyze index access for potential IndexError."""
        if hasattr(container, "length"):
            length: object = container.length  # type: ignore[union-attr]
            if isinstance(index, int):
                if hasattr(length, "to_z3"):
                    z3_len: z3.ExprRef = length.to_z3()  # type: ignore[union-attr]
                    condition_i: z3.BoolRef = z3.Or(
                        z3.IntVal(index) >= z3_len,
                        z3.IntVal(index) < -z3_len,
                    )
                    return SymbolicException.symbolic(
                        f"index_error_{pc}",
                        IndexError,
                        condition_i,
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
                z3_idx: z3.ExprRef = index.to_z3()  # type: ignore[union-attr]
                if hasattr(length, "to_z3"):
                    z3_len2: z3.ExprRef = length.to_z3()  # type: ignore[union-attr]
                    condition_s: z3.BoolRef = z3.Or(z3_idx >= z3_len2, z3_idx < -z3_len2)
                else:
                    condition_s = z3.Or(
                        z3_idx >= z3.IntVal(int(length)),
                        z3_idx < z3.IntVal(-int(length)),
                    )
                return SymbolicException.symbolic(
                    f"index_error_{pc}",
                    IndexError,
                    condition_s,
                    pc,
                )
        return None

    def analyze_key_access(
        self,
        container: object,
        key: object,
        pc: int,
    ) -> SymbolicException | None:
        """Analyze key access for potential KeyError."""
        if hasattr(container, "contains"):
            if hasattr(container, "contains_key"):
                contains_result: object = container.contains_key(key)  # type: ignore[union-attr]
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
        obj: object,
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
            has_attr: bool = obj.has_attribute(attr)  # type: ignore[union-attr]
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
        condition: object,
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
            falsy_cond: z3.BoolRef = condition.could_be_falsy()  # type: ignore[union-attr]
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
    args: tuple[object, ...],
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
    seen_paths: set[tuple[str, int]] = set()
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
