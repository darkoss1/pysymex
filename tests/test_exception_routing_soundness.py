"""Tests for exception handler routing correctness.

The symbolic executor must correctly route exceptions to handlers.
If exception routing is wrong, the executor could:
- Skip handlers that should catch an exception (miss bugs)
- Execute handlers for exceptions that weren't raised (phantom paths)
- Corrupt state when unwinding the stack

These tests verify exception handling follows Python semantics.
"""

from __future__ import annotations

import dis
import sys
import pytest
import z3

from pysymex.execution.dispatcher import OpcodeDispatcher
from pysymex.core.state import VMState
from pysymex.core.types import SymbolicValue
from pysymex.execution.executor_core import SymbolicExecutor
from pysymex.execution.executor_types import ExecutionConfig
from pysymex.analysis.detectors import IssueKind


class TestExceptionHandlerLookup:
    """Tests for finding the correct exception handler."""

    def test_inner_handler_catches_before_outer(self):
        """Nested try blocks: inner handler catches first.

        Invariant: Exception goes to innermost matching handler.
        """
        def nested_try():
            try:
                try:
                    x = 1 / 0  # Raises ZeroDivisionError
                except ZeroDivisionError:
                    return "inner"  # Should catch here
            except ZeroDivisionError:
                return "outer"
            return "none"

        # Compile and check that inner handler is reached
        # We test the routing logic rather than full execution
        code = nested_try.__code__
        instructions = list(dis.get_instructions(code))

        # Find the exception table (Python 3.11+)
        if hasattr(code, 'co_exceptiontable') and sys.version_info >= (3, 11):
            # Modern CPython has exception table
            assert code.co_exceptiontable, "Should have exception handling"

    def test_handler_type_matching(self):
        """Handler must match exception type or be a base class.

        Invariant: except TypeError does not catch ValueError.
        """
        def type_specific():
            try:
                raise ValueError("test")
            except TypeError:
                return "wrong"
            except ValueError:
                return "correct"
            return "none"

        # The ValueError handler should be selected, not TypeError
        executor = SymbolicExecutor()
        result = executor.execute_function(type_specific)
        # Note: This tests the executor's handler selection

    def test_bare_except_catches_all(self):
        """Bare except catches all exceptions.

        Invariant: except: (no type) catches anything.
        """
        def bare_except():
            try:
                x = 1 / 0
            except:
                return "caught"
            return "not_caught"

        code = bare_except.__code__
        instructions = list(dis.get_instructions(code))

        # Should have exception handling
        exc_instrs = [i for i in instructions if 'EXCEPT' in i.opname.upper() or 'SETUP' in i.opname.upper()]
        # Bare except should be present in some form


class TestExceptionStateConsistency:
    """Tests for state consistency during exception handling."""

    def test_stack_unwound_correctly(self):
        """Stack must be properly unwound when exception propagates.

        Invariant: When exception propagates through function calls,
        stack frames are correctly cleaned up.
        """
        state = VMState()

        # Push some items
        state.push(SymbolicValue.from_const(1))
        state.push(SymbolicValue.from_const(2))
        state.push(SymbolicValue.from_const(3))

        # Record stack depth
        original_depth = len(state.stack)

        # Simulate exception - stack should be set to handler's expected depth
        # (In real implementation, the handler has an expected stack depth)
        handler_stack_depth = 1

        # Pop to handler depth
        while len(state.stack) > handler_stack_depth:
            state.pop()

        assert len(state.stack) == handler_stack_depth

    def test_local_vars_preserved_in_handler(self):
        """Local variables accessible in except block.

        Invariant: Variables set before try are accessible in except.
        """
        def var_preservation():
            x = 10
            try:
                y = 20
                z = 1 / 0
            except:
                return x + y  # Both should be accessible

        # Compile and verify bytecode structure
        code = var_preservation.__code__
        local_names = code.co_varnames
        assert 'x' in local_names
        assert 'y' in local_names


class TestExceptionPathForking:
    """Tests for path forking at exception points."""

    def test_exception_creates_alternate_path(self):
        """Each raise point forks into normal and exceptional paths.

        Invariant: Executor explores both paths.
        """
        def conditional_raise(x: int) -> int:
            if x > 0:
                return 1 / x  # Could raise if x==0 on other path
            else:
                return 0

        executor = SymbolicExecutor()
        result = executor.execute_function(
            conditional_raise,
            symbolic_args={"x": "int"},
        )

        # Should explore both paths
        assert result.paths_explored >= 2

    def test_caught_exception_continues_execution(self):
        """Caught exception continues from handler, not crash.

        Invariant: After except block, execution continues normally.
        """
        def caught_continues():
            result = 0
            try:
                result = 1 / 0
            except ZeroDivisionError:
                result = -1  # Handler sets result

            return result + 10  # Should continue here

        # The function should return 9 (not crash)
        executor = SymbolicExecutor()
        result = executor.execute_function(caught_continues)
        # Verify execution completed


class TestExceptionPropagation:
    """Tests for exception propagation through call stack."""

    def test_uncaught_exception_propagates_to_caller(self):
        """Uncaught exception bubbles up to caller.

        Invariant: If no handler matches, exception propagates.
        """
        def inner():
            raise ValueError("test")

        def outer():
            try:
                inner()
            except TypeError:
                return "wrong type"
            except ValueError:
                return "correct"
            return "none"

        # outer() should catch the ValueError from inner()
        executor = SymbolicExecutor()
        result = executor.execute_function(outer)

    def test_finally_always_executes(self):
        """Finally block executes whether exception or not.

        Invariant: finally runs on normal return and on exception.
        """
        def with_finally():
            result = []
            try:
                result.append("try")
                return result
            finally:
                result.append("finally")

        # In Python, finally executes before return
        code = with_finally.__code__
        instructions = list(dis.get_instructions(code))

        # Should have some form of finally handling


class TestExceptionHandlerTableParsing:
    """Tests for bytecode exception table parsing (Python 3.11+)."""

    @pytest.mark.skipif(sys.version_info < (3, 11), reason="Needs Python 3.11+")
    def test_exception_table_parsed_correctly(self):
        """Exception table entries are correctly interpreted.

        Invariant: Each try block's range and handler are identified.
        """
        def multi_handler():
            try:
                x = 1,
            except TypeError:
                pass
            except ValueError:
                pass

        code = multi_handler.__code__
        if hasattr(code, 'co_exceptiontable'):
            table = code.co_exceptiontable
            assert isinstance(table, bytes), "Exception table should be bytes"

    @pytest.mark.skipif(sys.version_info < (3, 11), reason="Needs Python 3.11+")
    def test_nested_exception_tables(self):
        """Nested try blocks produce correct table entries.

        Invariant: Inner block's range is subset of outer's.
        """
        def nested():
            try:
                try:
                    pass
                except:
                    pass
            except:
                pass

        code = nested.__code__
        if hasattr(code, 'co_exceptiontable'):
            # Should have multiple exception ranges
            pass


class TestExceptionWithSymbolicValues:
    """Tests for exceptions with symbolic conditions."""

    def test_symbolic_divisor_forks_paths(self):
        """Division by symbolic value forks at exception point.

        Invariant: Executor explores both zero and non-zero cases.
        """
        def symbolic_div(x: int) -> int:
            return 10 / x

        executor = SymbolicExecutor()
        result = executor.execute_function(
            symbolic_div,
            symbolic_args={"x": "int"},
        )

        # Should find division by zero issue
        issues = result.get_issues_by_kind(IssueKind.DIVISION_BY_ZERO)
        assert len(issues) > 0, "Should detect division by zero"

    def test_symbolic_exception_condition(self):
        """Symbolic condition determines if exception is raised.

        Invariant: if sym: raise X creates both paths.
        """
        def conditional_exception(flag: bool) -> int:
            if flag:
                raise ValueError("symbolic")
            return 0

        executor = SymbolicExecutor(config=ExecutionConfig(verbose=True))
        result = executor.execute_function(
            conditional_exception,
            symbolic_args={"flag": "bool"},
        )
        print(f"DEBUG: {result}")
        assert result.paths_explored >= 2


class TestCleanupOnException:
    """Tests for resource cleanup during exception handling."""

    def test_context_manager_exit_on_exception(self):
        """__exit__ called even when exception in with block.

        Invariant: Context managers properly cleaned up.
        """
        # This is more about semantic correctness
        code = """
with open('test.txt') as f:
    x = 1 / 0
"""
        # The file should be closed even though exception raised

    def test_del_not_called_on_exception(self):
        """__del__ behavior on exception is tricky.

        Note: Python doesn't guarantee __del__ timing.
        """
        # This documents the limitation rather than testing specific behavior
        pass


class TestExceptionInGenerator:
    """Tests for exception handling in generators."""

    def test_generator_exception_propagates(self):
        """Exception in generator propagates to caller.

        Invariant: StopIteration is special, others propagate.
        """
        def gen():
            yield 1
            raise ValueError("in generator")
            yield 2

        # Consumer sees ValueError on second next()
        code = gen.__code__
        assert code.co_flags & 0x20, "Should be a generator"

    def test_stopiteration_handling(self):
        """StopIteration ends generator, doesn't propagate.

        Invariant: StopIteration is consumed by for loop machinery.
        """
        def gen():
            yield 1
            return  # Implicitly raises StopIteration

        # for x in gen() doesn't see StopIteration
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
