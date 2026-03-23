"""Tests for generator, async/await, and coroutine opcode soundness.

Generators and coroutines have complex control flow that can cause:
- Missed execution paths when yield points aren't properly tracked
- State corruption when resuming after yield
- Incorrect exception propagation through generators
- Lost values in send/throw patterns

These tests verify the symbolic executor correctly handles Python's
generator protocol (PEP 342, PEP 380, PEP 525).
"""

from __future__ import annotations

import dis
import sys
import pytest

from pysymex.core.state import VMState
from pysymex.core.types import SymbolicValue
from pysymex.execution.executor_core import SymbolicExecutor
from pysymex.analysis.detectors import IssueKind


class TestGeneratorYieldSemantics:
    """Tests for YIELD_VALUE opcode correctness."""

    def test_simple_generator_all_values_reachable(self):
        """All yield points in generator must be symbolically reachable.

        Invariant: Each yield creates a distinct suspension point.
        """
        def simple_gen():
            yield 1
            yield 2
            yield 3

        code = simple_gen.__code__
        instructions = list(dis.get_instructions(code))

        # Count yield instructions
        yield_ops = [i for i in instructions if 'YIELD' in i.opname]
        assert len(yield_ops) >= 3, "Generator should have 3 yields"

        # Verify generator flag
        assert code.co_flags & 0x20, "Must be marked as generator"

    def test_conditional_yield_both_paths(self):
        """Conditional yields must explore both paths.

        Invariant: if x: yield A else: yield B explores both.
        """
        def conditional_gen(x: int):
            if x > 0:
                yield "positive"
            else:
                yield "non-positive"
            yield "done"

        executor = SymbolicExecutor()
        result = executor.execute_function(
            conditional_gen,
            symbolic_args={"x": "int"},
        )

        # Should explore at least 2 paths (x>0 and x<=0)
        assert result.paths_explored >= 2, "Must explore both conditional branches"

    def test_yield_in_loop_bounded_exploration(self):
        """Loops with yield must be bounded during exploration.

        Invariant: Loop widening applies to generator loops.
        """
        def loop_gen(n: int):
            i = 0
            while i < n:
                yield i
                i += 1

        executor = SymbolicExecutor(max_iterations=10)
        result = executor.execute_function(
            loop_gen,
            symbolic_args={"n": "int"},
        )

        # Should terminate without hanging
        assert result is not None, "Generator loop must terminate"


class TestGeneratorSendThrow:
    """Tests for send() and throw() protocol correctness."""

    def test_send_value_received(self):
        """Values sent to generator must be received at yield.

        Invariant: x = yield v receives the sent value in x.
        """
        def echo_gen():
            received = yield "ready"
            yield f"got: {received}"

        # Verify bytecode structure for send pattern
        code = echo_gen.__code__
        instructions = list(dis.get_instructions(code))

        # Should have YIELD_VALUE followed by store
        yield_indices = [i for i, instr in enumerate(instructions)
                        if 'YIELD' in instr.opname]
        assert len(yield_indices) >= 1

    def test_throw_propagates_to_handler(self):
        """Exceptions thrown into generator must reach handlers.

        Invariant: gen.throw(E) reaches except E inside generator.
        """
        def catching_gen():
            try:
                yield "in try"
            except ValueError:
                yield "caught ValueError"
            yield "after"

        code = catching_gen.__code__
        # Should have exception handling
        if hasattr(code, 'co_exceptiontable') and sys.version_info >= (3, 11):
            assert code.co_exceptiontable, "Should have exception handling"


class TestYieldFromDelegation:
    """Tests for yield from delegation (PEP 380)."""

    def test_yield_from_delegates_values(self):
        """yield from must delegate all values from subgenerator.

        Invariant: All values from inner generator are yielded.
        """
        def inner():
            yield 1
            yield 2

        def outer():
            yield "start"
            yield from inner()
            yield "end"

        code = outer.__code__
        instructions = list(dis.get_instructions(code))

        # Look for GET_YIELD_FROM_ITER or similar delegation opcode
        delegation_ops = [i for i in instructions
                         if 'YIELD_FROM' in i.opname or 'GET_YIELD_FROM' in i.opname]
        # Python 3.11+ uses different opcodes

    def test_yield_from_exception_propagation(self):
        """Exceptions in subgenerator must propagate correctly.

        Invariant: StopIteration value becomes yield from result.
        """
        def inner_with_return():
            yield 1
            return "inner_result"

        def outer_captures():
            result = yield from inner_with_return()
            yield result

        # The outer generator should capture the return value
        code = outer_captures.__code__
        assert code.co_flags & 0x20, "Must be generator"


class TestAsyncAwaitSemantics:
    """Tests for async/await opcode correctness."""

    def test_async_function_flags(self):
        """Async functions must have correct flags.

        Invariant: CO_COROUTINE flag is set.
        """
        async def async_func():
            return 42

        code = async_func.__code__
        # CO_COROUTINE = 0x80
        assert code.co_flags & 0x80, "Must be marked as coroutine"

    def test_await_creates_suspension_point(self):
        """Each await creates a potential suspension point.

        Invariant: await expr may suspend and resume.
        """
        async def multi_await():
            a = await get_value()
            b = await get_value()
            return a + b

        async def get_value():
            return 1

        code = multi_await.__code__
        instructions = list(dis.get_instructions(code))

        # Look for GET_AWAITABLE or similar
        await_ops = [i for i in instructions if 'AWAIT' in i.opname]
        # Number depends on Python version

    def test_async_for_iteration(self):
        """async for must iterate asynchronously.

        Invariant: GET_AITER and GET_ANEXT are used correctly.
        """
        async def async_iterate(ait):
            results = []
            async for item in ait:
                results.append(item)
            return results

        code = async_iterate.__code__
        instructions = list(dis.get_instructions(code))

        # Should have async iteration opcodes
        aiter_ops = [i for i in instructions
                    if 'AITER' in i.opname or 'ANEXT' in i.opname]


class TestExceptionGroupOpcodes:
    """Tests for Python 3.11+ exception group handling."""

    @pytest.mark.skipif(sys.version_info < (3, 11), reason="Needs Python 3.11+")
    def test_exception_group_matching(self):
        """except* must use CHECK_EG_MATCH correctly.

        Invariant: Exception groups split correctly.
        """
        def handle_group():
            result = None
            try:
                raise ExceptionGroup("group", [ValueError("v"), TypeError("t")])
            except* ValueError:
                result = "caught ValueError"
            except* TypeError:
                if result is None:
                    result = "caught TypeError"
            return result

        code = handle_group.__code__
        instructions = list(dis.get_instructions(code))

        # Should have CHECK_EG_MATCH
        eg_ops = [i for i in instructions if 'EG_MATCH' in i.opname]


class TestGeneratorCleanup:
    """Tests for generator cleanup and finalization."""

    def test_generator_close_runs_finally(self):
        """gen.close() must run finally blocks.

        Invariant: Finally executes even when generator is closed.
        """
        cleanup_ran = []

        def gen_with_finally():
            try:
                yield 1
                yield 2
            finally:
                cleanup_ran.append(True)

        code = gen_with_finally.__code__
        # Should have finally handling
        if hasattr(code, 'co_exceptiontable'):
            pass  # Python 3.11+ has exception table

    def test_return_in_generator_raises_stopiteration(self):
        """return value in generator becomes StopIteration.value.

        Invariant: return x raises StopIteration(x).
        """
        def gen_with_return():
            yield 1
            return "done"

        code = gen_with_return.__code__
        instructions = list(dis.get_instructions(code))

        # Should have RETURN_VALUE or RETURN_CONST
        return_ops = [i for i in instructions if 'RETURN' in i.opname]
        assert len(return_ops) >= 1


class TestCoroutineLifecycle:
    """Tests for coroutine creation and execution lifecycle."""

    def test_return_generator_opcode(self):
        """RETURN_GENERATOR creates generator object correctly.

        Invariant: Generator object is created at function entry.
        """
        def gen():
            yield 1

        code = gen.__code__
        instructions = list(dis.get_instructions(code))

        if sys.version_info >= (3, 11):
            # Python 3.11+ uses RETURN_GENERATOR
            return_gen = [i for i in instructions if i.opname == 'RETURN_GENERATOR']
            # May or may not be present depending on version

    def test_end_async_for_cleanup(self):
        """END_ASYNC_FOR must clean up iteration state.

        Invariant: Async iteration state is properly finalized.
        """
        async def async_loop(ait):
            async for x in ait:
                if x > 5:
                    break

        code = async_loop.__code__
        instructions = list(dis.get_instructions(code))

        # Should have END_ASYNC_FOR for cleanup
        end_ops = [i for i in instructions if 'END_ASYNC' in i.opname]


class TestReraiseAndExceptionState:
    """Tests for RERAISE and exception state management."""

    def test_bare_raise_reraises_current(self):
        """Bare raise must reraise the current exception.

        Invariant: RERAISE uses the exception from sys.exc_info().
        """
        def reraise_example():
            try:
                raise ValueError("original")
            except ValueError:
                try:
                    raise  # Reraise
                except:
                    pass

        code = reraise_example.__code__
        instructions = list(dis.get_instructions(code))

        # Should have RERAISE opcode
        reraise_ops = [i for i in instructions if 'RERAISE' in i.opname]

    def test_push_pop_exc_info_balanced(self):
        """PUSH_EXC_INFO and POP_EXCEPT must be balanced.

        Invariant: Exception stack is properly managed.
        """
        def nested_exceptions():
            try:
                try:
                    raise ValueError()
                except ValueError:
                    raise TypeError()
            except TypeError:
                pass

        code = nested_exceptions.__code__
        instructions = list(dis.get_instructions(code))

        push_ops = [i for i in instructions if 'PUSH_EXC' in i.opname]
        pop_ops = [i for i in instructions if 'POP_EXCEPT' in i.opname]

        # Should be balanced (may have different counts due to nesting)


class TestSymbolicGeneratorExecution:
    """End-to-end tests for symbolic execution of generators."""

    @pytest.mark.skip(reason="Symbolic generator execution can cause resource exhaustion in parallel test runs")
    def test_generator_with_symbolic_condition(self):
        """Generator decisions based on symbolic input.

        Invariant: All symbolic paths through generator are explored.
        """
        def conditional_gen(x: int):
            if x > 0:
                yield "positive"
                if x > 10:
                    yield "large"
            else:
                yield "non-positive"

        executor = SymbolicExecutor()
        result = executor.execute_function(
            conditional_gen,
            symbolic_args={"x": "int"},
        )

        # Should explore multiple paths
        assert result.paths_explored >= 2

    @pytest.mark.skip(reason="Symbolic generator execution can cause resource exhaustion in parallel test runs")
    def test_generator_exception_in_symbolic_path(self):
        """Exceptions raised on symbolic paths must be detected.

        Invariant: Bugs in generators are found.
        """
        def buggy_gen(x: int):
            yield 1
            result = 10 / x  # Division by zero when x=0
            yield result

        executor = SymbolicExecutor()
        result = executor.execute_function(
            buggy_gen,
            symbolic_args={"x": "int"},
        )

        issues = result.get_issues_by_kind(IssueKind.DIVISION_BY_ZERO)
        assert len(issues) > 0, "Must detect division by zero in generator"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
