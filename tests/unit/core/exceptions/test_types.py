import pysymex.core.exceptions.types
import z3

class TestExceptionCategory:
    """Test suite for pysymex.core.exceptions.types.ExceptionCategory."""
    def test_initialization(self) -> None:
        """Scenario: category enum exists; expected RUNTIME member name."""
        assert pysymex.core.exceptions.types.ExceptionCategory.RUNTIME.name == "RUNTIME"


def test_exception_matches() -> None:
    """Scenario: ValueError matched by Exception handler; expected true."""
    assert pysymex.core.exceptions.types.exception_matches(ValueError, Exception) is True


def test_get_exception_category() -> None:
    """Scenario: ZeroDivisionError category lookup; expected arithmetic category."""
    assert (
        pysymex.core.exceptions.types.get_exception_category(ZeroDivisionError)
        == pysymex.core.exceptions.types.ExceptionCategory.ARITHMETIC
    )


class TestSymbolicException:
    """Test suite for pysymex.core.exceptions.types.SymbolicException."""
    def test_concrete(self) -> None:
        """Scenario: concrete constructor; expected unconditional condition."""
        exc = pysymex.core.exceptions.types.SymbolicException.concrete(ValueError, "bad")
        assert exc.is_unconditional() is True

    def test_symbolic(self) -> None:
        """Scenario: symbolic constructor with condition; expected stored condition expression."""
        cond = z3.Bool("c")
        exc = pysymex.core.exceptions.types.SymbolicException.symbolic("e", ValueError, cond)
        assert exc.condition == cond

    def test_type_name(self) -> None:
        """Scenario: concrete ValueError type name; expected class name string."""
        exc = pysymex.core.exceptions.types.SymbolicException.concrete(ValueError)
        assert exc.type_name == "ValueError"

    def test_is_unconditional(self) -> None:
        """Scenario: symbolic exception with non-constant condition; expected not unconditional."""
        exc = pysymex.core.exceptions.types.SymbolicException.symbolic(
            "e", ValueError, z3.Bool("maybe")
        )
        assert exc.is_unconditional() is False

    def test_may_occur(self) -> None:
        """Scenario: satisfiable condition; expected may_occur true."""
        solver = z3.Solver()
        exc = pysymex.core.exceptions.types.SymbolicException.symbolic("e", ValueError, z3.BoolVal(True))
        assert exc.may_occur(solver) is True

    def test_must_occur(self) -> None:
        """Scenario: true condition; expected must_occur true."""
        solver = z3.Solver()
        exc = pysymex.core.exceptions.types.SymbolicException.symbolic("e", ValueError, z3.BoolVal(True))
        assert exc.must_occur(solver) is True


class TestExceptionHandler:
    """Test suite for pysymex.core.exceptions.types.ExceptionHandler."""
    def test_catches(self) -> None:
        """Scenario: broad handler catches specific exception instance."""
        handler = pysymex.core.exceptions.types.ExceptionHandler((Exception,), target_pc=1)
        exc = pysymex.core.exceptions.types.SymbolicException.concrete(ValueError)
        assert handler.catches(exc) is True

    def test_catches_type(self) -> None:
        """Scenario: Exception handler catches ValueError type."""
        handler = pysymex.core.exceptions.types.ExceptionHandler((Exception,), target_pc=1)
        assert handler.catches_type(ValueError) is True


class TestFinallyHandler:
    """Test suite for pysymex.core.exceptions.types.FinallyHandler."""
    def test_initialization(self) -> None:
        """Scenario: finally handler stores target and exit PCs."""
        fh = pysymex.core.exceptions.types.FinallyHandler(target_pc=10, exit_pc=20)
        assert (fh.target_pc, fh.exit_pc) == (10, 20)


class TestTryBlock:
    """Test suite for pysymex.core.exceptions.types.TryBlock."""
    def test_in_try_block(self) -> None:
        """Scenario: PC inside range [start,end); expected true."""
        block = pysymex.core.exceptions.types.TryBlock(try_start=5, try_end=10)
        assert block.in_try_block(7) is True

    def test_find_handler(self) -> None:
        """Scenario: matching handler exists; expected returned handler object."""
        handler = pysymex.core.exceptions.types.ExceptionHandler((ValueError,), target_pc=99)
        block = pysymex.core.exceptions.types.TryBlock(0, 10, handlers=[handler])
        exc = pysymex.core.exceptions.types.SymbolicException.concrete(ValueError)
        assert block.find_handler(exc) == handler


class TestExceptionPath:
    """Test suite for pysymex.core.exceptions.types.ExceptionPath."""
    def test_add_condition(self) -> None:
        """Scenario: add condition to path; expected conjunction includes new condition."""
        path = pysymex.core.exceptions.types.ExceptionPath(
            pysymex.core.exceptions.types.SymbolicException.concrete(ValueError)
        )
        c = z3.Bool("c")
        path.add_condition(c)
        assert z3.eq(path.path_condition, z3.And(z3.BoolVal(True), c))

    def test_mark_caught(self) -> None:
        """Scenario: mark caught with handler; expected caught_by set."""
        path = pysymex.core.exceptions.types.ExceptionPath(
            pysymex.core.exceptions.types.SymbolicException.concrete(ValueError)
        )
        handler = pysymex.core.exceptions.types.ExceptionHandler((Exception,), 1)
        path.mark_caught(handler)
        assert path.caught_by == handler

    def test_mark_propagated(self) -> None:
        """Scenario: mark propagated; expected propagated flag true."""
        path = pysymex.core.exceptions.types.ExceptionPath(
            pysymex.core.exceptions.types.SymbolicException.concrete(ValueError)
        )
        path.mark_propagated()
        assert path.propagated is True


class TestExceptionState:
    """Test suite for pysymex.core.exceptions.types.ExceptionState."""
    def test_push_try(self) -> None:
        """Scenario: push try block; expected stack size increments."""
        state = pysymex.core.exceptions.types.ExceptionState()
        block = pysymex.core.exceptions.types.TryBlock(0, 1)
        state.push_try(block)
        assert len(state.try_stack) == 1

    def test_pop_try(self) -> None:
        """Scenario: pop after push; expected same try block returned."""
        state = pysymex.core.exceptions.types.ExceptionState()
        block = pysymex.core.exceptions.types.TryBlock(0, 1)
        state.push_try(block)
        assert state.pop_try() == block

    def test_current_try(self) -> None:
        """Scenario: one stacked try block; expected current_try returns it."""
        state = pysymex.core.exceptions.types.ExceptionState()
        block = pysymex.core.exceptions.types.TryBlock(0, 1)
        state.push_try(block)
        assert state.current_try() == block

    def test_raise_exception(self) -> None:
        """Scenario: raise exception in state; expected current_exception updated."""
        state = pysymex.core.exceptions.types.ExceptionState()
        exc = pysymex.core.exceptions.types.SymbolicException.concrete(ValueError)
        _ = state.raise_exception(exc)
        assert state.current_exception == exc

    def test_handle_exception(self) -> None:
        """Scenario: matching handler in try stack; expected returned target PC."""
        state = pysymex.core.exceptions.types.ExceptionState()
        handler = pysymex.core.exceptions.types.ExceptionHandler((ValueError,), target_pc=7)
        state.push_try(pysymex.core.exceptions.types.TryBlock(0, 10, handlers=[handler]))
        handled, pc = state.handle_exception(pysymex.core.exceptions.types.SymbolicException.concrete(ValueError))
        assert (handled, pc) == (handler, 7)

    def test_clear_exception(self) -> None:
        """Scenario: clear existing current exception; expected None."""
        state = pysymex.core.exceptions.types.ExceptionState(
            current_exception=pysymex.core.exceptions.types.SymbolicException.concrete(ValueError)
        )
        state.clear_exception()
        assert state.current_exception is None

    def test_suppress(self) -> None:
        """Scenario: suppress current exception; expected exception added to suppressed list."""
        exc = pysymex.core.exceptions.types.SymbolicException.concrete(ValueError)
        state = pysymex.core.exceptions.types.ExceptionState(current_exception=exc)
        state.suppress(exc)
        assert state.suppressed == [exc]

    def test_clone(self) -> None:
        """Scenario: clone state; expected separate object with copied stack."""
        state = pysymex.core.exceptions.types.ExceptionState(
            try_stack=[pysymex.core.exceptions.types.TryBlock(0, 1)]
        )
        clone = state.clone()
        assert clone is not state


class TestRaisesContract:
    """Test suite for pysymex.core.exceptions.types.RaisesContract."""
    def test_type_name(self) -> None:
        """Scenario: contract from type class; expected class name."""
        contract = pysymex.core.exceptions.types.RaisesContract(ValueError)
        assert contract.type_name == "ValueError"

    def test_matches(self) -> None:
        """Scenario: ValueError contract and matching concrete exception; expected true."""
        contract = pysymex.core.exceptions.types.RaisesContract(ValueError)
        exc = pysymex.core.exceptions.types.SymbolicException.concrete(ValueError)
        assert contract.matches(exc) is True


def test_raises() -> None:
    """Scenario: @raises decorator application; expected __raises__ contract list attached."""

    @pysymex.core.exceptions.types.raises(ValueError)
    def f() -> None:
        return None

    assert hasattr(f, "__raises__")
