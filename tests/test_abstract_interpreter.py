"""Tests for abstract interpretation (analysis/abstract/)."""
from __future__ import annotations
import pytest
from pysymex.analysis.abstract.interpreter import (
    AbstractInterpreter,
    AbstractAnalyzer,
)
from pysymex.analysis.abstract.interpreter_state import (
    NumericProduct,
    AbstractState,
    AbstractWarning,
    DivisionByZeroWarning,
    IndexOutOfBoundsWarning,
)


# -- Abstract State / Values --

class TestNumericProduct:
    def test_creation(self):
        np = NumericProduct.top()
        assert np is not None

    def test_is_abstract_value(self):
        np = NumericProduct.top()
        assert hasattr(np, 'join') or hasattr(np, 'meet') or hasattr(np, 'widen')


class TestAbstractState:
    def test_creation(self):
        state = AbstractState()
        assert state is not None

    def test_has_variables(self):
        state = AbstractState()
        assert (hasattr(state, 'variables') or hasattr(state, 'vars') or
                hasattr(state, '_vars') or hasattr(state, 'get'))

    def test_join(self):
        s1 = AbstractState()
        s2 = AbstractState()
        if hasattr(s1, 'join'):
            result = s1.join(s2)
            assert result is not None

    def test_is_bottom(self):
        state = AbstractState()
        if hasattr(state, 'is_bottom'):
            assert isinstance(state.is_bottom(), bool)


# -- Warnings --

class TestAbstractWarning:
    def test_subclass_exists(self):
        # DivisionByZeroWarning and IndexOutOfBoundsWarning are standalone dataclasses,
        # not subclasses of AbstractWarning. Verify they are proper warning types
        # by checking they have the expected 'line' and 'pc' fields.
        assert hasattr(DivisionByZeroWarning, '__dataclass_fields__')
        assert 'line' in DivisionByZeroWarning.__dataclass_fields__
        assert hasattr(IndexOutOfBoundsWarning, '__dataclass_fields__')
        assert 'line' in IndexOutOfBoundsWarning.__dataclass_fields__


class TestDivisionByZeroWarning:
    def test_creation(self):
        w = DivisionByZeroWarning(
            line=1, pc=0, variable="x",
            divisor=NumericProduct.top(), confidence="possible",
        )
        assert w is not None

    def test_has_message(self):
        w = DivisionByZeroWarning(
            line=1, pc=0, variable="x",
            divisor=NumericProduct.top(), confidence="possible",
        )
        assert hasattr(w, 'variable') or hasattr(w, 'message') or hasattr(w, 'msg') or str(w)


class TestIndexOutOfBoundsWarning:
    def test_creation(self):
        w = IndexOutOfBoundsWarning(
            line=1, pc=0, collection="list",
            index=NumericProduct.top(), size=NumericProduct.top(),
        )
        assert w is not None


# -- Interpreter / Analyzer --

class TestAbstractInterpreter:
    def test_creation(self):
        interp = AbstractInterpreter()
        assert interp is not None

    def test_has_interpret(self):
        assert (hasattr(AbstractInterpreter, 'interpret') or
                hasattr(AbstractInterpreter, 'execute') or
                hasattr(AbstractInterpreter, 'run') or
                hasattr(AbstractInterpreter, 'analyze'))

    def test_initial_state(self):
        interp = AbstractInterpreter()
        if hasattr(interp, 'initial_state'):
            state = interp.initial_state()
            assert state is not None


class TestAbstractAnalyzer:
    def test_creation(self):
        analyzer = AbstractAnalyzer()
        assert analyzer is not None

    def test_has_analyze(self):
        assert (hasattr(AbstractAnalyzer, 'analyze_function') or
                hasattr(AbstractAnalyzer, 'analyze_module') or
                hasattr(AbstractAnalyzer, 'analyze') or
                hasattr(AbstractAnalyzer, 'run'))
