import pytest
from pysymex.analysis.abstract.interpreter import AbstractAnalyzer, AbstractInterpreter
from pysymex.analysis.abstract.interpreter_state import AbstractState, NumericProduct
from pysymex.analysis.abstract.interpreter_values import Interval, SignValue, Congruence

def test_abstract_state_join_stack():
    state1 = AbstractState()
    state1.push(NumericProduct.const(5))
    
    state2 = AbstractState()
    state2.push(NumericProduct.const(10))
    
    joined = state1.join(state2)
    assert len(joined.stack) == 1
    val = joined.pop()
    assert val.interval.low == 5
    assert val.interval.high == 10

def test_modulo_evaluation():
    def func():
        return 5 % 2

    analyzer = AbstractAnalyzer()
    analyzer.analyze_function(func.__code__)
    # Actually we can just run the transfer instruction or check if it correctly computes modulo.
    # Wait, the interpreter pushes `result` from `left.div(right)`. Let's test `transfer_instruction`.
    # Let's inspect state after binary_op %
    import dis
    instr = type('Instr', (), {'opname': 'BINARY_OP', 'argrepr': '%', 'offset': 0, 'arg': 0, 'argval': 0, 'opcode': 0, 'starts_line': 1})()
    interp = AbstractInterpreter()
    state = AbstractState()
    state.push(NumericProduct.const(5))
    state.push(NumericProduct.const(2))
    
    interp._transfer_instruction(instr, state, 1, None, "")
    val = state.pop()
    # If it's a division, it would be 2. If it's modulo, it should be 1 (or top if not implemented).
    # Currently, it pushes quotient (2).
    assert val.interval.low == 1 # This will fail because it's 2 or Top

def test_fast_path_false_positive():
    def func():
        x = 5
        return x + 0

    analyzer = AbstractInterpreter()
    warnings = analyzer._analyze_trivial(func.__code__, "test.py")
    assert len(warnings) == 0 # This will fail if it flags + 0

def test_widening_on_dag():
    # A DAG with multiple paths to a single merge block
    def func(x):
        if x == 1:
            y = 1
        elif x == 2:
            y = 2
        elif x == 3:
            y = 3
        elif x == 4:
            y = 4
        elif x == 5:
            y = 5
        else:
            y = 6
        return y
    
    analyzer = AbstractAnalyzer()
    # It shouldn't over-widen y to Top just because it has many predecessors.
    analyzer.analyze_function(func.__code__)
    # We would need to inspect the state or we can just verify that we don't widen.

