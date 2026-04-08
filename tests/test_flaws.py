import z3
import dis
import inspect
from pysymex.analysis.detectors.specialized import IntegerOverflowDetector
from pysymex.analysis.taint.checker_core import TaintAnalyzer, TaintState, TaintedValue
from pysymex.analysis.concurrency.core import ConcurrencyAnalyzer, MemoryOrder


def _make_instruction(opname: str, opcode: int, arg: int, argval: object) -> dis.Instruction:
    params = set(inspect.signature(dis.Instruction).parameters)
    kwargs: dict[str, object] = {
        "opname": opname,
        "opcode": opcode,
        "arg": arg,
        "argval": argval,
        "argrepr": "",
        "offset": 0,
    }
    if "start_offset" in params:
        kwargs["start_offset"] = 0
    if "starts_line" in params:
        kwargs["starts_line"] = True if "line_number" in params else None
    if "line_number" in params:
        kwargs["line_number"] = 1
    if "is_jump_target" in params:
        kwargs["is_jump_target"] = False
    if "label" in params:
        kwargs["label"] = None
    if "baseopname" in params:
        kwargs["baseopname"] = opname
    if "baseopcode" in params:
        kwargs["baseopcode"] = opcode
    if "positions" in params:
        kwargs["positions"] = None
    if "cache_info" in params:
        kwargs["cache_info"] = None
    return dis.Instruction(**kwargs)

def test_issue_2():
    class MockSymValue:
        def __init__(self, name): self.name = name
        def __repr__(self): return self.name
    class MockState:
        def __init__(self, stack):
            self.stack = stack
            self.path_constraints = []
            self.pc = 0
        def peek(self, n=1):
            if len(self.stack) >= n: return self.stack[-n]
            return None
    state = MockState([MockSymValue('left'), MockSymValue('right')])
    print(f"Issue 2 (Overflow Detector): Left operand fetched: {state.peek(1)}, Right operand fetched: {state.peek()}")

def test_issue_4():
    analyzer = TaintAnalyzer()
    state = TaintState()
    state.push(TaintedValue('user_input', labels={'taint'}))
    state.push(TaintedValue('02x')) # format specifier pushed by Python 3.11+ for f'{user_input:02x}'
    
    # 4 == FVC_FORMAT_SPEC
    instr = _make_instruction('FORMAT_VALUE', 155, 4, 4)
    analyzer._process_instruction(instr, state, 1, 'test.py')
    
    top = state.peek()
    is_tainted = bool(top.labels)
    print(f"Issue 4 (TaintAnalyzer Stack): Top of stack after FORMAT_VALUE: {top.value_name}, is_tainted={is_tainted}")
    if state.stack:
        next_down = state.stack[0]
        print(f"  Item left on stack: {next_down.value_name}")

if __name__ == '__main__':
    test_issue_2()
    test_issue_4()
