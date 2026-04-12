import sys
from unittest.mock import Mock
from pysymex.analysis.detectors.static import (
    StaticKeyErrorDetector, StaticIndexErrorDetector, StaticTypeErrorDetector, StaticAssertionErrorDetector
)
from pysymex.analysis.detectors.types import DetectionContext
from pysymex.analysis.type_inference import PyType, TypeEnvironment

class MockInstr:
    def __init__(self, opname: str, argval: object = None, argrepr: str = "", offset: int = 10, starts_line: int | None = 10) -> None:
        self.opname = opname
        self.argval = argval
        self.argrepr = argrepr
        self.offset = offset
        self.starts_line = starts_line
        self.positions = Mock(lineno=starts_line) if starts_line else None

d1 = StaticKeyErrorDetector()
instr0 = MockInstr("NOP", offset=0)
instr1 = MockInstr("LOAD_FAST", argval="d", offset=2)
instr2 = MockInstr("LOAD_CONST", argval="k", offset=4)
instr3 = MockInstr("BINARY_SUBSCR", offset=6)
env = TypeEnvironment()
env.set_type("d", PyType.dict_())
ctx1 = DetectionContext(Mock(), [instr0, instr1, instr2, instr3], 6, instr3, 10, env) # type: ignore[arg-type]
print("KeyError:", d1.check(ctx1))

d2 = StaticIndexErrorDetector()
instr1 = MockInstr("LOAD_FAST", argval="lst", offset=2)
instr2 = MockInstr("LOAD_CONST", argval=10, offset=4)
instr3 = MockInstr("BINARY_SUBSCR", offset=6)
env2 = TypeEnvironment()
env2.set_type("lst", PyType.list_())
ctx2 = DetectionContext(Mock(), [instr0, instr1, instr2, instr3], 6, instr3, 10, env2) # type: ignore[arg-type]
print("IndexError:", d2.check(ctx2))

d3 = StaticTypeErrorDetector()
instr1 = MockInstr("LOAD_CONST", argval=1, offset=2)
instr2 = MockInstr("LOAD_CONST", argval="a", offset=4)
instr3 = MockInstr("BINARY_OP", argrepr="+", offset=6)
env3 = TypeEnvironment()
ctx3 = DetectionContext(Mock(), [instr0, instr1, instr2, instr3], 6, instr3, 10, env3) # type: ignore[arg-type]
print("TypeError:", d3.check(ctx3))

d4 = StaticAssertionErrorDetector()
instr1 = MockInstr("LOAD_CONST", argval=False, offset=2)
instr2 = MockInstr("LOAD_ASSERTION_ERROR", offset=4)
ctx4 = DetectionContext(Mock(), [instr0, instr1, instr2], 4, instr2, 10, TypeEnvironment()) # type: ignore[arg-type]
print("AssertionError:", d4.check(ctx4))
