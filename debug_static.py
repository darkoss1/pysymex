import sys
from unittest.mock import Mock
from pysymex.analysis.detectors.static import StaticTypeErrorDetector
from pysymex.analysis.detectors.types import DetectionContext
from pysymex.analysis.type_inference import TypeEnvironment

class MockInstr:
    def __init__(self, opname: str, argval: object = None, argrepr: str = "", offset: int = 10, starts_line: int | None = 10) -> None:
        self.opname = opname
        self.argval = argval
        self.argrepr = argrepr
        self.offset = offset
        self.starts_line = starts_line
        self.positions = Mock(lineno=starts_line) if starts_line else None

d = StaticTypeErrorDetector()
instr0 = MockInstr("NOP", offset=0)
instr1 = MockInstr("LOAD_CONST", argval=1, offset=2)
instr2 = MockInstr("LOAD_CONST", argval="a", offset=4)
instr3 = MockInstr("BINARY_OP", argrepr="+", offset=6)
env = TypeEnvironment()
ctx = DetectionContext(Mock(), [instr0, instr1, instr2, instr3], 6, instr3, 10, env) # type: ignore[arg-type]

issue = d.check(ctx)
print("Issue is:", issue)
