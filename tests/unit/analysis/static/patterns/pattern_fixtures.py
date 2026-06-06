import dis
from collections.abc import Sequence

from pysymex.analysis.static.patterns.base import PatternHandler
from pysymex.analysis.static.patterns.kinds import PatternKind, PatternMatch
from pysymex.analysis.static.types import TypeEnvironment


def mock_instr(
    opname: str,
    argval: object = None,
    arg: int | None = None,
    offset: int = 10,
    starts_line: int | None = 10,
) -> dis.Instruction:
    def _sentinel() -> None:
        return None

    template = next(dis.get_instructions(_sentinel))
    return template._replace(
        opname=opname,
        opcode=dis.opmap.get(opname, 0),
        arg=arg,
        argval=argval,
        argrepr=str(argval) if argval is not None else "",
        offset=offset,
        starts_line=starts_line,
    )


class DummyHandler(PatternHandler):
    def pattern_kinds(self) -> set[PatternKind]:
        return {PatternKind.DICT_GET}

    def match(
        self,
        instructions: Sequence[dis.Instruction],
        start_idx: int,
        env: TypeEnvironment,
    ) -> PatternMatch | None:
        return None
