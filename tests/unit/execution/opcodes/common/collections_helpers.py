from __future__ import annotations

import dis


def instr(opname: str, argval: object = None, arg: int = 0, offset: int = 0) -> dis.Instruction:
    base = next(iter(dis.get_instructions(compile("x = 1", "<test>", "exec"))))
    return base._replace(opname=opname, argval=argval, arg=arg, offset=offset)
