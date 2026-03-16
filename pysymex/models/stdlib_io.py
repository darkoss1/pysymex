"""Symbolic models for copy, io, heapq, and bisect modules.

Models:
- copy: copy, deepcopy
- io: StringIO, BytesIO, read, write, getvalue
- heapq: heappush, heappop, heapify, heapreplace, heappushpop, nlargest, nsmallest
- bisect: bisect_left, bisect_right, bisect, insort_left, insort_right, insort
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.core.types import (
    SymbolicList,
    SymbolicNone,
    SymbolicString,
    SymbolicValue,
)
from pysymex.models.builtins import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState


class CopyModel(FunctionModel):
    """Model for copy.copy()."""

    name = "copy"
    qualname = "copy.copy"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if args:
            return ModelResult(value=args[0])
        result, constraint = SymbolicValue.symbolic(f"copy_{state .pc }")
        return ModelResult(value=result, constraints=[constraint])


class DeepcopyModel(FunctionModel):
    """Model for copy.deepcopy()."""

    name = "deepcopy"
    qualname = "copy.deepcopy"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if args:
            val = args[0]
            if isinstance(val, SymbolicValue):
                result, constraint = SymbolicValue.symbolic(f"deepcopy_{val .name }")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.z3_int == val.z3_int],
                )
            if isinstance(val, SymbolicString):
                result, constraint = SymbolicString.symbolic(f"deepcopy_{val .name }")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.z3_str == val.z3_str],
                )
            if isinstance(val, SymbolicList):
                result, constraint = SymbolicList.symbolic(f"deepcopy_{val .name }")
                return ModelResult(
                    value=result,
                    constraints=[constraint, result.z3_len == val.z3_len],
                )
        result, constraint = SymbolicValue.symbolic(f"deepcopy_{state .pc }")
        return ModelResult(value=result, constraints=[constraint])


class StringIOModel(FunctionModel):
    """Model for io.StringIO()."""

    name = "StringIO"
    qualname = "io.StringIO"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"stringio_{state .pc }")
        return ModelResult(value=result, constraints=[constraint])


class BytesIOModel(FunctionModel):
    """Model for io.BytesIO()."""

    name = "BytesIO"
    qualname = "io.BytesIO"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"bytesio_{state .pc }")
        return ModelResult(value=result, constraints=[constraint])


class IOReadModel(FunctionModel):
    """Model for file.read() / StringIO.read()."""

    name = "read"
    qualname = "io.read"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"io_read_{state .pc }")
        return ModelResult(value=result, constraints=[constraint])


class IOWriteModel(FunctionModel):
    """Model for file.write() / StringIO.write()."""

    name = "write"
    qualname = "io.write"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        if args and isinstance(args[0], SymbolicString):
            return ModelResult(
                value=SymbolicValue(
                    _name=f"written_{state .pc }",
                    z3_int=args[0].z3_len,
                    is_int=z3.BoolVal(True),
                    z3_bool=z3.BoolVal(False),
                    is_bool=z3.BoolVal(False),
                )
            )
        result, constraint = SymbolicValue.symbolic(f"io_write_{state .pc }")
        return ModelResult(
            value=result, constraints=[constraint, result.is_int, result.z3_int >= 0]
        )


class IOGetvalueModel(FunctionModel):
    """Model for StringIO.getvalue()."""

    name = "getvalue"
    qualname = "io.StringIO.getvalue"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"io_getvalue_{state .pc }")
        return ModelResult(value=result, constraints=[constraint])


class HeappushModel(FunctionModel):
    """Model for heapq.heappush()."""

    name = "heappush"
    qualname = "heapq.heappush"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        return ModelResult(
            value=SymbolicNone("none"),
            side_effects={"mutates_arg": 0},
        )


class HeappopModel(FunctionModel):
    """Model for heapq.heappop()."""

    name = "heappop"
    qualname = "heapq.heappop"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"heappop_{state .pc }")
        return ModelResult(
            value=result,
            constraints=[constraint],
            side_effects={"mutates_arg": 0},
        )


class HeapifyModel(FunctionModel):
    """Model for heapq.heapify()."""

    name = "heapify"
    qualname = "heapq.heapify"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        return ModelResult(
            value=SymbolicNone("none"),
            side_effects={"mutates_arg": 0},
        )


class HeapreplaceModel(FunctionModel):
    """Model for heapq.heapreplace()."""

    name = "heapreplace"
    qualname = "heapq.heapreplace"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"heapreplace_{state .pc }")
        return ModelResult(
            value=result,
            constraints=[constraint],
            side_effects={"mutates_arg": 0},
        )


class HeappushpopModel(FunctionModel):
    """Model for heapq.heappushpop()."""

    name = "heappushpop"
    qualname = "heapq.heappushpop"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"heappushpop_{state .pc }")
        return ModelResult(
            value=result,
            constraints=[constraint],
            side_effects={"mutates_arg": 0},
        )


class NlargestModel(FunctionModel):
    """Model for heapq.nlargest()."""

    name = "nlargest"
    qualname = "heapq.nlargest"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"nlargest_{state .pc }")
        if args and isinstance(args[0], int):
            return ModelResult(
                value=result,
                constraints=[constraint, result.z3_len == args[0]],
            )
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class NsmallestModel(FunctionModel):
    """Model for heapq.nsmallest()."""

    name = "nsmallest"
    qualname = "heapq.nsmallest"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"nsmallest_{state .pc }")
        if args and isinstance(args[0], int):
            return ModelResult(
                value=result,
                constraints=[constraint, result.z3_len == args[0]],
            )
        return ModelResult(value=result, constraints=[constraint, result.z3_len >= 0])


class BisectLeftModel(FunctionModel):
    """Model for bisect.bisect_left()."""

    name = "bisect_left"
    qualname = "bisect.bisect_left"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"bisect_left_{state .pc }")
        constraints = [constraint, result.is_int, result.z3_int >= 0]
        if len(args) >= 1:
            lst = args[0]
            if isinstance(lst, SymbolicList):
                constraints.append(result.z3_int <= lst.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BisectRightModel(FunctionModel):
    """Model for bisect.bisect_right()."""

    name = "bisect_right"
    qualname = "bisect.bisect_right"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"bisect_right_{state .pc }")
        constraints = [constraint, result.is_int, result.z3_int >= 0]
        if len(args) >= 1:
            lst = args[0]
            if isinstance(lst, SymbolicList):
                constraints.append(result.z3_int <= lst.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BisectModel(FunctionModel):
    """Model for bisect.bisect() (alias for bisect_right)."""

    name = "bisect"
    qualname = "bisect.bisect"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"bisect_{state .pc }")
        constraints = [constraint, result.is_int, result.z3_int >= 0]
        if len(args) >= 1:
            lst = args[0]
            if isinstance(lst, SymbolicList):
                constraints.append(result.z3_int <= lst.z3_len)
        return ModelResult(value=result, constraints=constraints)


class InsortLeftModel(FunctionModel):
    """Model for bisect.insort_left()."""

    name = "insort_left"
    qualname = "bisect.insort_left"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        return ModelResult(
            value=SymbolicNone("none"),
            side_effects={"mutates_arg": 0},
        )


class InsortRightModel(FunctionModel):
    """Model for bisect.insort_right()."""

    name = "insort_right"
    qualname = "bisect.insort_right"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        return ModelResult(
            value=SymbolicNone("none"),
            side_effects={"mutates_arg": 0},
        )


class InsortModel(FunctionModel):
    """Model for bisect.insort() (alias for insort_right)."""

    name = "insort"
    qualname = "bisect.insort"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        return ModelResult(
            value=SymbolicNone("none"),
            side_effects={"mutates_arg": 0},
        )


copy_models = [
    CopyModel(),
    DeepcopyModel(),
]
io_models = [
    StringIOModel(),
    BytesIOModel(),
    IOReadModel(),
    IOWriteModel(),
    IOGetvalueModel(),
]
heapq_models = [
    HeappushModel(),
    HeappopModel(),
    HeapifyModel(),
    HeapreplaceModel(),
    HeappushpopModel(),
    NlargestModel(),
    NsmallestModel(),
]
bisect_models = [
    BisectLeftModel(),
    BisectRightModel(),
    BisectModel(),
    InsortLeftModel(),
    InsortRightModel(),
    InsortModel(),
]