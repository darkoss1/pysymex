"""Symbolic models for Python bytes and bytearray operations.

Provides relationship-preserving symbolic models for bytes/bytearray methods.
bytes is immutable (like str), bytearray is mutable (like list).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.core.types import SymbolicList, SymbolicNone, SymbolicString, SymbolicValue
from pysymex.models.builtins_base import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState


def _get_symbolic_bytes(arg: object) -> SymbolicList | None:
    """Extract SymbolicList (used for bytes/bytearray) from argument."""
    if isinstance(arg, SymbolicList):
        return arg
    return getattr(arg, "_symbolic_list", None) if arg is not None else None


class BytesDecodeModel(FunctionModel):
    """Model for bytes.decode()."""

    name = "decode"
    qualname = "bytes.decode"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.decode()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicString.symbolic(f"decode_{state .pc }")
        constraints = [constraint]
        if b is not None:
            constraints.append(result.z3_len <= b.z3_len)
            constraints.append(result.z3_len >= 0)
        return ModelResult(value=result, constraints=constraints)


class BytesCountModel(FunctionModel):
    """Model for bytes.count(sub)."""

    name = "count"
    qualname = "bytes.count"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.count(sub)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_count_{state .pc }")
        constraints = [constraint, result.is_int, result.z3_int >= 0]
        if b is not None:
            constraints.append(result.z3_int <= b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytesFindModel(FunctionModel):
    """Model for bytes.find(sub)."""

    name = "find"
    qualname = "bytes.find"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.find(sub)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_find_{state .pc }")
        constraints = [constraint, result.is_int, result.z3_int >= -1]
        if b is not None:
            constraints.append(result.z3_int < b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytesRfindModel(FunctionModel):
    """Model for bytes.rfind(sub)."""

    name = "rfind"
    qualname = "bytes.rfind"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.rfind(sub)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_rfind_{state .pc }")
        constraints = [constraint, result.is_int, result.z3_int >= -1]
        if b is not None:
            constraints.append(result.z3_int < b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytesIndexModel(FunctionModel):
    """Model for bytes.index(sub)."""

    name = "index"
    qualname = "bytes.index"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.index(sub)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_index_{state .pc }")
        constraints = [constraint, result.is_int, result.z3_int >= 0]
        side_effects: dict[str, object] = {
            "potential_exception": {"type": "ValueError", "message": "subsection not found"}
        }
        if b is not None:
            constraints.append(result.z3_int < b.z3_len)
        return ModelResult(value=result, constraints=constraints, side_effects=side_effects)


class BytesRindexModel(FunctionModel):
    """Model for bytes.rindex(sub)."""

    name = "rindex"
    qualname = "bytes.rindex"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.rindex(sub)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_rindex_{state .pc }")
        constraints = [constraint, result.is_int, result.z3_int >= 0]
        side_effects: dict[str, object] = {
            "potential_exception": {"type": "ValueError", "message": "subsection not found"}
        }
        if b is not None:
            constraints.append(result.z3_int < b.z3_len)
        return ModelResult(value=result, constraints=constraints, side_effects=side_effects)


class BytesJoinModel(FunctionModel):
    """Model for bytes.join(iterable)."""

    name = "join"
    qualname = "bytes.join"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.join(iterable)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"bytes_join_{state .pc }")
        constraints = [constraint, result.z3_len >= 0]
        return ModelResult(value=result, constraints=constraints)


class BytesSplitModel(FunctionModel):
    """Model for bytes.split(sep)."""

    name = "split"
    qualname = "bytes.split"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.split(sep)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_split_{state .pc }")
        constraints = [constraint, result.z3_len >= 1]
        if b is not None:
            constraints.append(result.z3_len <= b.z3_len + 1)
        return ModelResult(value=result, constraints=constraints)


class BytesRsplitModel(FunctionModel):
    """Model for bytes.rsplit(sep)."""

    name = "rsplit"
    qualname = "bytes.rsplit"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.rsplit(sep)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_rsplit_{state .pc }")
        constraints = [constraint, result.z3_len >= 1]
        if b is not None:
            constraints.append(result.z3_len <= b.z3_len + 1)
        return ModelResult(value=result, constraints=constraints)


class BytesReplaceModel(FunctionModel):
    """Model for bytes.replace(old, new)."""

    name = "replace"
    qualname = "bytes.replace"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.replace(old, new)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"bytes_replace_{state .pc }")
        constraints = [constraint, result.z3_len >= 0]
        return ModelResult(value=result, constraints=constraints)


class BytesStripModel(FunctionModel):
    """Model for bytes.strip()."""

    name = "strip"
    qualname = "bytes.strip"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.strip()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_strip_{state .pc }")
        constraints = [constraint, result.z3_len >= 0]
        if b is not None:
            constraints.append(result.z3_len <= b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytesLstripModel(FunctionModel):
    """Model for bytes.lstrip()."""

    name = "lstrip"
    qualname = "bytes.lstrip"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.lstrip()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_lstrip_{state .pc }")
        constraints = [constraint, result.z3_len >= 0]
        if b is not None:
            constraints.append(result.z3_len <= b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytesRstripModel(FunctionModel):
    """Model for bytes.rstrip()."""

    name = "rstrip"
    qualname = "bytes.rstrip"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.rstrip()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_rstrip_{state .pc }")
        constraints = [constraint, result.z3_len >= 0]
        if b is not None:
            constraints.append(result.z3_len <= b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytesStartswithModel(FunctionModel):
    """Model for bytes.startswith(prefix)."""

    name = "startswith"
    qualname = "bytes.startswith"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.startswith(prefix)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_startswith_{state .pc }")
        constraints = [constraint, result.is_bool]
        if b is not None:
            constraints.append(z3.Implies(b.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class BytesEndswithModel(FunctionModel):
    """Model for bytes.endswith(suffix)."""

    name = "endswith"
    qualname = "bytes.endswith"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.endswith(suffix)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_endswith_{state .pc }")
        constraints = [constraint, result.is_bool]
        if b is not None:
            constraints.append(z3.Implies(b.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class BytesUpperModel(FunctionModel):
    """Model for bytes.upper()."""

    name = "upper"
    qualname = "bytes.upper"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.upper()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_upper_{state .pc }")
        constraints = [constraint]
        if b is not None:
            constraints.append(result.z3_len == b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytesLowerModel(FunctionModel):
    """Model for bytes.lower()."""

    name = "lower"
    qualname = "bytes.lower"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.lower()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_lower_{state .pc }")
        constraints = [constraint]
        if b is not None:
            constraints.append(result.z3_len == b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytesTitleModel(FunctionModel):
    """Model for bytes.title()."""

    name = "title"
    qualname = "bytes.title"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.title()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_title_{state .pc }")
        constraints = [constraint]
        if b is not None:
            constraints.append(result.z3_len == b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytesCapitalizeModel(FunctionModel):
    """Model for bytes.capitalize()."""

    name = "capitalize"
    qualname = "bytes.capitalize"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.capitalize()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_capitalize_{state .pc }")
        constraints = [constraint]
        if b is not None:
            constraints.append(result.z3_len == b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytesSwapcaseModel(FunctionModel):
    """Model for bytes.swapcase()."""

    name = "swapcase"
    qualname = "bytes.swapcase"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.swapcase()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_swapcase_{state .pc }")
        constraints = [constraint]
        if b is not None:
            constraints.append(result.z3_len == b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytesContainsModel(FunctionModel):
    """Model for bytes.__contains__(sub)."""

    name = "__contains__"
    qualname = "bytes.__contains__"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.__contains__(sub)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_contains_{state .pc }")
        constraints = [constraint, result.is_bool]
        if b is not None:
            constraints.append(z3.Implies(b.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class BytesLenModel(FunctionModel):
    """Model for len(bytes)."""

    name = "__len__"
    qualname = "bytes.__len__"

    def apply(
        self,
        args: list[StackValue],
        """Apply the len(bytes)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        if b is not None:
            result = SymbolicValue(
                _name=f"len_bytes_{state .pc }",
                z3_int=b.z3_len,
                is_int=z3.BoolVal(True),
                z3_bool=z3.BoolVal(False),
                is_bool=z3.BoolVal(False),
            )
            return ModelResult(value=result, constraints=[])
        result, constraint = SymbolicValue.symbolic(f"bytes_len_{state .pc }")
        return ModelResult(
            value=result,
            constraints=[constraint, result.is_int, result.z3_int >= 0],
        )


class BytesHexModel(FunctionModel):
    """Model for bytes.hex()."""

    name = "hex"
    qualname = "bytes.hex"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.hex()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicString.symbolic(f"bytes_hex_{state .pc }")
        constraints = [constraint]
        if b is not None:
            constraints.append(result.z3_len == b.z3_len * 2)
        return ModelResult(value=result, constraints=constraints)


class BytesPartitionModel(FunctionModel):
    """Model for bytes.partition(sep)."""

    name = "partition"
    qualname = "bytes.partition"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.partition(sep)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"bytes_partition_{state .pc }")
        constraints = [constraint, result.z3_len == 3]
        return ModelResult(value=result, constraints=constraints)


class BytesRpartitionModel(FunctionModel):
    """Model for bytes.rpartition(sep)."""

    name = "rpartition"
    qualname = "bytes.rpartition"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.rpartition(sep)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"bytes_rpartition_{state .pc }")
        constraints = [constraint, result.z3_len == 3]
        return ModelResult(value=result, constraints=constraints)


class BytesSplitlinesModel(FunctionModel):
    """Model for bytes.splitlines()."""

    name = "splitlines"
    qualname = "bytes.splitlines"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.splitlines()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_splitlines_{state .pc }")
        constraints = [constraint, result.z3_len >= 0]
        if b is not None:
            constraints.append(result.z3_len <= b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytesCenterModel(FunctionModel):
    """Model for bytes.center(width)."""

    name = "center"
    qualname = "bytes.center"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.center(width)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        width = args[1] if len(args) > 1 else None
        result, constraint = SymbolicList.symbolic(f"bytes_center_{state .pc }")
        constraints = [constraint]
        if b is not None and width is not None:
            w = getattr(width, "z3_int", None)
            if w is not None:
                constraints.append(result.z3_len == z3.If(w > b.z3_len, w, b.z3_len))
        return ModelResult(value=result, constraints=constraints)


class BytesLjustModel(FunctionModel):
    """Model for bytes.ljust(width)."""

    name = "ljust"
    qualname = "bytes.ljust"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.ljust(width)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        width = args[1] if len(args) > 1 else None
        result, constraint = SymbolicList.symbolic(f"bytes_ljust_{state .pc }")
        constraints = [constraint]
        if b is not None and width is not None:
            w = getattr(width, "z3_int", None)
            if w is not None:
                constraints.append(result.z3_len == z3.If(w > b.z3_len, w, b.z3_len))
        return ModelResult(value=result, constraints=constraints)


class BytesRjustModel(FunctionModel):
    """Model for bytes.rjust(width)."""

    name = "rjust"
    qualname = "bytes.rjust"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.rjust(width)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        width = args[1] if len(args) > 1 else None
        result, constraint = SymbolicList.symbolic(f"bytes_rjust_{state .pc }")
        constraints = [constraint]
        if b is not None and width is not None:
            w = getattr(width, "z3_int", None)
            if w is not None:
                constraints.append(result.z3_len == z3.If(w > b.z3_len, w, b.z3_len))
        return ModelResult(value=result, constraints=constraints)


class BytesZfillModel(FunctionModel):
    """Model for bytes.zfill(width)."""

    name = "zfill"
    qualname = "bytes.zfill"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.zfill(width)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        width = args[1] if len(args) > 1 else None
        result, constraint = SymbolicList.symbolic(f"bytes_zfill_{state .pc }")
        constraints = [constraint]
        if b is not None and width is not None:
            w = getattr(width, "z3_int", None)
            if w is not None:
                constraints.append(result.z3_len == z3.If(w > b.z3_len, w, b.z3_len))
        return ModelResult(value=result, constraints=constraints)


class BytesTranslateModel(FunctionModel):
    """Model for bytes.translate(table)."""

    name = "translate"
    qualname = "bytes.translate"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.translate(table)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_translate_{state .pc }")
        constraints = [constraint, result.z3_len >= 0]
        if b is not None:
            constraints.append(result.z3_len <= b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytesMaketransModel(FunctionModel):
    """Model for bytes.maketrans(from, to)."""

    name = "maketrans"
    qualname = "bytes.maketrans"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.maketrans(from, to)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"bytes_maketrans_{state .pc }")
        constraints = [constraint, result.z3_len == 256]
        return ModelResult(value=result, constraints=constraints)


class BytesExpandtabsModel(FunctionModel):
    """Model for bytes.expandtabs()."""

    name = "expandtabs"
    qualname = "bytes.expandtabs"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.expandtabs()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_expandtabs_{state .pc }")
        constraints = [constraint]
        if b is not None:
            constraints.append(result.z3_len >= b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytesIsdigitModel(FunctionModel):
    """Model for bytes.isdigit()."""

    name = "isdigit"
    qualname = "bytes.isdigit"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.isdigit()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_isdigit_{state .pc }")
        constraints = [constraint, result.is_bool]
        if b is not None:
            constraints.append(z3.Implies(b.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class BytesIsalphaModel(FunctionModel):
    """Model for bytes.isalpha()."""

    name = "isalpha"
    qualname = "bytes.isalpha"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.isalpha()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_isalpha_{state .pc }")
        constraints = [constraint, result.is_bool]
        if b is not None:
            constraints.append(z3.Implies(b.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class BytesIsalnumModel(FunctionModel):
    """Model for bytes.isalnum()."""

    name = "isalnum"
    qualname = "bytes.isalnum"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.isalnum()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_isalnum_{state .pc }")
        constraints = [constraint, result.is_bool]
        if b is not None:
            constraints.append(z3.Implies(b.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class BytesIsspaceModel(FunctionModel):
    """Model for bytes.isspace()."""

    name = "isspace"
    qualname = "bytes.isspace"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.isspace()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_isspace_{state .pc }")
        constraints = [constraint, result.is_bool]
        if b is not None:
            constraints.append(z3.Implies(b.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class BytesIslowerModel(FunctionModel):
    """Model for bytes.islower()."""

    name = "islower"
    qualname = "bytes.islower"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.islower()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_islower_{state .pc }")
        constraints = [constraint, result.is_bool]
        if b is not None:
            constraints.append(z3.Implies(b.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class BytesIsupperModel(FunctionModel):
    """Model for bytes.isalpha()."""

    name = "isupper"
    qualname = "bytes.isupper"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.isalpha()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_isupper_{state .pc }")
        constraints = [constraint, result.is_bool]
        if b is not None:
            constraints.append(z3.Implies(b.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class BytesIstitleModel(FunctionModel):
    """Model for bytes.istitle()."""

    name = "istitle"
    qualname = "bytes.istitle"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.istitle()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytes_istitle_{state .pc }")
        constraints = [constraint, result.is_bool]
        if b is not None:
            constraints.append(z3.Implies(b.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class BytesRemovePrefixModel(FunctionModel):
    """Model for bytes.removeprefix(prefix)."""

    name = "removeprefix"
    qualname = "bytes.removeprefix"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.removeprefix(prefix)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_removeprefix_{state .pc }")
        constraints = [constraint, result.z3_len >= 0]
        if b is not None:
            constraints.append(result.z3_len <= b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytesRemoveSuffixModel(FunctionModel):
    """Model for bytes.removesuffix(suffix)."""

    name = "removesuffix"
    qualname = "bytes.removesuffix"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytes.removesuffix(suffix)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"bytes_removesuffix_{state .pc }")
        constraints = [constraint, result.z3_len >= 0]
        if b is not None:
            constraints.append(result.z3_len <= b.z3_len)
        return ModelResult(value=result, constraints=constraints)


class BytearrayAppendModel(FunctionModel):
    """Model for bytearray.append(item)."""

    name = "append"
    qualname = "bytearray.append"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytearray.append(item)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        side_effects: dict[str, object] = {}
        if b is not None:
            new_len = z3.Int(f"bytearray_len_{state .pc }")
            constraints.append(new_len == b.z3_len + 1)
            b.z3_len = new_len
            side_effects["bytearray_mutation"] = {"operation": "append"}
        return ModelResult(value=SymbolicNone(), constraints=constraints, side_effects=side_effects)


class BytearrayExtendModel(FunctionModel):
    """Model for bytearray.extend(iterable)."""

    name = "extend"
    qualname = "bytearray.extend"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytearray.extend(iterable)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        side_effects: dict[str, object] = {}
        if b is not None:
            new_len = z3.Int(f"bytearray_len_{state .pc }")
            constraints.append(new_len >= b.z3_len)
            b.z3_len = new_len
            side_effects["bytearray_mutation"] = {"operation": "extend"}
        return ModelResult(value=SymbolicNone(), constraints=constraints, side_effects=side_effects)


class BytearrayInsertModel(FunctionModel):
    """Model for bytearray.insert(index, item)."""

    name = "insert"
    qualname = "bytearray.insert"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytearray.insert(index, item)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        side_effects: dict[str, object] = {}
        if b is not None:
            new_len = z3.Int(f"bytearray_len_{state .pc }")
            constraints.append(new_len == b.z3_len + 1)
            b.z3_len = new_len
            side_effects["bytearray_mutation"] = {"operation": "insert"}
        return ModelResult(value=SymbolicNone(), constraints=constraints, side_effects=side_effects)


class BytearrayPopModel(FunctionModel):
    """Model for bytearray.pop(index=-1)."""

    name = "pop"
    qualname = "bytearray.pop"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytearray.pop(index=-1)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"bytearray_pop_{state .pc }")
        constraints = [constraint, result.is_int, result.z3_int >= 0, result.z3_int <= 255]
        side_effects: dict[str, object] = {}
        if b is not None:
            side_effects["potential_exception"] = {
                "type": "IndexError",
                "condition": b.z3_len == 0,
                "message": "pop from empty bytearray",
            }
            new_len = z3.Int(f"bytearray_len_{state .pc }")
            constraints.append(new_len == b.z3_len - 1)
            constraints.append(new_len >= 0)
            b.z3_len = new_len
            side_effects["bytearray_mutation"] = {"operation": "pop"}
        return ModelResult(value=result, constraints=constraints, side_effects=side_effects)


class BytearrayRemoveModel(FunctionModel):
    """Model for bytearray.remove(value)."""

    name = "remove"
    qualname = "bytearray.remove"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytearray.remove(value)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        side_effects: dict[str, object] = {
            "potential_exception": {"type": "ValueError", "message": "value not found in bytearray"}
        }
        if b is not None:
            new_len = z3.Int(f"bytearray_len_{state .pc }")
            constraints.append(new_len == b.z3_len - 1)
            constraints.append(new_len >= 0)
            b.z3_len = new_len
            side_effects["bytearray_mutation"] = {"operation": "remove"}
        return ModelResult(value=SymbolicNone(), constraints=constraints, side_effects=side_effects)


class BytearrayClearModel(FunctionModel):
    """Model for bytearray.clear()."""

    name = "clear"
    qualname = "bytearray.clear"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytearray.clear()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if b is not None:
            b.z3_len = z3.IntVal(0)
        return ModelResult(value=SymbolicNone(), constraints=constraints)


class BytearrayReverseModel(FunctionModel):
    """Model for bytearray.reverse()."""

    name = "reverse"
    qualname = "bytearray.reverse"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytearray.reverse()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        return ModelResult(value=SymbolicNone())


class BytearrayCopyModel(FunctionModel):
    """Model for bytearray.copy()."""

    name = "copy"
    qualname = "bytearray.copy"

    def apply(
        self,
        args: list[StackValue],
        """Apply the bytearray.copy()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        b = _get_symbolic_bytes(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"bytearray_copy_{state .pc }")
        constraints = [constraint]
        if b is not None:
            constraints.append(result.z3_len == b.z3_len)
        return ModelResult(value=result, constraints=constraints)


BYTES_MODELS = [
    BytesDecodeModel(),
    BytesCountModel(),
    BytesFindModel(),
    BytesRfindModel(),
    BytesIndexModel(),
    BytesRindexModel(),
    BytesJoinModel(),
    BytesSplitModel(),
    BytesRsplitModel(),
    BytesReplaceModel(),
    BytesStripModel(),
    BytesLstripModel(),
    BytesRstripModel(),
    BytesStartswithModel(),
    BytesEndswithModel(),
    BytesUpperModel(),
    BytesLowerModel(),
    BytesTitleModel(),
    BytesCapitalizeModel(),
    BytesSwapcaseModel(),
    BytesContainsModel(),
    BytesLenModel(),
    BytesHexModel(),
    BytesPartitionModel(),
    BytesRpartitionModel(),
    BytesSplitlinesModel(),
    BytesCenterModel(),
    BytesLjustModel(),
    BytesRjustModel(),
    BytesZfillModel(),
    BytesTranslateModel(),
    BytesMaketransModel(),
    BytesExpandtabsModel(),
    BytesIsdigitModel(),
    BytesIsalphaModel(),
    BytesIsalnumModel(),
    BytesIsspaceModel(),
    BytesIslowerModel(),
    BytesIsupperModel(),
    BytesIstitleModel(),
    BytesRemovePrefixModel(),
    BytesRemoveSuffixModel(),
    BytearrayAppendModel(),
    BytearrayExtendModel(),
    BytearrayInsertModel(),
    BytearrayPopModel(),
    BytearrayRemoveModel(),
    BytearrayClearModel(),
    BytearrayReverseModel(),
    BytearrayCopyModel(),
]


class BytesIsasciiModel(FunctionModel):
    name = "isascii"
    qualname = "bytes.isascii"

    def apply(
        self,
        args: list[StackValue],
        """Apply the BytesIsasciiModel model."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"isascii_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class BytearrayIsasciiModel(FunctionModel):
    name = "isascii"
    qualname = "bytearray.isascii"

    def apply(
        self,
        args: list[StackValue],
        """Apply the BytearrayIsasciiModel model."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"isascii_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


BYTES_MODELS.extend([BytesIsasciiModel(), BytearrayIsasciiModel()])
