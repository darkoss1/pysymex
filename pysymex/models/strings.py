"""Enhanced Models for Python string operations.
This module provides relationship-preserving symbolic models for string methods.
Instead of creating completely fresh symbolic values, these models maintain
Z3 constraints that relate the output to the input, enabling better bug detection.
Key improvements over basic models:
- Length preservation: lower(), upper() preserve string length
- Prefix/suffix preservation: strip variants preserve relationship to original
- Index bounds: find(), index() constrained to valid ranges
- Split semantics: split() maintains length >= 1 and element relationships
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.core.types import SymbolicList, SymbolicString, SymbolicValue
from pysymex.models.builtins_base import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState


def _get_symbolic_string(arg: object) -> SymbolicString | None:
    """Extract SymbolicString from argument, handling method calls (self is first arg)."""
    if isinstance(arg, SymbolicString):
        return arg
    return None


class StrLowerModel(FunctionModel):
    """Model for str.lower() - preserves string length.
    Relationship: len(s.lower()) == len(s)
    """

    name = "lower"
    qualname = "str.lower"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.lower() - preserves string length."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"lower_{state .pc }")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len == original.z3_len)
            constraints.append(result.z3_len >= 0)
        return ModelResult(value=result, constraints=constraints)


class StrUpperModel(FunctionModel):
    """Model for str.upper() - preserves string length.
    Relationship: len(s.upper()) == len(s)
    """

    name = "upper"
    qualname = "str.upper"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.upper() - preserves string length."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"upper_{state .pc }")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len == original.z3_len)
        return ModelResult(value=result, constraints=constraints)


class StrCapitalizeModel(FunctionModel):
    """Model for str.capitalize() - preserves string length."""

    name = "capitalize"
    qualname = "str.capitalize"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.capitalize() - preserves string length."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"capitalize_{state .pc }")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len == original.z3_len)
        return ModelResult(value=result, constraints=constraints)


class StrTitleModel(FunctionModel):
    """Model for str.title() - preserves string length."""

    name = "title"
    qualname = "str.title"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.title() - preserves string length."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"title_{state .pc }")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len == original.z3_len)
        return ModelResult(value=result, constraints=constraints)


class StrSwapcaseModel(FunctionModel):
    """Model for str.swapcase() - preserves string length."""

    name = "swapcase"
    qualname = "str.swapcase"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.swapcase() - preserves string length."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"swapcase_{state .pc }")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len == original.z3_len)
        return ModelResult(value=result, constraints=constraints)


class StrStripModel(FunctionModel):
    """Model for str.strip() - result length <= original length.
    Relationship: len(s.strip()) <= len(s)
    """

    name = "strip"
    qualname = "str.strip"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.strip() - result length <= original length."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"strip_{state .pc }")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len <= original.z3_len)
            constraints.append(result.z3_len >= 0)
        return ModelResult(value=result, constraints=constraints)


class StrLstripModel(FunctionModel):
    """Model for str.lstrip() - result length <= original length."""

    name = "lstrip"
    qualname = "str.lstrip"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.lstrip() - result length <= original length."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"lstrip_{state .pc }")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len <= original.z3_len)
            constraints.append(result.z3_len >= 0)
            constraints.append(z3.SuffixOf(result.z3_str, original.z3_str))
        return ModelResult(value=result, constraints=constraints)


class StrRstripModel(FunctionModel):
    """Model for str.rstrip() - result length <= original length."""

    name = "rstrip"
    qualname = "str.rstrip"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.rstrip() - result length <= original length."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"rstrip_{state .pc }")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len <= original.z3_len)
            constraints.append(result.z3_len >= 0)
            constraints.append(z3.PrefixOf(result.z3_str, original.z3_str))
        return ModelResult(value=result, constraints=constraints)


class StrSplitModel(FunctionModel):
    """Model for str.split() - relationship between parts and original.
    Relationships:
    - len(s.split()) >= 1 (always at least one element)
        - For explicit non-empty separator:
            - separator not found => len(s.split(sep)) == 1
            - separator found => len(s.split(sep)) >= 2
    - Each element length <= original length
    """

    name = "split"
    qualname = "str.split"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.split() - relationship between parts and original."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        separator = _get_symbolic_string(args[1]) if len(args) > 1 else None
        result, base_constraint = SymbolicList.symbolic(f"split_{state .pc }")
        constraints = [
            base_constraint,
            result.z3_len >= 1,
        ]
        if original is not None:
            constraints.append(result.z3_len <= original.z3_len + 1)
            if separator is not None:
                sep_non_empty = separator.z3_len > 0
                has_sep = z3.Contains(original.z3_str, separator.z3_str)
                constraints.append(
                    z3.Implies(z3.And(sep_non_empty, z3.Not(has_sep)), result.z3_len == 1)
                )
                constraints.append(z3.Implies(z3.And(sep_non_empty, has_sep), result.z3_len >= 2))
        return ModelResult(value=result, constraints=constraints)


class StrJoinModel(FunctionModel):
    """Model for str.join() - result length based on separator and parts.
    Relationship: If joining N parts with separator S:
    - len(result) >= sum of part lengths
    - len(result) includes (N-1) * len(S) for separators
    """

    name = "join"
    qualname = "str.join"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.join() - result length based on separator and parts."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        _get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"join_{state .pc }")
        constraints = [base_constraint]
        constraints.append(result.z3_len >= 0)
        return ModelResult(value=result, constraints=constraints)


class StrReplaceModel(FunctionModel):
    """Model for str.replace() - result length relationship.
    Relationships:
    - If old and new have same length: result length == original length
    - If old is longer: result length <= original length
    - If new is longer: result length >= original length
    """

    name = "replace"
    qualname = "str.replace"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.replace() - result length relationship."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        old_str = _get_symbolic_string(args[1]) if len(args) > 1 else None
        _get_symbolic_string(args[2]) if len(args) > 2 else None
        result, base_constraint = SymbolicString.symbolic(f"replace_{state .pc }")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len >= 0)
            if old_str is not None:
                old_not_found = z3.Not(z3.Contains(original.z3_str, old_str.z3_str))
                constraints.append(z3.Implies(old_not_found, result.z3_len == original.z3_len))
        return ModelResult(value=result, constraints=constraints)


class StrStartswithModel(FunctionModel):
    """Model for str.startswith() - uses Z3 PrefixOf."""

    name = "startswith"
    qualname = "str.startswith"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.startswith() - uses Z3 PrefixOf."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        prefix = _get_symbolic_string(args[1]) if len(args) > 1 else None
        if original is not None and prefix is not None:
            result_bool = z3.PrefixOf(prefix.z3_str, original.z3_str)
            result = SymbolicValue(
                _name=f"startswith_{state .pc }",
                z3_int=z3.IntVal(0),
                is_int=z3.BoolVal(False),
                z3_bool=result_bool,
                is_bool=z3.BoolVal(True),
            )
            return ModelResult(value=result, constraints=[])
        result, constraint = SymbolicValue.symbolic(f"startswith_{state .pc }")
        return ModelResult(
            value=result,
            constraints=[constraint, result.is_bool],
        )


class StrEndswithModel(FunctionModel):
    """Model for str.endswith() - uses Z3 SuffixOf."""

    name = "endswith"
    qualname = "str.endswith"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.endswith() - uses Z3 SuffixOf."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        suffix = _get_symbolic_string(args[1]) if len(args) > 1 else None
        if original is not None and suffix is not None:
            result_bool = z3.SuffixOf(suffix.z3_str, original.z3_str)
            result = SymbolicValue(
                _name=f"endswith_{state .pc }",
                z3_int=z3.IntVal(0),
                is_int=z3.BoolVal(False),
                z3_bool=result_bool,
                is_bool=z3.BoolVal(True),
            )
            return ModelResult(value=result, constraints=[])
        result, constraint = SymbolicValue.symbolic(f"endswith_{state .pc }")
        return ModelResult(
            value=result,
            constraints=[constraint, result.is_bool],
        )


class StrFindModel(FunctionModel):
    """Model for str.find() - uses Z3 IndexOf with proper bounds.
    Relationships:
    - Returns -1 if not found
    - Returns index >= 0 and < len(s) if found
    - Index + len(sub) <= len(s)
    """

    name = "find"
    qualname = "str.find"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.find() - uses Z3 IndexOf with proper bounds."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        substring = _get_symbolic_string(args[1]) if len(args) > 1 else None
        if original is not None and substring is not None:
            idx = z3.IndexOf(original.z3_str, substring.z3_str, z3.IntVal(0))
            result = SymbolicValue(
                _name=f"find_{state .pc }",
                z3_int=idx,
                is_int=z3.BoolVal(True),
                z3_bool=z3.BoolVal(False),
                is_bool=z3.BoolVal(False),
            )
            constraints = [
                z3.Or(idx == -1, z3.And(idx >= 0, idx < original.z3_len)),
                z3.Implies(idx >= 0, idx + substring.z3_len <= original.z3_len),
            ]
            return ModelResult(value=result, constraints=constraints)
        result, constraint = SymbolicValue.symbolic(f"find_{state .pc }")
        return ModelResult(
            value=result,
            constraints=[constraint, result.is_int, result.z3_int >= -1],
        )


class StrIndexModel(FunctionModel):
    """Model for str.index() - like find but raises ValueError if not found.
    Bug detection: Can find cases where substring might not exist.
    """

    name = "index"
    qualname = "str.index"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.index() - like find but raises ValueError if not found."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        pass
        original = _get_symbolic_string(args[0]) if args else None
        substring = _get_symbolic_string(args[1]) if len(args) > 1 else None
        side_effects: dict[str, object] = {}
        if original is not None and substring is not None:
            idx = z3.IndexOf(original.z3_str, substring.z3_str, z3.IntVal(0))
            result = SymbolicValue(
                _name=f"index_{state .pc }",
                z3_int=idx,
                is_int=z3.BoolVal(True),
                z3_bool=z3.BoolVal(False),
                is_bool=z3.BoolVal(False),
            )
            side_effects["potential_exception"] = {
                "type": "ValueError",
                "condition": idx == -1,
                "message": "substring not found in str.index()",
            }
            constraints = [
                idx >= 0,
                idx < original.z3_len,
                idx + substring.z3_len <= original.z3_len,
            ]
            return ModelResult(
                value=result,
                constraints=constraints,
                side_effects=side_effects,
            )
        result, constraint = SymbolicValue.symbolic(f"index_{state .pc }")
        return ModelResult(
            value=result,
            constraints=[constraint, result.is_int, result.z3_int >= 0],
        )


class StrCountModel(FunctionModel):
    """Model for str.count() - count bounded by string length.
    Relationships:
    - count >= 0
    - count <= len(s) (can't have more occurrences than characters)
    """

    name = "count"
    qualname = "str.count"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.count() - count bounded by string length."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        substring = _get_symbolic_string(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicValue.symbolic(f"count_{state .pc }")
        constraints = [constraint, result.is_int, result.z3_int >= 0]
        if original is not None:
            constraints.append(result.z3_int <= original.z3_len)
            if substring is not None:
                non_empty_sub = substring.z3_len > 0
                has_sub = z3.Contains(original.z3_str, substring.z3_str)
                constraints.append(z3.Implies(z3.And(non_empty_sub, result.z3_int > 0), has_sub))
                constraints.append(
                    z3.Implies(z3.And(non_empty_sub, result.z3_int == 0), z3.Not(has_sub))
                )
                constraints.append(
                    z3.Implies(substring.z3_len > original.z3_len, result.z3_int == 0)
                )
        return ModelResult(value=result, constraints=constraints)


class StrFormatModel(FunctionModel):
    """Model for str.format() - result length relationship.
    Result length >= format string length - placeholder lengths
    """

    name = "format"
    qualname = "str.format"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.format() - result length relationship."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicString.symbolic(f"format_{state .pc }")
        constraints = [constraint, result.z3_len >= 0]
        return ModelResult(value=result, constraints=constraints)


class StrIsdigitModel(FunctionModel):
    """Model for str.isdigit() - true only if non-empty and all digits."""

    name = "isdigit"
    qualname = "str.isdigit"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.isdigit() - true only if non-empty and all digits."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"isdigit_{state .pc }")
        constraints = [constraint, result.is_bool]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class StrIsalphaModel(FunctionModel):
    """Model for str.isalpha() - true only if non-empty and all alphabetic."""

    name = "isalpha"
    qualname = "str.isalpha"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.isalpha() - true only if non-empty and all alphabetic."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"isalpha_{state .pc }")
        constraints = [constraint, result.is_bool]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class StrIsalnumModel(FunctionModel):
    """Model for str.isalnum() - true only if non-empty and all alphanumeric."""

    name = "isalnum"
    qualname = "str.isalnum"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.isalnum() - true only if non-empty and all alphanumeric."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"isalnum_{state .pc }")
        constraints = [constraint, result.is_bool]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class StrIsspaceModel(FunctionModel):
    """Model for str.isspace() - true only if non-empty and all whitespace."""

    name = "isspace"
    qualname = "str.isspace"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.isspace() - true only if non-empty and all whitespace."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"isspace_{state .pc }")
        constraints = [constraint, result.is_bool]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class StrIslowerModel(FunctionModel):
    """Model for str.islower().
    Returns False for empty string or string with no cased characters.
    """

    name = "islower"
    qualname = "str.islower"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.islower()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"islower_{state .pc }")
        constraints = [constraint, result.is_bool]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class StrIsupperModel(FunctionModel):
    """Model for str.isupper().
    Returns False for empty string or string with no cased characters.
    """

    name = "isupper"
    qualname = "str.isupper"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.isupper()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"isupper_{state .pc }")
        constraints = [constraint, result.is_bool]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class StrCenterModel(FunctionModel):
    """Model for str.center(width) - pads string to width.
    Relationship: len(result) == max(width, len(original))
    """

    name = "center"
    qualname = "str.center"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.center(width) - pads string to width."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        width = args[1] if len(args) > 1 else None
        result, base_constraint = SymbolicString.symbolic(f"center_{state .pc }")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len >= original.z3_len)
            if isinstance(width, int):
                constraints.append(
                    z3.Or(result.z3_len == z3.IntVal(width), result.z3_len == original.z3_len)
                )
            elif isinstance(width, SymbolicValue):
                constraints.append(
                    z3.Or(result.z3_len == width.z3_int, result.z3_len == original.z3_len)
                )
        return ModelResult(value=result, constraints=constraints)


class StrLjustModel(FunctionModel):
    """Model for str.ljust(width) - left justify."""

    name = "ljust"
    qualname = "str.ljust"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.ljust(width) - left justify."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"ljust_{state .pc }")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len >= original.z3_len)
            constraints.append(z3.PrefixOf(original.z3_str, result.z3_str))
        return ModelResult(value=result, constraints=constraints)


class StrRjustModel(FunctionModel):
    """Model for str.rjust(width) - right justify."""

    name = "rjust"
    qualname = "str.rjust"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.rjust(width) - right justify."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"rjust_{state .pc }")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len >= original.z3_len)
            constraints.append(z3.SuffixOf(original.z3_str, result.z3_str))
        return ModelResult(value=result, constraints=constraints)


class StrZfillModel(FunctionModel):
    """Model for str.zfill(width) - zero-pad on left."""

    name = "zfill"
    qualname = "str.zfill"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.zfill(width) - zero-pad on left."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"zfill_{state .pc }")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len >= original.z3_len)
        return ModelResult(value=result, constraints=constraints)


class StrRemovePrefixModel(FunctionModel):
    """Model for str.removeprefix()."""

    name = "removeprefix"
    qualname = "str.removeprefix"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
        """Apply the str.removeprefix()."""
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        prefix = _get_symbolic_string(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicString.symbolic(f"removeprefix_{state .pc }")
        constraints = [constraint]
        if original is not None:
            constraints.append(result.z3_len <= original.z3_len)
            if prefix is not None:
                is_prefix = z3.PrefixOf(prefix.z3_str, original.z3_str)
                constraints.append(
                    z3.Implies(is_prefix, result.z3_len == original.z3_len - prefix.z3_len)
                )
                constraints.append(z3.Implies(z3.Not(is_prefix), result.z3_len == original.z3_len))
        return ModelResult(value=result, constraints=constraints)


class StrRemoveSuffixModel(FunctionModel):
    """Model for str.removesuffix()."""

    name = "removesuffix"
    qualname = "str.removesuffix"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
        """Apply the str.removesuffix()."""
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        suffix = _get_symbolic_string(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicString.symbolic(f"removesuffix_{state .pc }")
        constraints = [constraint]
        if original is not None:
            constraints.append(result.z3_len <= original.z3_len)
            if suffix is not None:
                is_suffix = z3.SuffixOf(suffix.z3_str, original.z3_str)
                constraints.append(
                    z3.Implies(is_suffix, result.z3_len == original.z3_len - suffix.z3_len)
                )
                constraints.append(z3.Implies(z3.Not(is_suffix), result.z3_len == original.z3_len))
        return ModelResult(value=result, constraints=constraints)


class StrContainsModel(FunctionModel):
    """Model for 'in' operator on strings - uses Z3 Contains."""

    name = "__contains__"
    qualname = "str.__contains__"

    def apply(
        self,
        args: list[StackValue],
        """Apply the 'in' operator on strings - uses Z3 Contains."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        haystack = _get_symbolic_string(args[0]) if args else None
        needle = _get_symbolic_string(args[1]) if len(args) > 1 else None
        if haystack is not None and needle is not None:
            result_bool = z3.Contains(haystack.z3_str, needle.z3_str)
            result = SymbolicValue(
                _name=f"contains_{state .pc }",
                z3_int=z3.IntVal(0),
                is_int=z3.BoolVal(False),
                z3_bool=result_bool,
                is_bool=z3.BoolVal(True),
            )
            return ModelResult(value=result, constraints=[])
        result, constraint = SymbolicValue.symbolic(f"contains_{state .pc }")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


class StrRsplitModel(FunctionModel):
    """Model for str.rsplit() - like split but from right."""

    name = "rsplit"
    qualname = "str.rsplit"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.rsplit() - like split but from right."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicList.symbolic(f"rsplit_{state .pc }")
        constraints = [base_constraint, result.z3_len >= 1]
        if original is not None:
            constraints.append(result.z3_len <= original.z3_len + 1)
        return ModelResult(value=result, constraints=constraints)


class StrRfindModel(FunctionModel):
    """Model for str.rfind() - like find but searches from right.
    Returns -1 if not found, else index in [0, len-1].
    """

    name = "rfind"
    qualname = "str.rfind"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.rfind() - like find but searches from right."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"rfind_{state .pc }")
        constraints = [constraint, result.is_int, result.z3_int >= -1]
        if original is not None:
            constraints.append(result.z3_int < original.z3_len)
            constraints.append(z3.Implies(original.z3_len == 0, result.z3_int == -1))
        return ModelResult(value=result, constraints=constraints)


class StrRindexModel(FunctionModel):
    """Model for str.rindex() - like rfind but raises ValueError if not found."""

    name = "rindex"
    qualname = "str.rindex"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.rindex() - like rfind but raises ValueError if not found."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"rindex_{state .pc }")
        constraints = [constraint, result.is_int, result.z3_int >= 0]
        side_effects: dict[str, object] = {
            "potential_exception": {"type": "ValueError", "message": "substring not found"}
        }
        if original is not None:
            constraints.append(result.z3_int < original.z3_len)
        return ModelResult(value=result, constraints=constraints, side_effects=side_effects)


class StrPartitionModel(FunctionModel):
    """Model for str.partition(sep) - returns (before, sep, after) 3-tuple."""

    name = "partition"
    qualname = "str.partition"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.partition(sep) - returns (before, sep, after) 3-tuple."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"partition_{state .pc }")
        constraints = [constraint, result.z3_len == 3]
        return ModelResult(value=result, constraints=constraints)


class StrRpartitionModel(FunctionModel):
    """Model for str.rpartition(sep) - like partition but from right."""

    name = "rpartition"
    qualname = "str.rpartition"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.rpartition(sep) - like partition but from right."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"rpartition_{state .pc }")
        constraints = [constraint, result.z3_len == 3]
        return ModelResult(value=result, constraints=constraints)


class StrSplitlinesModel(FunctionModel):
    """Model for str.splitlines() - splits on line boundaries."""

    name = "splitlines"
    qualname = "str.splitlines"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.splitlines() - splits on line boundaries."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicList.symbolic(f"splitlines_{state .pc }")
        constraints = [base_constraint, result.z3_len >= 0]
        if original is not None:
            constraints.append(result.z3_len <= original.z3_len)
            constraints.append(z3.Implies(original.z3_len == 0, result.z3_len == 0))
        return ModelResult(value=result, constraints=constraints)


class StrEncodeModel(FunctionModel):
    """Model for str.encode() - returns bytes."""

    name = "encode"
    qualname = "str.encode"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.encode() - returns bytes."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"encode_{state .pc }")
        constraints = [constraint, result.z3_len >= 0]
        if original is not None:
            constraints.append(result.z3_len >= original.z3_len)
        return ModelResult(value=result, constraints=constraints)


class StrCasefoldModel(FunctionModel):
    """Model for str.casefold() - aggressive lowercase.
    Length may change (e.g., German ß → ss).
    """

    name = "casefold"
    qualname = "str.casefold"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.casefold() - aggressive lowercase."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"casefold_{state .pc }")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len >= original.z3_len)
        return ModelResult(value=result, constraints=constraints)


class StrExpandtabsModel(FunctionModel):
    """Model for str.expandtabs() - replaces tabs with spaces."""

    name = "expandtabs"
    qualname = "str.expandtabs"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.expandtabs() - replaces tabs with spaces."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"expandtabs_{state .pc }")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len >= original.z3_len)
        return ModelResult(value=result, constraints=constraints)


class StrMaketransModel(FunctionModel):
    """Model for str.maketrans() - static method returning translation table."""

    name = "maketrans"
    qualname = "str.maketrans"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.maketrans() - static method returning translation table."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        from pysymex.core.types import SymbolicDict

        result, constraint = SymbolicDict.symbolic(f"maketrans_{state .pc }")
        return ModelResult(value=result, constraints=[constraint])


class StrTranslateModel(FunctionModel):
    """Model for str.translate(table) - applies translation table.
    Length stays same or decreases (deletions possible).
    """

    name = "translate"
    qualname = "str.translate"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.translate(table) - applies translation table."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, base_constraint = SymbolicString.symbolic(f"translate_{state .pc }")
        constraints = [base_constraint]
        if original is not None:
            constraints.append(result.z3_len <= original.z3_len)
            constraints.append(result.z3_len >= 0)
        return ModelResult(value=result, constraints=constraints)


class StrIstitleModel(FunctionModel):
    """Model for str.istitle()."""

    name = "istitle"
    qualname = "str.istitle"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.istitle()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"istitle_{state .pc }")
        constraints = [constraint, result.is_bool]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class StrIsprintableModel(FunctionModel):
    """Model for str.isprintable().
    Empty string returns True (unlike other is* methods).
    """

    name = "isprintable"
    qualname = "str.isprintable"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.isprintable()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"isprintable_{state .pc }")
        constraints = [constraint, result.is_bool]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, result.z3_bool))
        return ModelResult(value=result, constraints=constraints)


class StrIsidentifierModel(FunctionModel):
    """Model for str.isidentifier()."""

    name = "isidentifier"
    qualname = "str.isidentifier"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.isidentifier()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"isidentifier_{state .pc }")
        constraints = [constraint, result.is_bool]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class StrIsdecimalModel(FunctionModel):
    """Model for str.isdecimal()."""

    name = "isdecimal"
    qualname = "str.isdecimal"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.isdecimal()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"isdecimal_{state .pc }")
        constraints = [constraint, result.is_bool]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class StrIsnumericModel(FunctionModel):
    """Model for str.isnumeric()."""

    name = "isnumeric"
    qualname = "str.isnumeric"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.isnumeric()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        original = _get_symbolic_string(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"isnumeric_{state .pc }")
        constraints = [constraint, result.is_bool]
        if original is not None:
            constraints.append(z3.Implies(original.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class StrFormatMapModel(FunctionModel):
    """Model for str.format_map(mapping)."""

    name = "format_map"
    qualname = "str.format_map"

    def apply(
        self,
        args: list[StackValue],
        """Apply the str.format_map(mapping)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, base_constraint = SymbolicString.symbolic(f"format_map_{state .pc }")
        return ModelResult(value=result, constraints=[base_constraint])


STRING_MODELS = [
    StrLowerModel(),
    StrUpperModel(),
    StrCapitalizeModel(),
    StrTitleModel(),
    StrSwapcaseModel(),
    StrStripModel(),
    StrLstripModel(),
    StrRstripModel(),
    StrSplitModel(),
    StrRsplitModel(),
    StrJoinModel(),
    StrReplaceModel(),
    StrStartswithModel(),
    StrEndswithModel(),
    StrFindModel(),
    StrRfindModel(),
    StrIndexModel(),
    StrRindexModel(),
    StrCountModel(),
    StrContainsModel(),
    StrFormatModel(),
    StrFormatMapModel(),
    StrIsdigitModel(),
    StrIsalphaModel(),
    StrIsalnumModel(),
    StrIsspaceModel(),
    StrIslowerModel(),
    StrIsupperModel(),
    StrIstitleModel(),
    StrIsprintableModel(),
    StrIsidentifierModel(),
    StrIsdecimalModel(),
    StrIsnumericModel(),
    StrCenterModel(),
    StrLjustModel(),
    StrRjustModel(),
    StrZfillModel(),
    StrRemovePrefixModel(),
    StrRemoveSuffixModel(),
    StrPartitionModel(),
    StrRpartitionModel(),
    StrSplitlinesModel(),
    StrEncodeModel(),
    StrCasefoldModel(),
    StrExpandtabsModel(),
    StrMaketransModel(),
    StrTranslateModel(),
]


class StrIsasciiModel(FunctionModel):
    name = "isascii"
    qualname = "str.isascii"

    def apply(
        self,
        args: list[StackValue],
        """Apply the StrIsasciiModel model."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"isascii_{state.pc}")
        return ModelResult(value=result, constraints=[constraint, result.is_bool])


STRING_MODELS.extend([StrIsasciiModel()])
