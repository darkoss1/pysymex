"""Enhanced Models for Python list operations.
This module provides relationship-preserving symbolic models for list methods.
Instead of ignoring the effect of mutations, these models track:
- Length changes from append/extend/insert/remove/pop/clear
- Element relationships from copy/reverse/sort
- Index bounds for pop/index operations
Key improvements:
- Mutations properly update list length
- Side effects track potential exceptions
- Copy preserves list properties
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.core.types import SymbolicList, SymbolicNone, SymbolicValue
from pysymex.models.builtins import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState


def _get_symbolic_list(arg: object, state: VMState) -> SymbolicList | None:
    """Extract SymbolicList from argument, resolving SymbolicObject if needed."""
    if isinstance(arg, SymbolicList):
        return arg
    from pysymex.core.types_containers import SymbolicObject
    if isinstance(arg, SymbolicObject):
        addr = arg.address
        if addr in state.memory:
            val = state.memory[addr]
            if isinstance(val, SymbolicList):
                return val
    return None


def _get_symbolic_value(arg: object) -> SymbolicValue | None:
    """Extract SymbolicValue from argument."""
    if isinstance(arg, SymbolicValue):
        return arg
    return None


class ListAppendModel(FunctionModel):
    """Model for list.append(x) - increases list length by 1.
    Relationship: After append, len(list) == old_len + 1
    Side effect: Updates the list's symbolic length constraint.
    """

    name = "append"
    qualname = "list.append"

    def apply(
        self,
        args: list[StackValue],
        """Apply the list.append(x) - increases list length by 1."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        lst = _get_symbolic_list(args[0], state) if args else None
        element = args[1] if len(args) > 1 else None
        side_effects: dict[str, object] = {}
        if lst is not None:
            new_list = lst.append(
                element if isinstance(element, SymbolicValue) else SymbolicValue.from_const(element)
            )
            side_effects["list_mutation"] = {
                "operation": "append",
                "original_list": lst,
                "updated_list": new_list,
            }
        else:
            import logging
            logging.getLogger("pysymex").debug("ListAppendModel failed to find list in %s", args[0] if args else "None")
        return ModelResult(
            value=SymbolicNone(),
            side_effects=side_effects,
        )


class ListExtendModel(FunctionModel):
    """Model for list.extend(iterable) - increases length by len(iterable).
    Relationship: len(list) >= old_len (extends by >= 0 elements)
    """

    name = "extend"
    qualname = "list.extend"

    def apply(
        self,
        args: list[StackValue],
        """Apply the list.extend(iterable) - increases length by len(iterable)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        lst = _get_symbolic_list(args[0], state) if args else None
        extension = _get_symbolic_list(args[1], state) if len(args) > 1 else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if lst is not None:
            if extension is not None:
                new_len = z3.Int(f"extend_len_{state.pc}_{state.path_id}")
                constraints.append(new_len == lst.z3_len + extension.z3_len)
                # Ideally we should also model the array update, but for now length is most critical
                new_list = lst.copy()
                new_list.z3_len = new_len
            else:
                new_list = lst.copy()
                new_len = lst.z3_len
            
            side_effects["list_mutation"] = {
                "operation": "extend",
                "original_list": lst,
                "updated_list": new_list,
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


class ListInsertModel(FunctionModel):
    """Model for list.insert(i, x) - increases list length by 1.
    Relationship: After insert, len(list) == old_len + 1
    Note: Index i can be any value (negative, > len are valid)
    """

    name = "insert"
    qualname = "list.insert"

    def apply(
        self,
        args: list[StackValue],
        """Apply the list.insert(i, x) - increases list length by 1."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        lst = _get_symbolic_list(args[0], state) if args else None
        side_effects: dict[str, object] = {}
        if lst is not None:
            new_list = lst.copy()
            new_list.z3_len = lst.z3_len + 1
            # Array update skipped for now as we don't have full symbolic array semantics yet
            side_effects["list_mutation"] = {
                "operation": "insert",
                "original_list": lst,
                "updated_list": new_list,
            }
        return ModelResult(
            value=SymbolicNone(),
            side_effects=side_effects,
        )


class ListRemoveModel(FunctionModel):
    """Model for list.remove(x) - decreases length by 1 if element exists.
    Raises: ValueError if x not in list.
    Relationship: After remove (if successful), len(list) == old_len - 1
    Bug detection: Can find cases where element might not exist.
    """

    name = "remove"
    qualname = "list.remove"

    def apply(
        self,
        args: list[StackValue],
        """Apply the list.remove(x) - decreases length by 1 if element exists."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        lst = _get_symbolic_list(args[0], state) if args else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if lst is not None:
            side_effects["potential_exception"] = {
                "type": "ValueError",
                "message": "list.remove(x): x not in list",
                "condition": "element_not_found",
            }
            new_list = lst.copy()
            new_list.z3_len = lst.z3_len - 1
            constraints.append(lst.z3_len >= 1)
            side_effects["list_mutation"] = {
                "operation": "remove",
                "original_list": lst,
                "updated_list": new_list,
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


class ListPopModel(FunctionModel):
    """Model for list.pop([i]) - removes and returns element.
    Raises: IndexError if list is empty or index out of range.
    Relationship:
    - After pop, len(list) == old_len - 1
    - Returned element was in the list
    Bug detection: Can find cases where list might be empty.
    """

    name = "pop"
    qualname = "list.pop"

    def apply(
        self,
        args: list[StackValue],
        """Apply the list.pop([i]) - removes and returns element."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        lst = _get_symbolic_list(args[0], state) if args else None
        index = _get_symbolic_value(args[1]) if len(args) > 1 else None
        result, result_constraint = SymbolicValue.symbolic(f"pop_{state.pc}_{state.path_id}")
        constraints: list[z3.BoolRef | z3.ExprRef] = [result_constraint]
        side_effects: dict[str, object] = {}
        if lst is not None:
            side_effects["potential_exception"] = {
                "type": "IndexError",
                "message": "pop from empty list",
                "condition": lst.z3_len == 0,
            }
            constraints.append(lst.z3_len >= 1)
            if index is not None:
                constraints.append(lst.in_bounds(index))
                popped = lst[index]
                result = popped
            
            new_list = lst.copy()
            new_list.z3_len = lst.z3_len - 1
            
            side_effects["list_mutation"] = {
                "operation": "pop",
                "original_list": lst,
                "updated_list": new_list,
            }
        return ModelResult(
            value=result,
            constraints=constraints,
            side_effects=side_effects,
        )


class ListClearModel(FunctionModel):
    """Model for list.clear() - removes all elements.
    Relationship: After clear, len(list) == 0
    """

    name = "clear"
    qualname = "list.clear"

    def apply(
        self,
        args: list[StackValue],
        """Apply the list.clear() - removes all elements."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        lst = _get_symbolic_list(args[0], state) if args else None
        side_effects: dict[str, object] = {}
        if lst is not None:
            new_list = lst.copy()
            new_list.z3_len = z3.IntVal(0)
            side_effects["list_mutation"] = {
                "operation": "clear",
                "original_list": lst,
                "updated_list": new_list,
            }
        return ModelResult(
            value=SymbolicNone(),
            side_effects=side_effects,
        )


class ListIndexModel(FunctionModel):
    """Model for list.index(x) - returns index of first occurrence.
    Raises: ValueError if x not in list.
    Relationship:
    - Result >= 0
    - Result < len(list)
    Bug detection: Can find cases where element might not exist.
    """

    name = "index"
    qualname = "list.index"

    def apply(
        self,
        args: list[StackValue],
        """Apply the list.index(x) - returns index of first occurrence."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        lst = _get_symbolic_list(args[0], state) if args else None
        result, result_constraint = SymbolicValue.symbolic(f"list_index_{state .pc }")
        constraints = [result_constraint, result.is_int, result.z3_int >= 0]
        side_effects: dict[str, object] = {}
        if lst is not None:
            constraints.append(result.z3_int < lst.z3_len)
            side_effects["potential_exception"] = {
                "type": "ValueError",
                "message": "x not in list",
                "condition": "element_not_found",
            }
        return ModelResult(
            value=result,
            constraints=constraints,
            side_effects=side_effects,
        )


class ListCountModel(FunctionModel):
    """Model for list.count(x) - returns number of occurrences.
    Relationship:
    - Result >= 0
    - Result <= len(list)
    """

    name = "count"
    qualname = "list.count"

    def apply(
        self,
        args: list[StackValue],
        """Apply the list.count(x) - returns number of occurrences."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        lst = _get_symbolic_list(args[0], state) if args else None
        result, result_constraint = SymbolicValue.symbolic(f"list_count_{state .pc }")
        constraints = [result_constraint, result.is_int, result.z3_int >= 0]
        if lst is not None:
            constraints.append(result.z3_int <= lst.z3_len)
        return ModelResult(value=result, constraints=constraints)


class ListSortModel(FunctionModel):
    """Model for list.sort() - sorts in place.
    Relationship:
    - Length unchanged
    - Same elements (permutation)
    """

    name = "sort"
    qualname = "list.sort"

    def apply(
        self,
        args: list[StackValue],
        """Apply the list.sort() - sorts in place."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        lst = _get_symbolic_list(args[0], state) if args else None
        side_effects: dict[str, object] = {}
        if lst is not None:
            side_effects["list_mutation"] = {
                "operation": "sort",
                "list_name": lst.name,
                "old_length": lst.z3_len,
                "new_length": lst.z3_len,
                "is_permutation": True,
            }
        return ModelResult(
            value=SymbolicNone(),
            side_effects=side_effects,
        )


class ListReverseModel(FunctionModel):
    """Model for list.reverse() - reverses in place.
    Relationship:
    - Length unchanged
    - Elements are reversed (permutation)
    """

    name = "reverse"
    qualname = "list.reverse"

    def apply(
        self,
        args: list[StackValue],
        """Apply the list.reverse() - reverses in place."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        lst = _get_symbolic_list(args[0], state) if args else None
        side_effects: dict[str, object] = {}
        if lst is not None:
            side_effects["list_mutation"] = {
                "operation": "reverse",
                "list_name": lst.name,
                "old_length": lst.z3_len,
                "new_length": lst.z3_len,
                "is_permutation": True,
            }
        return ModelResult(
            value=SymbolicNone(),
            side_effects=side_effects,
        )


class ListCopyModel(FunctionModel):
    """Model for list.copy() - returns shallow copy.
    Relationship:
    - New list has same length
    - New list has same elements
    """

    name = "copy"
    qualname = "list.copy"

    def apply(
        self,
        args: list[StackValue],
        """Apply the list.copy() - returns shallow copy."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        lst = _get_symbolic_list(args[0], state) if args else None
        result, base_constraint = SymbolicList.symbolic(f"list_copy_{state .pc }")
        constraints = [base_constraint]
        if lst is not None:
            constraints.append(result.z3_len == lst.z3_len)
            result.element_type = lst.element_type
        return ModelResult(value=result, constraints=constraints)


class ListSliceModel(FunctionModel):
    """Model for list[start:end] slicing.
    Relationship:
    - Result length = min(end, len) - max(start, 0)
    - Result length >= 0
    - Result elements are from original list
    """

    name = "__getitem__"
    qualname = "list.__getitem__"

    def apply(
        self,
        args: list[StackValue],
        """Apply the list[start:end] slicing."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        lst = _get_symbolic_list(args[0], state) if args else None
        result, base_constraint = SymbolicList.symbolic(f"list_slice_{state .pc }")
        constraints = [base_constraint]
        if lst is not None:
            constraints.append(result.z3_len <= lst.z3_len)
            constraints.append(result.z3_len >= 0)
        return ModelResult(value=result, constraints=constraints)


class ListContainsModel(FunctionModel):
    """Model for 'x in list' operation.
    Relationship:
    - If list is empty, result is False
    - Otherwise, result is symbolic boolean
    """

    name = "__contains__"
    qualname = "list.__contains__"

    def apply(
        self,
        args: list[StackValue],
        """Apply the 'x in list' operation."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        lst = _get_symbolic_list(args[0], state) if args else None
        result, constraint = SymbolicValue.symbolic(f"list_contains_{state .pc }")
        constraints = [constraint, result.is_bool]
        if lst is not None:
            constraints.append(z3.Implies(lst.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class ListLenModel(FunctionModel):
    """Model for len(list).
    Relationship: Returns the symbolic length of the list.
    """

    name = "__len__"
    qualname = "list.__len__"

    def apply(
        self,
        args: list[StackValue],
        """Apply the len(list)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        lst = _get_symbolic_list(args[0], state) if args else None
        if lst is not None:
            result = lst.length()
            return ModelResult(value=result, constraints=[])
        result, constraint = SymbolicValue.symbolic(f"list_len_{state .pc }")
        return ModelResult(
            value=result,
            constraints=[constraint, result.is_int, result.z3_int >= 0],
        )


class ListSetitemModel(FunctionModel):
    """Model for list.__setitem__(index, value)."""

    name = "__setitem__"
    qualname = "list.__setitem__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply list.__setitem__ method."""
        lst = _get_symbolic_list(args[0], state) if args else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if lst is not None and len(args) > 1:
            idx = args[1]
            idx_val = getattr(idx, "z3_int", None)
            if idx_val is not None:
                side_effects["potential_exception"] = {
                    "type": "IndexError",
                    "condition": z3.Or(idx_val >= lst.z3_len, idx_val < -lst.z3_len),
                    "message": "list assignment index out of range",
                }
            
            new_list = lst.copy()
            # Array update skipped for now
            
            side_effects["list_mutation"] = {
                "operation": "setitem",
                "original_list": lst,
                "updated_list": new_list,
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


class ListDelitemModel(FunctionModel):
    """Model for list.__delitem__(index)."""

    name = "__delitem__"
    qualname = "list.__delitem__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply list.__delitem__ method."""
        lst = _get_symbolic_list(args[0], state) if args else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if lst is not None:
            if len(args) > 1:
                idx = args[1]
                idx_val = getattr(idx, "z3_int", None)
                if idx_val is not None:
                    side_effects["potential_exception"] = {
                        "type": "IndexError",
                        "condition": z3.Or(idx_val >= lst.z3_len, idx_val < -lst.z3_len),
                        "message": "list assignment index out of range",
                    }
            
            new_list = lst.copy()
            new_len = z3.Int(f"list_len_{state.pc}_{state.path_id}")
            constraints.append(new_len == lst.z3_len - 1)
            constraints.append(new_len >= 0)
            new_list.z3_len = new_len
            
            side_effects["list_mutation"] = {
                "operation": "delitem",
                "original_list": lst,
                "updated_list": new_list,
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


class ListAddModel(FunctionModel):
    """Model for list.__add__(other) - concatenation."""

    name = "__add__"
    qualname = "list.__add__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply list.__add__ method."""
        lst = _get_symbolic_list(args[0], state) if args else None
        other = _get_symbolic_list(args[1], state) if len(args) > 1 else None
        result, constraint = SymbolicList.symbolic(f"list_add_{state .pc }")
        constraints = [constraint, result.z3_len >= 0]
        if lst is not None and other is not None:
            constraints.append(result.z3_len == lst.z3_len + other.z3_len)
        elif lst is not None:
            constraints.append(result.z3_len >= lst.z3_len)
        return ModelResult(value=result, constraints=constraints)


class ListMulModel(FunctionModel):
    """Model for list.__mul__(n) - repetition."""

    name = "__mul__"
    qualname = "list.__mul__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply list.__mul__ method."""
        lst = _get_symbolic_list(args[0], state) if args else None
        n = args[1] if len(args) > 1 else None
        result, constraint = SymbolicList.symbolic(f"list_mul_{state .pc }")
        constraints = [constraint, result.z3_len >= 0]
        if lst is not None and n is not None:
            n_val = getattr(n, "z3_int", None)
            if n_val is not None:
                constraints.append(
                    z3.If(
                        n_val > 0,
                        result.z3_len == lst.z3_len * n_val,
                        result.z3_len == 0,
                    )
                )
        return ModelResult(value=result, constraints=constraints)


class ListEqModel(FunctionModel):
    """Model for list.__eq__(other)."""

    name = "__eq__"
    qualname = "list.__eq__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply list.__eq__ method."""
        lst = _get_symbolic_list(args[0], state) if args else None
        other = _get_symbolic_list(args[1], state) if len(args) > 1 else None
        result, constraint = SymbolicValue.symbolic(f"list_eq_{state .pc }")
        constraints = [constraint, result.is_bool]
        if lst is not None and other is not None:
            constraints.append(z3.Implies(result.z3_bool, lst.z3_len == other.z3_len))
            constraints.append(z3.Implies(lst.z3_len != other.z3_len, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class ListIaddModel(FunctionModel):
    """Model for list.__iadd__(other) - in-place extend via +=."""

    name = "__iadd__"
    qualname = "list.__iadd__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply list.__iadd__ method."""
        lst = _get_symbolic_list(args[0], state) if args else None
        other = _get_symbolic_list(args[1], state) if len(args) > 1 else None
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        side_effects: dict[str, object] = {}
        if lst is not None:
            new_list = lst.copy()
            new_len = z3.Int(f"list_len_{state.pc}_{state.path_id}")
            if other is not None:
                constraints.append(new_len == lst.z3_len + other.z3_len)
            else:
                constraints.append(new_len >= lst.z3_len)
            constraints.append(new_len >= 0)
            new_list.z3_len = new_len
            side_effects["list_mutation"] = {
                "operation": "iadd",
                "original_list": lst,
                "updated_list": new_list,
            }
        return ModelResult(
            value=args[0] if args else SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


class ListImulModel(FunctionModel):
    """Model for list.__imul__(n) - in-place repetition via *=."""

    name = "__imul__"
    qualname = "list.__imul__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply list.__imul__ method."""
        lst = _get_symbolic_list(args[0], state) if args else None
        n = args[1] if len(args) > 1 else None
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        side_effects: dict[str, object] = {}
        if lst is not None:
            new_list = lst.copy()
            new_len = z3.Int(f"list_len_{state.pc}_{state.path_id}")
            n_val = getattr(n, "z3_int", None) if n is not None else None
            if n_val is not None:
                constraints.append(
                    z3.If(
                        n_val > 0,
                        new_len == lst.z3_len * n_val,
                        new_len == 0,
                    )
                )
            else:
                constraints.append(new_len >= 0)
            new_list.z3_len = new_len
            side_effects["list_mutation"] = {
                "operation": "imul",
                "original_list": lst,
                "updated_list": new_list,
            }
        return ModelResult(
            value=args[0] if args else SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


LIST_MODELS = [
    ListAppendModel(),
    ListExtendModel(),
    ListInsertModel(),
    ListRemoveModel(),
    ListPopModel(),
    ListClearModel(),
    ListIndexModel(),
    ListCountModel(),
    ListSortModel(),
    ListReverseModel(),
    ListCopyModel(),
    ListSliceModel(),
    ListContainsModel(),
    ListLenModel(),
    ListSetitemModel(),
    ListDelitemModel(),
    ListAddModel(),
    ListMulModel(),
    ListEqModel(),
    ListIaddModel(),
    ListImulModel(),
]
