"""Collection opcodes (lists, tuples, dicts, sets)."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, cast

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.addressing import next_address
from pysymex.core.havoc import HavocValue
from pysymex.core.solver import get_model, is_satisfiable
from pysymex.core.type_checks import is_type_subscription
from pysymex.core.types import (
    Z3_FALSE,
    SymbolicNone,
    SymbolicValue,
    SymbolicString,
)
from pysymex.core.types_containers import (
    SymbolicDict,
    SymbolicList,
    SymbolicObject,
)
from pysymex.execution.dispatcher import OpcodeResult, opcode_handler

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher


@opcode_handler("BUILD_LIST")
def handle_build_list(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a list from stack items, preserving concrete values in Z3 Array."""
    count = int(instr.argval) if instr.argval else 0
    items: list[StackValue] = []
    for _ in range(count):
        if state.stack:
            items.insert(0, state.pop())
    sym_list, constraint = SymbolicList.symbolic(f"list_{state.pc}")
    z3_array = sym_list.z3_array
    for i, item in enumerate(items):
        if isinstance(item, SymbolicValue):
            z3_array = z3.Store(z3_array, i, item.z3_int)
        elif isinstance(item, (int, bool)):
            z3_array = z3.Store(z3_array, i, z3.IntVal(int(item)))
        elif isinstance(item, SymbolicList):
            z3_array = z3.Store(z3_array, i, z3.IntVal(next_address()))
        else:
            val: object = SymbolicValue.from_const(item) if not hasattr(item, "z3_int") else item
            z3_array = z3.Store(z3_array, i, val.z3_int if hasattr(val, "z3_int") else z3.IntVal(0))
    sym_list.z3_array = z3_array
    sym_list.z3_len = z3.IntVal(count)
    sym_list._concrete_items = items

    addr = next_address()
    state.memory[addr] = sym_list
    obj_handle = SymbolicObject(f"list_{addr}", addr, z3.IntVal(addr), {addr})

    state = state.push(obj_handle)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("BUILD_TUPLE")
def handle_build_tuple(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a tuple from stack items, preserving concrete values in Z3 Array."""
    count = int(instr.argval) if instr.argval else 0
    items: list[StackValue] = []
    for _ in range(count):
        if state.stack:
            items.insert(0, state.pop())
    sym_list, constraint = SymbolicList.symbolic(f"tuple_{state.pc}")
    z3_array = sym_list.z3_array
    for i, item in enumerate(items):
        if isinstance(item, SymbolicValue):
            z3_array = z3.Store(z3_array, i, item.z3_int)
        elif isinstance(item, (int, bool)):
            z3_array = z3.Store(z3_array, i, z3.IntVal(int(item)))
        else:
            val: object = SymbolicValue.from_const(item) if not hasattr(item, "z3_int") else item
            z3_array = z3.Store(z3_array, i, val.z3_int if hasattr(val, "z3_int") else z3.IntVal(0))
    sym_list.z3_array = z3_array
    sym_list.z3_len = z3.IntVal(count)
    sym_list._concrete_items = items
    state = state.push(sym_list)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("BUILD_SET")
def handle_build_set(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Build a set from stack items."""
    count = int(instr.argval) if instr.argval else 0
    for _ in range(count):
        if state.stack:
            state.pop()
    sym_val, constraint = SymbolicValue.symbolic(f"set_{state.pc}")
    state = state.push(sym_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("BUILD_MAP")
def handle_build_map(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Build a dict from stack items."""
    count = int(instr.argval) if instr.argval else 0
    items: list[tuple[object, object]] = []
    for _ in range(count):
        if state.stack and len(state.stack) >= 2:
            val = state.pop()
            key = state.pop()
            items.append((key, val))
    items.reverse()
    sym_dict, constraint = SymbolicDict.symbolic(f"dict_{state.pc}")
    sym_dict._concrete_items = {}
    for key, val in items:
        s_key = key if isinstance(key, SymbolicString) else SymbolicString.from_const(str(key))
        s_val = val if isinstance(val, SymbolicValue) else SymbolicValue.from_const(val)
        sym_dict = sym_dict.__setitem__(s_key, s_val)
    sym_dict.z3_len = z3.IntVal(count)

    state = state.push(sym_dict)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("BUILD_CONST_KEY_MAP")
def handle_build_const_key_map(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a dict with constant keys, preserving key-value pairs."""
    count = int(instr.argval) if instr.argval else 0
    
    keys_tuple = state.pop()
    
    values = []
    for _ in range(count):
        val = state.pop()
        values.append(val)
    values.reverse()

    sym_dict, constraint = SymbolicDict.symbolic(f"dict_{state.pc}")
    sym_dict._concrete_items = {}
    
    concrete_keys: list[object] | None = None
    if keys_tuple:
        if hasattr(keys_tuple, "_enhanced_object") and isinstance(keys_tuple._enhanced_object, (list, tuple)):
             concrete_keys = list(keys_tuple._enhanced_object)
        elif hasattr(keys_tuple, "_constant_value") and isinstance(keys_tuple._constant_value, (list, tuple)):
             concrete_keys = list(keys_tuple._constant_value)

    if concrete_keys and len(concrete_keys) == len(values):
        for key, val in zip(concrete_keys, values, strict=False):
            s_key = key if isinstance(key, SymbolicString) else SymbolicString.from_const(str(key))
            s_val = val if isinstance(val, SymbolicValue) else SymbolicValue.from_const(val)
            sym_dict = sym_dict.__setitem__(s_key, s_val)
    else:
        pass
    sym_dict.z3_len = z3.IntVal(count)

    state = state.push(sym_dict)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("BUILD_STRING")
def handle_build_string(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a string from stack items (f-string) with precise concatenation."""
    count = int(instr.argval) if instr.argval else 0
    items: list[object] = []
    for _ in range(count):
        if state.stack:
            items.insert(0, state.pop())

    if not items:
        state = state.push(SymbolicString.from_const(""))
        return OpcodeResult.continue_with(state.advance_pc())

    result_sym = None
    for item in items:
        if isinstance(item, SymbolicString):
            part = item
        elif isinstance(item, SymbolicValue):
            z3_expr = z3.If(
                item.is_int,
                item.z3_int,
                z3.If(item.is_bool, z3.If(item.z3_bool, z3.IntVal(1), z3.IntVal(0)), z3.IntVal(0)),
            )
            new_z3_str = z3.IntToStr(z3_expr)
            part = SymbolicString(
                _name=f"str({item.name})", _z3_str=new_z3_str, _z3_len=z3.Length(new_z3_str), taint_labels=item.taint_labels
            )
        else:
            part = SymbolicString.from_const(str(item))

        if result_sym is None:
            result_sym = part
        else:
            result_sym = result_sym + part

    state = state.push(result_sym)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("BUILD_SLICE")
def handle_build_slice(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a slice object."""
    argc = int(instr.argval) if instr.argval else 2
    for _ in range(argc):
        if state.stack:
            state.pop()
    sym_val, constraint = SymbolicValue.symbolic(f"slice_{state.pc}")
    state = state.push(sym_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("LIST_EXTEND")
def handle_list_extend(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Extend a list precisely, especially for constant sequences."""
    val = state.pop()
    index = int(instr.argval) if instr.argval is not None else 1
    container = state.peek(index - 1)

    if isinstance(container, SymbolicList):
        new_container = container.extend(val)
        state.stack[-index] = new_container

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("SET_UPDATE", "DICT_UPDATE", "DICT_MERGE")
def handle_collection_update(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Basic update for other collections."""
    val = state.pop()
    index = int(instr.argval) if instr.argval is not None else 1
    container = state.peek(index - 1)

    if instr.opname in ("DICT_UPDATE", "DICT_MERGE") and isinstance(container, SymbolicDict):
        new_container = container.update(val)
        state.stack[-index] = new_container
    elif instr.opname == "SET_UPDATE":
        # Support for SymbolicSet if added, or fallback
        if hasattr(container, "update"):
            new_container = container.update(val)
            state.stack[-index] = new_container

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)






@opcode_handler("LIST_APPEND")
def handle_list_append(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Append to a list (used in list comprehensions)."""
    val = state.pop()
    index = int(instr.argval) if instr.argval is not None else 1

    container = state.peek(index - 1)
    if isinstance(container, SymbolicList):
        s_item = val if hasattr(val, "z3_int") else SymbolicValue.from_const(val)
        new_list = container.append(cast("SymbolicValue", s_item))

        state.stack[-index] = new_list
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("SET_ADD")
def handle_set_add(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Add to a set (used in set comprehensions)."""
    state.pop()  # val

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("MAP_ADD")
def handle_map_add(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Add to a dict (used in dict comprehensions)."""
    val = state.pop()
    key = state.pop()
    index = int(instr.argval) if instr.argval is not None else 1
    container = state.peek(index - 1)
    if isinstance(container, SymbolicDict) and isinstance(key, SymbolicString):
        s_val = val if isinstance(val, SymbolicValue) else SymbolicValue.from_const(val)
        new_dict = container.__setitem__(key, s_val)
        state.stack[-index] = new_dict
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("BINARY_SUBSCR", "BINARY_SUBSCR_GETITEM")
def handle_binary_subscr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Subscript operation (obj[key])."""
    index = state.pop()
    container = state.pop()

    if isinstance(container, HavocValue):
        container_taint = getattr(container, "taint_labels", None)
        ret, tc = HavocValue.havoc(
            f"{getattr(container, 'name', 'havoc')}[{state.pc}]",
            taint_labels=container_taint,
        )
        state = state.push(ret)
        state = state.add_constraint(tc)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    if is_type_subscription(container):
        result, constraint = SymbolicValue.symbolic(f"generic_{state.pc}")
        state = state.add_constraint(constraint)
        state = state.push(result)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    issues: list[Issue] = []

    
    real_container = container
    if hasattr(container, "address"):
        real_container = state.memory.get(container.address, container)
    elif hasattr(container, "_enhanced_object") and container._enhanced_object is not None:
        eo = container._enhanced_object
        if hasattr(eo, "address"):
            real_container = state.memory.get(eo.address, eo)
        else:
            real_container = eo
    elif hasattr(container, "_constant_value") and container._constant_value is not None:
         real_container = container._constant_value

    if isinstance(real_container, (SymbolicList, SymbolicString)) and isinstance(
        index, SymbolicValue
    ):
        name = "index" if isinstance(real_container, SymbolicList) else "string index"
        oob_check = [
            *state.path_constraints,
            index.is_int,
            z3.Or(
                index.z3_int < -real_container.z3_len,
                index.z3_int >= real_container.z3_len,
            ),
        ]
        if is_satisfiable(oob_check):
            issues.append(
                Issue(
                    kind=IssueKind.INDEX_ERROR,
                    message=f"Possible {name} out of bounds: {real_container.name}[{index.name}]",
                    constraints=list(oob_check),
                    model=get_model(oob_check),
                    pc=state.pc,
                )
            )
        state = state.add_constraint(
            z3.And(index.z3_int >= -real_container.z3_len, index.z3_int < real_container.z3_len)
        )
        result = real_container[index]
    elif (isinstance(real_container, SymbolicDict) or (hasattr(real_container, 'z3_array') and hasattr(real_container, 'known_keys'))) and isinstance(index, (SymbolicString, SymbolicValue)):
        result, presence_check = real_container[index]
        
        # Check if KeyError is possible
        missing_check = list(state.path_constraints) + [z3.Not(presence_check)]
        if is_satisfiable(missing_check):
            issue = Issue(
                kind=IssueKind.KEY_ERROR,
                message=f"Possible KeyError: {index.name} not in {getattr(real_container, '_name', 'dict')}",
                constraints=list(missing_check),
                model=get_model(missing_check),
                pc=state.pc,
            )
            # IMPORTANT: Fork by copying BEFORE adding constraints to preserve independence
            state_continue = state.fork().add_constraint(presence_check)
            state_error = state.fork().add_constraint(z3.Not(presence_check))
            
            # The continuation state gets the result and moves forward
            state_continue = state_continue.push(result)
            state_continue = state_continue.advance_pc()
            
            return OpcodeResult.fork([state_continue, state_error], [None, issue])

        # If missing is UNSAT, key MUST be present
        state = state.add_constraint(presence_check)
        state = state.push(result)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    else:
        try:
            import collections.abc

            from pysymex.core.havoc import is_havoc

            if is_havoc(real_container):
                result, constraint = real_container[index]
                state = state.add_constraint(constraint)
            elif isinstance(
                real_container, (collections.abc.Sequence, collections.abc.Mapping, SymbolicValue)
            ):
                result, constraint = SymbolicValue.symbolic(f"subscr_{state.pc}")
                state = state.add_constraint(constraint)
            else:
                issue = Issue(
                    kind=IssueKind.TYPE_ERROR,
                    message=f"Object is not subscriptable: {type(real_container).__name__}",
                    constraints=list(state.path_constraints),
                    model=get_model(state.path_constraints),
                    pc=state.pc,
                )
                return OpcodeResult.error(issue, state)
        except ImportError:
            result, constraint = SymbolicValue.symbolic(f"subscr_{state.pc}")
            state = state.add_constraint(constraint)
    state = state.push(result)
    state = state.advance_pc()
    if issues:
        return OpcodeResult(new_states=[state], issues=issues)
    return OpcodeResult.continue_with(state)


@opcode_handler("STORE_SUBSCR")
def handle_store_subscr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store subscript (obj[key] = value) with mandatory error detection."""
    key = state.pop()
    container = state.pop()
    val = state.pop()
    issues: list[Issue] = []

    real_container = container
    container_addr = -1
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = state.memory.get(container_addr, container)

    if isinstance(real_container, (SymbolicList, SymbolicString)) and isinstance(
        key, SymbolicValue
    ):

        oob_check = [
            *state.path_constraints,
            key.is_int,
            z3.Or(key.z3_int < -real_container.z3_len, key.z3_int >= real_container.z3_len),
        ]
        if is_satisfiable(oob_check):
            issue = Issue(
                kind=IssueKind.INDEX_ERROR,
                message=f"Possible index out of bounds on store: {real_container.name}[{key.name}]",
                constraints=list(oob_check),
                model=get_model(oob_check),
                pc=state.pc,
            )

            if not is_satisfiable(
                [
                    *state.path_constraints,
                    z3.And(
                        key.is_int,
                        key.z3_int >= -real_container.z3_len,
                        key.z3_int < real_container.z3_len,
                    ),
                ]
            ):
                return OpcodeResult.error(issue, state)
            issues.append(issue)

        if isinstance(real_container, SymbolicList):

            if hasattr(real_container, "__setitem__"):

                new_container = real_container.__setitem__(key, val)
                if container_addr != -1:
                    state.memory[container_addr] = new_container
            else:
                return OpcodeResult.error(
                    Issue(
                        IssueKind.TYPE_ERROR,
                        f"Cannot store to {real_container.name}",
                        list(state.path_constraints),
                        get_model(state.path_constraints),
                        state.pc,
                    ),
                    state,
                )

    elif isinstance(real_container, SymbolicDict) and isinstance(key, SymbolicString):

        new_container = real_container.__setitem__(key, val)
        if container_addr != -1:
            state.memory[container_addr] = new_container

    elif real_container is None or (
        hasattr(real_container, "is_none")
        and is_satisfiable([*state.path_constraints, real_container.is_none])
    ):
        must_be_none = real_container is None or not is_satisfiable(
            [*state.path_constraints, z3.Not(getattr(real_container, "is_none", Z3_FALSE))]
        )
        is_unconstrained_var = hasattr(real_container, "is_none") and z3.is_const(real_container.is_none) and getattr(real_container, "is_none").decl().kind() == z3.Z3_OP_UNINTERPRETED
        
        if must_be_none or not is_unconstrained_var:
            issue = Issue(
                IssueKind.NULL_DEREFERENCE,
                "Store to None object",
                list(state.path_constraints),
                get_model(state.path_constraints),
                state.pc,
            )
            if must_be_none:
                return OpcodeResult.error(issue, state)
            issues.append(issue)

        if hasattr(real_container, "is_none"):
            state = state.add_constraint(z3.Not(real_container.is_none))

    state = state.advance_pc()
    if issues:
        return OpcodeResult(new_states=[state], issues=issues)
    return OpcodeResult.continue_with(state)


@opcode_handler("DELETE_SUBSCR")
def handle_delete_subscr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete subscript (del obj[key]) with error detection (KeyError / IndexError)."""
    key = state.pop()
    container = state.pop()
    issues: list[Issue] = []

    if isinstance(container, SymbolicDict) and isinstance(key, SymbolicString):
        exists_check = [*state.path_constraints, z3.Not(container.contains_key(key).z3_bool)]
        if is_satisfiable(exists_check):
            issue = Issue(
                kind=IssueKind.KEY_ERROR,
                message=f"Possible KeyError on delete: {key.name} in {container.name}",
                constraints=list(exists_check),
                model=get_model(exists_check),
                pc=state.pc,
            )

            if not is_satisfiable([*state.path_constraints, container.contains_key(key).z3_bool]):
                return OpcodeResult.error(issue, state)
            issues.append(issue)

    elif isinstance(container, SymbolicList) and isinstance(key, SymbolicValue):
        oob_check = [
            *state.path_constraints,
            key.is_int,
            z3.Or(key.z3_int < -container.z3_len, key.z3_int >= container.z3_len),
        ]
        if is_satisfiable(oob_check):
            issue = Issue(
                kind=IssueKind.INDEX_ERROR,
                message=f"Possible index out of bounds on delete: {container.name}[{key.name}]",
                constraints=list(oob_check),
                model=get_model(oob_check),
                pc=state.pc,
            )

            if not is_satisfiable(
                [
                    *state.path_constraints,
                    z3.And(
                        key.is_int, key.z3_int >= -container.z3_len, key.z3_int < container.z3_len
                    ),
                ]
            ):
                return OpcodeResult.error(issue, state)
            issues.append(issue)

    state = state.advance_pc()
    if issues:
        return OpcodeResult(new_states=[state], issues=issues)
    return OpcodeResult.continue_with(state)


@opcode_handler("BINARY_SLICE")
def handle_binary_slice(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Slice operation (obj[start:stop])."""
    stop = state.pop()
    start = state.pop()
    container = state.pop()

    if not isinstance(start, SymbolicValue):
        start = SymbolicValue.from_const(start)
    if not isinstance(stop, SymbolicValue):
        stop = SymbolicValue.from_const(stop)

    if isinstance(container, SymbolicNone):
        issue = Issue(
            kind=IssueKind.TYPE_ERROR,
            message="TypeError: 'NoneType' object is not subscriptable",
            constraints=list(state.path_constraints),
            model=get_model(state.path_constraints),
            pc=state.pc,
        )
        return OpcodeResult(new_states=[], issues=[issue], terminal=True)

    if isinstance(container, SymbolicString):
        length_val = stop.z3_int - start.z3_int
        real_start = z3.If(start.z3_int < 0, start.z3_int + container.z3_len, start.z3_int)
        result = container.substring(
            SymbolicValue(
                _name=f"start_{state.pc}",
                z3_int=real_start,
                is_int=z3.BoolVal(True),
                z3_bool=z3.BoolVal(False),
                is_bool=z3.BoolVal(False),
            ),
            SymbolicValue(
                _name=f"len_{state.pc}",
                z3_int=length_val,
                is_int=z3.BoolVal(True),
                z3_bool=z3.BoolVal(False),
                is_bool=z3.BoolVal(False),
            ),
        )
        state = state.push(result)
    elif isinstance(container, SymbolicList):
        result_len = z3.Int(f"slice_len_{state.pc}")
        result, constraint = SymbolicList.symbolic(f"slice_{state.pc}")
        result.z3_len = result_len
        state = state.add_constraint(constraint)
        state = state.add_constraint(result_len >= 0)
        state = state.push(result)
    else:
        result, constraint = SymbolicValue.symbolic(f"slice_{state.pc}")
        state = state.add_constraint(constraint)
        state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("STORE_SLICE")
def handle_store_slice(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store slice (obj[start:stop] = value)."""
    state.pop()
    state.pop()
    state.pop()
    state.pop()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("UNPACK_SEQUENCE")
def handle_unpack_sequence(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Unpack a sequence into individual values with length validation."""
    count = int(instr.argval) if instr.argval else 0
    container = state.pop() if state.stack else None

    issues = []
    if hasattr(container, "z3_len"):
        len_check = [*state.path_constraints, container.z3_len != count]
        if is_satisfiable(len_check):
            issue = Issue(
                kind=IssueKind.VALUE_ERROR,
                message=f"Possible ValueError: expected {count} items to unpack, got length {container.z3_len}",
                constraints=list(len_check),
                model=get_model(len_check),
                pc=state.pc,
            )

            if not is_satisfiable([*state.path_constraints, container.z3_len == count]):
                return OpcodeResult.error(issue, state)
            issues.append(issue)
        state = state.add_constraint(container.z3_len == count)
    elif container is None or (
        hasattr(container, "is_none")
        and is_satisfiable([*state.path_constraints, container.is_none])
    ):
        must_be_none = container is None or not is_satisfiable(
            [*state.path_constraints, z3.Not(getattr(container, "is_none", Z3_FALSE))]
        )
        
        is_unconstrained_var = hasattr(container, "is_none") and z3.is_const(container.is_none) and container.is_none.decl().kind() == z3.Z3_OP_UNINTERPRETED
        
        if must_be_none or not is_unconstrained_var:
            issue = Issue(
                IssueKind.NULL_DEREFERENCE,
                "Unpacking None",
                list(state.path_constraints),
                get_model(state.path_constraints),
                state.pc,
            )
            if must_be_none:
                return OpcodeResult.error(issue, state)
            issues.append(issue)
        
        # Assume it's actually not None on the continuation path to avoid cascading FPs
        if hasattr(container, "is_none"):
            state = state.add_constraint(z3.Not(container.is_none))

    for i in range(count):
        if isinstance(container, SymbolicList):
            val = container[SymbolicValue.from_const(i)]
        else:
            val, constraint = SymbolicValue.symbolic(f"unpack_{state.pc}_{i}")
            state = state.add_constraint(constraint)
        state = state.push(val)

    state = state.advance_pc()
    if issues:
        return OpcodeResult(new_states=[state], issues=issues)
    return OpcodeResult.continue_with(state)


@opcode_handler("UNPACK_EX")
def handle_unpack_ex(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Unpack with starred target."""
    if state.stack:
        state.pop()
    arg = int(instr.argval) if instr.argval else 0
    before = arg & 0xFF
    after = (arg >> 8) & 0xFF
    for i in range(before + 1 + after):
        val, constraint = SymbolicValue.symbolic(f"unpack_ex_{state.pc}_{i}")
        state = state.push(val)
        state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _format_value_symbolic(val: object, state: VMState) -> SymbolicString:
    """Helper to format a value symbolically."""
    if isinstance(val, SymbolicString):
        return val
    if isinstance(val, SymbolicValue):

        z3_expr = z3.If(
            val.is_int,
            val.z3_int,
            z3.If(val.is_bool, z3.If(val.z3_bool, z3.IntVal(1), z3.IntVal(0)), z3.IntVal(0)),
        )

        new_z3_str = z3.If(z3_expr < 0, z3.Concat("-", z3.IntToStr(-z3_expr)), z3.IntToStr(z3_expr))

        new_z3_str = z3.If(val.is_none, z3.StringVal("None"), new_z3_str)

        return SymbolicString(
            _name=f"str({val.name})", _z3_str=new_z3_str, _z3_len=z3.Length(new_z3_str), taint_labels=val.taint_labels
        )
    return SymbolicString.from_const(str(val))


@opcode_handler("FORMAT_VALUE")
def handle_format_value(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Format a value for f-strings precisely."""
    flags = int(instr.argval) if instr.argval else 0
    if flags & 0x04:
        if state.stack:
            state.pop()

    if not state.stack:
        sym_str, constraint = SymbolicString.symbolic(f"formatted_{state.pc}")
        state = state.push(sym_str)
        return OpcodeResult.continue_with(state.add_constraint(constraint).advance_pc())

    val = state.pop()
    result = _format_value_symbolic(val, state)
    state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("CONVERT_VALUE")
def handle_convert_value(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Convert value for f-string (Python 3.13+)."""
    if not state.stack:
        sym_str, constraint = SymbolicString.symbolic(f"converted_{state.pc}")
        return OpcodeResult.continue_with(
            state.push(sym_str).add_constraint(constraint).advance_pc()
        )

    val = state.pop()

    result = _format_value_symbolic(val, state)
    state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("FORMAT_SIMPLE")
def handle_format_simple(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Simple format (Python 3.13+)."""
    if not state.stack:
        sym_str, constraint = SymbolicString.symbolic(f"format_simple_{state.pc}")
        return OpcodeResult.continue_with(
            state.push(sym_str).add_constraint(constraint).advance_pc()
        )

    val = state.pop()
    result = _format_value_symbolic(val, state)
    state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("FORMAT_WITH_SPEC")
def handle_format_with_spec(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Format with spec (Python 3.13+)."""
    if len(state.stack) < 2:

        if state.stack:
            state.pop()
        sym_str, constraint = SymbolicString.symbolic(f"format_spec_{state.pc}")
        return OpcodeResult.continue_with(
            state.push(sym_str).add_constraint(constraint).advance_pc()
        )

    state.pop()  # spec
    val = state.pop()

    result = _format_value_symbolic(val, state)
    state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
