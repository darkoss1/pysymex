"""Collection opcodes (lists, tuples, dicts, sets)."""

from __future__ import annotations


import dis

from typing import TYPE_CHECKING, Any


import z3


from pysymex.analysis.detectors import Issue, IssueKind

from pysymex.core.addressing import next_address

from pysymex.core.solver import get_model, is_satisfiable

from pysymex.core.types import SymbolicDict, SymbolicList, SymbolicString, SymbolicValue

from pysymex.execution.dispatcher import OpcodeResult, opcode_handler

if TYPE_CHECKING:
    from pysymex.core.state import VMState

    from pysymex.execution.dispatcher import OpcodeDispatcher

BUILTIN_TYPE_NAMES: frozenset[str] = frozenset(
    {
        "list",
        "dict",
        "tuple",
        "set",
        "frozenset",
        "type",
        "bytes",
        "bytearray",
        "memoryview",
        "range",
        "slice",
        "property",
        "classmethod",
        "staticmethod",
        "super",
        "object",
        "str",
        "int",
        "float",
        "bool",
        "complex",
        "Optional",
        "Union",
        "Callable",
        "Literal",
        "Annotated",
        "ClassVar",
        "Final",
        "Type",
        "Generic",
        "Protocol",
        "ParamSpec",
        "TypeVar",
        "TypeAlias",
        "Sequence",
        "Mapping",
        "MutableMapping",
        "MutableSequence",
        "Iterable",
        "Iterator",
        "Generator",
        "Coroutine",
        "AsyncGenerator",
        "AsyncIterator",
        "Awaitable",
        "Collection",
        "Deque",
        "DefaultDict",
        "OrderedDict",
        "Counter",
        "ChainMap",
        "Pattern",
        "Match",
        "IO",
        "TextIO",
        "BinaryIO",
        "NamedTuple",
        "TypedDict",
        "Any",
    }
)


def is_type_subscription(container: object) -> bool:
    """Return True if *container* is a type object being subscripted for
    generic-alias syntax (e.g. ``list[int]``) rather than real indexing."""

    name: str = getattr(container, "_name", "") or getattr(container, "name", "") or ""

    if name.startswith("global_"):
        base = name[7:]

        if base in BUILTIN_TYPE_NAMES:
            return True

    if name.startswith("import_"):
        base = name[7:]

        if base in BUILTIN_TYPE_NAMES:
            return True

    model_name: str | None = getattr(container, "model_name", None)

    if model_name and model_name in BUILTIN_TYPE_NAMES:
        return True

    return False


@opcode_handler("BUILD_LIST")
def handle_build_list(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a list from stack items, preserving concrete values in Z3 Array."""

    count = int(instr.argval) if instr.argval else 0

    items: list[Any] = []

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
            val: Any = SymbolicValue.from_const(item) if not hasattr(item, "z3_int") else item

            z3_array = z3.Store(z3_array, i, val.z3_int if hasattr(val, "z3_int") else z3.IntVal(0))

    sym_list.z3_array = z3_array

    sym_list.z3_len = z3.IntVal(count)

    sym_list._concrete_items = items

    state.push(sym_list)

    state.add_constraint(constraint)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("BUILD_TUPLE")
def handle_build_tuple(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a tuple from stack items, preserving concrete values in Z3 Array."""

    count = int(instr.argval) if instr.argval else 0

    items: list[Any] = []

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
            val: Any = SymbolicValue.from_const(item) if not hasattr(item, "z3_int") else item

            z3_array = z3.Store(z3_array, i, val.z3_int if hasattr(val, "z3_int") else z3.IntVal(0))

    sym_list.z3_array = z3_array

    sym_list.z3_len = z3.IntVal(count)

    sym_list._concrete_items = items

    state.push(sym_list)

    state.add_constraint(constraint)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("BUILD_SET")
def handle_build_set(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Build a set from stack items."""

    count = int(instr.argval) if instr.argval else 0

    for _ in range(count):
        if state.stack:
            state.pop()

    sym_val, constraint = SymbolicValue.symbolic(f"set_{state.pc}")

    state.push(sym_val)

    state.add_constraint(constraint)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("BUILD_MAP")
def handle_build_map(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Build a dict from stack items."""

    count = int(instr.argval) if instr.argval else 0

    items: list[tuple[Any, Any]] = []

    for _ in range(count):
        if state.stack and len(state.stack) >= 2:
            val = state.pop()

            key = state.pop()

            items.append((key, val))

    items.reverse()

    sym_dict, constraint = SymbolicDict.symbolic(f"dict_{state.pc}")

    for key, val in items:
        if isinstance(key, SymbolicString):
            s_val = val if isinstance(val, SymbolicValue) else SymbolicValue.from_const(val)

            new_array = z3.Store(sym_dict.z3_array, key.z3_str, s_val.z3_int)

            sym_dict.z3_array = new_array

            new_keys = z3.Concat(sym_dict.known_keys, z3.Unit(key.z3_str))

            sym_dict.known_keys = new_keys

    sym_dict.z3_len = z3.IntVal(count)

    state.push(sym_dict)

    state.add_constraint(constraint)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("BUILD_CONST_KEY_MAP")
def handle_build_const_key_map(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a dict with constant keys, preserving key-value pairs."""

    count = int(instr.argval) if instr.argval else 0

    keys_tuple = state.pop() if state.stack else None

    values: list[Any] = []

    for _ in range(count):
        if state.stack:
            values.insert(0, state.pop())

    sym_dict, constraint = SymbolicDict.symbolic(f"dict_{state.pc}")

    concrete_keys: list[Any] | None = (
        getattr(keys_tuple, "_concrete_items", None) if keys_tuple else None
    )

    if concrete_keys and len(concrete_keys) == len(values):
        for key, val in zip(concrete_keys, values, strict=False):
            if isinstance(key, SymbolicString):
                s_val: Any = (
                    val if isinstance(val, SymbolicValue) else SymbolicValue.from_const(val)
                )

                sym_dict.z3_array = z3.Store(sym_dict.z3_array, key.z3_str, s_val.z3_int)

                sym_dict.known_keys = z3.Concat(sym_dict.known_keys, z3.Unit(key.z3_str))

            elif isinstance(key, str):
                str_key = SymbolicString.from_const(key)

                s_val = val if isinstance(val, SymbolicValue) else SymbolicValue.from_const(val)

                sym_dict.z3_array = z3.Store(sym_dict.z3_array, str_key.z3_str, s_val.z3_int)

                sym_dict.known_keys = z3.Concat(sym_dict.known_keys, z3.Unit(str_key.z3_str))

    sym_dict.z3_len = z3.IntVal(count)

    state.push(sym_dict)

    state.add_constraint(constraint)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("BUILD_STRING")
def handle_build_string(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a string from stack items (f-string)."""

    count = int(instr.argval) if instr.argval else 0

    for _ in range(count):
        if state.stack:
            state.pop()

    sym_str, constraint = SymbolicString.symbolic(f"fstring_{state.pc}")

    state.push(sym_str)

    state.add_constraint(constraint)

    state.pc += 1

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

    state.push(sym_val)

    state.add_constraint(constraint)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("LIST_EXTEND", "SET_UPDATE", "DICT_UPDATE", "DICT_MERGE")
def handle_collection_extend(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Extend a collection with another."""

    if state.stack:
        state.pop()

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("LIST_APPEND")
def handle_list_append(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Append to a list (used in list comprehensions)."""

    if state.stack:
        state.pop()

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("SET_ADD")
def handle_set_add(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Add to a set (used in set comprehensions)."""

    if state.stack:
        state.pop()

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("MAP_ADD")
def handle_map_add(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Add to a dict (used in dict comprehensions)."""

    if state.stack:
        state.pop()

    if state.stack:
        state.pop()

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("BINARY_SUBSCR")
def handle_binary_subscr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Subscript operation (obj[key])."""

    index = state.pop()

    container = state.pop()

    if is_type_subscription(container):
        result, constraint = SymbolicValue.symbolic(f"generic_{state.pc}")

        state.add_constraint(constraint)

        state.push(result)

        state.pc += 1

        return OpcodeResult.continue_with(state)

    issues: list[Issue] = []

    if isinstance(container, SymbolicList) and isinstance(index, SymbolicValue):
        oob_check = [
            *state.path_constraints,
            index.is_int,
            z3.Or(
                index.z3_int < -container.z3_len,
                index.z3_int >= container.z3_len,
            ),
        ]

        if is_satisfiable(oob_check):
            issues.append(
                Issue(
                    kind=IssueKind.INDEX_ERROR,
                    message=f"Possible index out of bounds: {container.name}[{index.name}]",
                    constraints=list(oob_check),
                    model=get_model(oob_check),
                    pc=state.pc,
                )
            )

        state.add_constraint(
            z3.And(index.z3_int >= -container.z3_len, index.z3_int < container.z3_len)
        )

        result = container[index]

    elif isinstance(container, SymbolicString) and isinstance(index, SymbolicValue):
        oob_check = [
            *state.path_constraints,
            index.is_int,
            z3.Or(
                index.z3_int < -container.z3_len,
                index.z3_int >= container.z3_len,
            ),
        ]

        if is_satisfiable(oob_check):
            issues.append(
                Issue(
                    kind=IssueKind.INDEX_ERROR,
                    message=f"Possible string index out of bounds: {container.name}[{index.name}]",
                    constraints=list(oob_check),
                    model=get_model(oob_check),
                    pc=state.pc,
                )
            )

        state.add_constraint(
            z3.And(index.z3_int >= -container.z3_len, index.z3_int < container.z3_len)
        )

        result = container[index]

    elif isinstance(container, SymbolicDict) and isinstance(index, SymbolicString):
        result = container[index]

    else:
        result, constraint = SymbolicValue.symbolic(f"subscr_{state.pc}")

        state.add_constraint(constraint)

    state.push(result)

    state.pc += 1

    if issues:
        return OpcodeResult(new_states=[state], issues=issues)

    return OpcodeResult.continue_with(state)


@opcode_handler("STORE_SUBSCR")
def handle_store_subscr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store subscript (obj[key] = value)."""

    state.pop()

    state.pop()

    state.pop()

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("DELETE_SUBSCR")
def handle_delete_subscr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete subscript (del obj[key])."""

    state.pop()

    state.pop()

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("BINARY_SLICE")
def handle_binary_slice(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Slice operation (obj[start:stop])."""

    state.pop()

    state.pop()

    container = state.pop()

    if isinstance(container, SymbolicList):
        result_len = z3.Int(f"slice_len_{state.pc}")

        result, constraint = SymbolicList.symbolic(f"slice_{state.pc}")

        result.z3_len = result_len

        state.add_constraint(constraint)

        state.add_constraint(result_len >= 0)

        state.push(result)

    elif isinstance(container, SymbolicString):
        result, constraint = SymbolicString.symbolic(f"str_slice_{state.pc}")

        state.add_constraint(constraint)

        state.push(result)

    else:
        result, constraint = SymbolicValue.symbolic(f"slice_{state.pc}")

        state.add_constraint(constraint)

        state.push(result)

    state.pc += 1

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

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("UNPACK_SEQUENCE")
def handle_unpack_sequence(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Unpack a sequence into individual values."""

    count = int(instr.argval) if instr.argval else 0

    if state.stack:
        state.pop()

    for i in range(count):
        val, constraint = SymbolicValue.symbolic(f"unpack_{state.pc}_{i}")

        state.push(val)

        state.add_constraint(constraint)

    state.pc += 1

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

        state.push(val)

        state.add_constraint(constraint)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("FORMAT_VALUE")
def handle_format_value(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Format a value for f-strings."""

    flags = int(instr.argval) if instr.argval else 0

    if flags & 0x04:
        if state.stack:
            state.pop()

    if state.stack:
        state.pop()

    sym_str, constraint = SymbolicString.symbolic(f"formatted_{state.pc}")

    state.push(sym_str)

    state.add_constraint(constraint)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("CONVERT_VALUE")
def handle_convert_value(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Convert value for f-string (Python 3.13+)."""

    if state.stack:
        state.pop()

    sym_str, constraint = SymbolicString.symbolic(f"converted_{state.pc}")

    state.push(sym_str)

    state.add_constraint(constraint)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("FORMAT_SIMPLE")
def handle_format_simple(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Simple format (Python 3.13+)."""

    if state.stack:
        state.pop()

    sym_str, constraint = SymbolicString.symbolic(f"format_simple_{state.pc}")

    state.push(sym_str)

    state.add_constraint(constraint)

    state.pc += 1

    return OpcodeResult.continue_with(state)


@opcode_handler("FORMAT_WITH_SPEC")
def handle_format_with_spec(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Format with spec (Python 3.13+)."""

    if state.stack:
        state.pop()

    if state.stack:
        state.pop()

    sym_str, constraint = SymbolicString.symbolic(f"format_spec_{state.pc}")

    state.push(sym_str)

    state.add_constraint(constraint)

    state.pc += 1

    return OpcodeResult.continue_with(state)
