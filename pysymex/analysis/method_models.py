"""Pre-defined models for methods of common Python types."""

from __future__ import annotations

from .function_models import FunctionSummary, ParameterInfo
from .type_inference import PyType, TypeKind


class MethodModels:
    """Pre-defined models for methods of common types.
    
    **Architectural Role:**
    Providing logical summaries for all built-in methods (e.g., `list.append`, 
    `str.upper`) allows the engine to skip expensive bytecode exploration of
    the C-implemented standard library. 
    
    **Semantic Mapping:**
    Each model specifies:
    - **Purity**: Whether the method has side-effects.
    - **Readonly**: Whether it modifies internal state.
    - **Return Type**: The inferred type of the result (e.g., `PyType.str_type()`).
    - **Exceptions**: Documented sets of possible SMT-driven exceptions (e.g. `KeyError`).
    """

    _models: dict[tuple[TypeKind, str], FunctionSummary] = {}

    @classmethod
    def get(cls, type_kind: TypeKind, method_name: str) -> FunctionSummary | None:
        """Get the logical summary model for a specific method.
        
        Forces initialization of the registry on the first call. If no model
        exists, the engine typically falls back to a sound 'Top' approximation.
        """
        if not cls._models:
            cls._init_models()
        return cls._models.get((type_kind, method_name))

    @classmethod
    def _init_models(cls) -> None:
        """Initialize method models."""
        cls._add_str_methods()
        cls._add_list_methods()
        cls._add_dict_methods()
        cls._add_set_methods()

    @classmethod
    def _add_str_methods(cls) -> None:
        """Add string method models."""
        str_pure_str: list[tuple[str, list[ParameterInfo]]] = [
            ("upper", []),
            ("lower", []),
            ("capitalize", []),
            ("title", []),
            ("swapcase", []),
            ("casefold", []),
            ("strip", [ParameterInfo("chars", 0, has_default=True)]),
            ("lstrip", [ParameterInfo("chars", 0, has_default=True)]),
            ("rstrip", [ParameterInfo("chars", 0, has_default=True)]),
            ("center", [ParameterInfo("width", 0), ParameterInfo("fillchar", 1, has_default=True)]),
            ("ljust", [ParameterInfo("width", 0), ParameterInfo("fillchar", 1, has_default=True)]),
            ("rjust", [ParameterInfo("width", 0), ParameterInfo("fillchar", 1, has_default=True)]),
            ("zfill", [ParameterInfo("width", 0)]),
            (
                "replace",
                [
                    ParameterInfo("old", 0),
                    ParameterInfo("new", 1),
                    ParameterInfo("count", 2, has_default=True),
                ],
            ),
        ]
        for name, params in str_pure_str:
            cls._models[(TypeKind.STR, name)] = FunctionSummary(
                name=f"str.{name }",
                parameters=params,
                return_type=PyType.str_type(),
                is_pure=True,
                is_readonly=True,
            )
        cls._models[(TypeKind.STR, "split")] = FunctionSummary(
            name="str.split",
            parameters=[
                ParameterInfo("sep", 0, has_default=True),
                ParameterInfo("maxsplit", 1, has_default=True),
            ],
            return_type=PyType.list_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._models[(TypeKind.STR, "rsplit")] = FunctionSummary(
            name="str.rsplit",
            parameters=[
                ParameterInfo("sep", 0, has_default=True),
                ParameterInfo("maxsplit", 1, has_default=True),
            ],
            return_type=PyType.list_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._models[(TypeKind.STR, "splitlines")] = FunctionSummary(
            name="str.splitlines",
            parameters=[ParameterInfo("keepends", 0, has_default=True)],
            return_type=PyType.list_type(),
            is_pure=True,
            is_readonly=True,
        )
        str_pure_bool = [
            "isalnum",
            "isalpha",
            "isascii",
            "isdecimal",
            "isdigit",
            "isidentifier",
            "islower",
            "isnumeric",
            "isprintable",
            "isspace",
            "istitle",
            "isupper",
        ]
        for name in str_pure_bool:
            cls._models[(TypeKind.STR, name)] = FunctionSummary(
                name=f"str.{name }",
                parameters=[],
                return_type=PyType.bool_type(),
                is_pure=True,
                is_readonly=True,
            )
        str_search_int = [
            (
                "find",
                [
                    ParameterInfo("sub", 0),
                    ParameterInfo("start", 1, has_default=True),
                    ParameterInfo("end", 2, has_default=True),
                ],
            ),
            (
                "rfind",
                [
                    ParameterInfo("sub", 0),
                    ParameterInfo("start", 1, has_default=True),
                    ParameterInfo("end", 2, has_default=True),
                ],
            ),
            (
                "index",
                [
                    ParameterInfo("sub", 0),
                    ParameterInfo("start", 1, has_default=True),
                    ParameterInfo("end", 2, has_default=True),
                ],
            ),
            (
                "rindex",
                [
                    ParameterInfo("sub", 0),
                    ParameterInfo("start", 1, has_default=True),
                    ParameterInfo("end", 2, has_default=True),
                ],
            ),
            (
                "count",
                [
                    ParameterInfo("sub", 0),
                    ParameterInfo("start", 1, has_default=True),
                    ParameterInfo("end", 2, has_default=True),
                ],
            ),
        ]
        for name, params in str_search_int:
            may_raise: set[str] = {"ValueError"} if "index" in name else set()
            cls._models[(TypeKind.STR, name)] = FunctionSummary(
                name=f"str.{name }",
                parameters=params,
                return_type=PyType.int_type(),
                is_pure=True,
                is_readonly=True,
                may_raise=may_raise,
            )
        cls._models[(TypeKind.STR, "join")] = FunctionSummary(
            name="str.join",
            parameters=[ParameterInfo("iterable", 0)],
            return_type=PyType.str_type(),
            is_pure=True,
            is_readonly=True,
            may_raise={"TypeError"},
        )
        cls._models[(TypeKind.STR, "format")] = FunctionSummary(
            name="str.format",
            var_positional="args",
            var_keyword="kwargs",
            return_type=PyType.str_type(),
            is_pure=True,
            is_readonly=True,
            may_raise={"KeyError", "IndexError", "ValueError"},
        )
        cls._models[(TypeKind.STR, "startswith")] = FunctionSummary(
            name="str.startswith",
            parameters=[
                ParameterInfo("prefix", 0),
                ParameterInfo("start", 1, has_default=True),
                ParameterInfo("end", 2, has_default=True),
            ],
            return_type=PyType.bool_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._models[(TypeKind.STR, "endswith")] = FunctionSummary(
            name="str.endswith",
            parameters=[
                ParameterInfo("suffix", 0),
                ParameterInfo("start", 1, has_default=True),
                ParameterInfo("end", 2, has_default=True),
            ],
            return_type=PyType.bool_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._models[(TypeKind.STR, "encode")] = FunctionSummary(
            name="str.encode",
            parameters=[
                ParameterInfo("encoding", 0, has_default=True, default_value="utf-8"),
                ParameterInfo("errors", 1, has_default=True, default_value="strict"),
            ],
            return_type=PyType.bytes_type(),
            is_pure=True,
            is_readonly=True,
            may_raise={"UnicodeEncodeError"},
        )

    @classmethod
    def _add_list_methods(cls) -> None:
        """Add list method models."""
        cls._models[(TypeKind.LIST, "append")] = FunctionSummary(
            name="list.append",
            parameters=[ParameterInfo("x", 0)],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        cls._models[(TypeKind.LIST, "extend")] = FunctionSummary(
            name="list.extend",
            parameters=[ParameterInfo("iterable", 0)],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        cls._models[(TypeKind.LIST, "insert")] = FunctionSummary(
            name="list.insert",
            parameters=[ParameterInfo("i", 0), ParameterInfo("x", 1)],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        cls._models[(TypeKind.LIST, "remove")] = FunctionSummary(
            name="list.remove",
            parameters=[ParameterInfo("x", 0)],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
            may_raise={"ValueError"},
        )
        cls._models[(TypeKind.LIST, "pop")] = FunctionSummary(
            name="list.pop",
            parameters=[ParameterInfo("i", 0, has_default=True, default_value=-1)],
            return_type=PyType.unknown(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
            may_raise={"IndexError"},
        )
        cls._models[(TypeKind.LIST, "clear")] = FunctionSummary(
            name="list.clear",
            parameters=[],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        cls._models[(TypeKind.LIST, "sort")] = FunctionSummary(
            name="list.sort",
            parameters=[
                ParameterInfo("key", 0, has_default=True),
                ParameterInfo("reverse", 1, has_default=True, default_value=False),
            ],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        cls._models[(TypeKind.LIST, "reverse")] = FunctionSummary(
            name="list.reverse",
            parameters=[],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        cls._models[(TypeKind.LIST, "copy")] = FunctionSummary(
            name="list.copy",
            parameters=[],
            return_type=PyType.list_type(),
            is_pure=True,
            is_readonly=True,
        )
        cls._models[(TypeKind.LIST, "index")] = FunctionSummary(
            name="list.index",
            parameters=[
                ParameterInfo("x", 0),
                ParameterInfo("start", 1, has_default=True),
                ParameterInfo("end", 2, has_default=True),
            ],
            return_type=PyType.int_type(),
            is_pure=True,
            is_readonly=True,
            may_raise={"ValueError"},
        )
        cls._models[(TypeKind.LIST, "count")] = FunctionSummary(
            name="list.count",
            parameters=[ParameterInfo("x", 0)],
            return_type=PyType.int_type(),
            is_pure=True,
            is_readonly=True,
        )

    @classmethod
    def _add_dict_methods(cls) -> None:
        """Add dict method models."""
        cls._models[(TypeKind.DICT, "get")] = FunctionSummary(
            name="dict.get",
            parameters=[
                ParameterInfo("key", 0),
                ParameterInfo("default", 1, has_default=True),
            ],
            return_type=PyType.unknown(),
            is_pure=True,
            is_readonly=True,
        )
        cls._models[(TypeKind.DICT, "setdefault")] = FunctionSummary(
            name="dict.setdefault",
            parameters=[
                ParameterInfo("key", 0),
                ParameterInfo("default", 1, has_default=True),
            ],
            return_type=PyType.unknown(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        cls._models[(TypeKind.DICT, "pop")] = FunctionSummary(
            name="dict.pop",
            parameters=[
                ParameterInfo("key", 0),
                ParameterInfo("default", 1, has_default=True),
            ],
            return_type=PyType.unknown(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
            may_raise={"KeyError"},
        )
        cls._models[(TypeKind.DICT, "popitem")] = FunctionSummary(
            name="dict.popitem",
            parameters=[],
            return_type=PyType.tuple_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
            may_raise={"KeyError"},
        )
        cls._models[(TypeKind.DICT, "keys")] = FunctionSummary(
            name="dict.keys",
            parameters=[],
            return_type=PyType(kind=TypeKind.DICT_KEYS),
            is_pure=True,
            is_readonly=True,
        )
        cls._models[(TypeKind.DICT, "values")] = FunctionSummary(
            name="dict.values",
            parameters=[],
            return_type=PyType(kind=TypeKind.DICT_VALUES),
            is_pure=True,
            is_readonly=True,
        )
        cls._models[(TypeKind.DICT, "items")] = FunctionSummary(
            name="dict.items",
            parameters=[],
            return_type=PyType(kind=TypeKind.DICT_ITEMS),
            is_pure=True,
            is_readonly=True,
        )
        cls._models[(TypeKind.DICT, "update")] = FunctionSummary(
            name="dict.update",
            parameters=[ParameterInfo("other", 0, has_default=True)],
            var_keyword="kwargs",
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        cls._models[(TypeKind.DICT, "clear")] = FunctionSummary(
            name="dict.clear",
            parameters=[],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        cls._models[(TypeKind.DICT, "copy")] = FunctionSummary(
            name="dict.copy",
            parameters=[],
            return_type=PyType.dict_type(),
            is_pure=True,
            is_readonly=True,
        )

    @classmethod
    def _add_set_methods(cls) -> None:
        """Add set method models."""
        cls._models[(TypeKind.SET, "add")] = FunctionSummary(
            name="set.add",
            parameters=[ParameterInfo("elem", 0)],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        cls._models[(TypeKind.SET, "remove")] = FunctionSummary(
            name="set.remove",
            parameters=[ParameterInfo("elem", 0)],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
            may_raise={"KeyError"},
        )
        cls._models[(TypeKind.SET, "discard")] = FunctionSummary(
            name="set.discard",
            parameters=[ParameterInfo("elem", 0)],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        cls._models[(TypeKind.SET, "pop")] = FunctionSummary(
            name="set.pop",
            parameters=[],
            return_type=PyType.unknown(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
            may_raise={"KeyError"},
        )
        cls._models[(TypeKind.SET, "clear")] = FunctionSummary(
            name="set.clear",
            parameters=[],
            return_type=PyType.none_type(),
            is_pure=False,
            is_readonly=False,
            mutates_parameters={"self"},
        )
        set_ops: list[tuple[str, list[ParameterInfo]]] = [
            ("union", []),
            ("intersection", []),
            ("difference", []),
            ("symmetric_difference", [ParameterInfo("other", 0)]),
        ]
        for name, params in set_ops:
            cls._models[(TypeKind.SET, name)] = FunctionSummary(
                name=f"set.{name }",
                parameters=params,
                var_positional="others" if not params else None,
                return_type=PyType.set_type(),
                is_pure=True,
                is_readonly=True,
            )
        set_comparisons = ["issubset", "issuperset", "isdisjoint"]
        for name in set_comparisons:
            cls._models[(TypeKind.SET, name)] = FunctionSummary(
                name=f"set.{name }",
                parameters=[ParameterInfo("other", 0)],
                return_type=PyType.bool_type(),
                is_pure=True,
                is_readonly=True,
            )
        set_updates = [
            "update",
            "intersection_update",
            "difference_update",
            "symmetric_difference_update",
        ]
        for name in set_updates:
            cls._models[(TypeKind.SET, name)] = FunctionSummary(
                name=f"set.{name }",
                var_positional="others",
                return_type=PyType.none_type(),
                is_pure=False,
                is_readonly=False,
                mutates_parameters={"self"},
            )
        cls._models[(TypeKind.SET, "copy")] = FunctionSummary(
            name="set.copy",
            parameters=[],
            return_type=PyType.set_type(),
            is_pure=True,
            is_readonly=True,
        )
