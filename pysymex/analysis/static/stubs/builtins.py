# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Built-in type stubs (int, str, list, dict, etc.) always available for inference."""

from __future__ import annotations

from pysymex.analysis.static.stubs.types import ClassStub, FunctionStub, ModuleStub, StubType


class BuiltinStubs:
    """
    Pre-defined stubs for common built-in types and functions.
    These are always available without loading external stub files.
    """

    @staticmethod
    def get_builtin_module() -> ModuleStub:
        """Get stub for builtins module."""
        stub = ModuleStub(name="builtins")
        stub.functions["len"] = FunctionStub(
            name="len",
            params={"__obj": StubType("Sized", "typing")},
            return_type=StubType.int_type(),
        )
        stub.functions["range"] = FunctionStub(
            name="range",
            params={
                "start": StubType.int_type(),
                "stop": StubType.int_type(),
                "step": StubType.int_type(),
            },
            return_type=StubType("range", "builtins"),
        )
        stub.functions["enumerate"] = FunctionStub(
            name="enumerate",
            params={
                "iterable": StubType("Iterable", "typing", (StubType.typevar("T"),)),
                "start": StubType.int_type(),
            },
            return_type=StubType(
                "Iterator",
                "typing",
                (StubType.tuple_of(StubType.int_type(), StubType.typevar("T")),),
            ),
        )
        stub.functions["zip"] = FunctionStub(
            name="zip",
            params={
                "*iterables": StubType("Iterable", "typing"),
            },
            return_type=StubType("Iterator", "typing", (StubType("tuple", "builtins"),)),
        )
        stub.functions["map"] = FunctionStub(
            name="map",
            params={
                "func": StubType.callable([StubType.typevar("T")], StubType.typevar("S")),
                "*iterables": StubType("Iterable", "typing", (StubType.typevar("T"),)),
            },
            return_type=StubType("Iterator", "typing", (StubType.typevar("S"),)),
        )
        stub.functions["filter"] = FunctionStub(
            name="filter",
            params={
                "func": StubType.optional(
                    StubType.callable([StubType.typevar("T")], StubType.bool_type())
                ),
                "iterable": StubType("Iterable", "typing", (StubType.typevar("T"),)),
            },
            return_type=StubType("Iterator", "typing", (StubType.typevar("T"),)),
        )
        stub.functions["sorted"] = FunctionStub(
            name="sorted",
            params={
                "iterable": StubType("Iterable", "typing", (StubType.typevar("T"),)),
                "key": StubType.optional(
                    StubType.callable([StubType.typevar("T")], StubType.any_type())
                ),
                "reverse": StubType.bool_type(),
            },
            return_type=StubType.list_of(StubType.typevar("T")),
        )
        stub.functions["isinstance"] = FunctionStub(
            name="isinstance",
            params={
                "obj": StubType.object_type(),
                "classinfo": StubType.union(
                    StubType("type", "builtins"),
                    StubType.tuple_of(StubType("type", "builtins")),
                ),
            },
            return_type=StubType.bool_type(),
        )
        stub.functions["hasattr"] = FunctionStub(
            name="hasattr",
            params={
                "obj": StubType.object_type(),
                "name": StubType.str_type(),
            },
            return_type=StubType.bool_type(),
        )
        stub.functions["getattr"] = FunctionStub(
            name="getattr",
            params={
                "obj": StubType.object_type(),
                "name": StubType.str_type(),
                "default": StubType.any_type(),
            },
            return_type=StubType.any_type(),
        )
        return stub

    @staticmethod
    def get_collections_module() -> ModuleStub:
        """Get stub for collections module."""
        stub = ModuleStub(name="collections")
        defaultdict_class = ClassStub(
            name="defaultdict",
            bases=[StubType.dict_of(StubType.typevar("K"), StubType.typevar("V"))],
        )
        defaultdict_class.methods["__getitem__"] = FunctionStub(
            name="__getitem__",
            params={"key": StubType.typevar("K")},
            return_type=StubType.typevar("V"),
        )
        stub.classes["defaultdict"] = defaultdict_class
        counter_class = ClassStub(
            name="Counter",
            bases=[StubType.dict_of(StubType.typevar("T"), StubType.int_type())],
        )
        counter_class.methods["__getitem__"] = FunctionStub(
            name="__getitem__",
            params={"key": StubType.typevar("T")},
            return_type=StubType.int_type(),
        )
        stub.classes["Counter"] = counter_class
        ordered_dict_class = ClassStub(
            name="OrderedDict",
            bases=[StubType.dict_of(StubType.typevar("K"), StubType.typevar("V"))],
        )
        stub.classes["OrderedDict"] = ordered_dict_class
        deque_class = ClassStub(
            name="deque",
            bases=[StubType("MutableSequence", "typing", (StubType.typevar("T"),))],
        )
        deque_class.methods["append"] = FunctionStub(
            name="append",
            params={"x": StubType.typevar("T")},
            return_type=StubType.none_type(),
        )
        deque_class.methods["appendleft"] = FunctionStub(
            name="appendleft",
            params={"x": StubType.typevar("T")},
            return_type=StubType.none_type(),
        )
        stub.classes["deque"] = deque_class
        return stub


__all__ = ["BuiltinStubs"]
