# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Models for the collections module.

This module provides symbolic models for collections module types:
- Counter
- defaultdict
- deque
- OrderedDict
- ChainMap
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.core.state import VMState
    from pysymex.core.types.scalars import SymbolicValue
    from pysymex.core.types.containers import SymbolicDict, SymbolicList
else:
    from pysymex.core.types.scalars import SymbolicDict, SymbolicList


class CounterModel:
    """Model for collections.Counter.

    Counter is a dict subclass for counting hashable objects.
    Elements are stored as dictionary keys and counts as values.
    """

    @staticmethod
    def model_init(
        state: VMState,
        iterable: SymbolicList | None = None,
    ) -> SymbolicDict:
        """Model Counter() initialization.

        Args:
            state: Current VM state
            iterable: Optional iterable to count

        Returns:
            A SymbolicDict representing the Counter
        """
        counter = SymbolicDict.empty("counter")
        return counter

    @staticmethod
    def model_most_common(
        counter: SymbolicDict,
        n: SymbolicValue | int | None = None,
    ) -> SymbolicList:
        """Model Counter.most_common(n).

        Args:
            counter: The Counter to get elements from
            n: Number of elements to return (None = all)

        Returns:
            A SymbolicList of (element, count) tuples
        """
        result = SymbolicList.empty("most_common_result")
        return result

    @staticmethod
    def model_elements(counter: SymbolicDict) -> SymbolicList:
        """Model Counter.elements().

        Returns:
            Iterator over elements, repeating each as many times as its count
        """
        return SymbolicList.empty("counter_elements")

    @staticmethod
    def model_subtract(
        counter: SymbolicDict,
        other: SymbolicDict | None = None,
    ) -> None:
        """Model Counter.subtract().

        Subtracts counts (unlike -, keeps zeros and negatives).
        """
        pass

    @staticmethod
    def model_update(
        counter: SymbolicDict,
        other: SymbolicDict | None = None,
    ) -> None:
        """Model Counter.update().

        Adds counts from other.
        """
        pass


class DefaultDictModel:
    """Model for collections.defaultdict.

    A dict subclass that calls a factory function to supply missing values.
    Key property: __getitem__ never raises KeyError.
    """

    @staticmethod
    def model_init(
        state: VMState,
        default_factory: object = None,
    ) -> SymbolicDict:
        """Model defaultdict() initialization.

        Args:
            state: Current VM state
            default_factory: Callable for missing values

        Returns:
            A SymbolicDict that won't raise KeyError
        """
        dd = SymbolicDict.empty("defaultdict")
        setattr(dd, "_has_default_factory", True)
        return dd

    @staticmethod
    def model_getitem(
        dd: SymbolicDict,
        key: SymbolicValue,
    ) -> SymbolicValue:
        """Model defaultdict[key].

        Unlike regular dict, this never raises KeyError.
        Returns the existing value or creates a new default.

        Args:
            dd: The defaultdict to access
            key: The key to look up

        Returns:
            The value (existing or default)
        """
        from pysymex.core.types.scalars import SymbolicValue

        result, _ = SymbolicValue.symbolic(f"defaultdict_value_{key}")
        return result

    @staticmethod
    def model_missing(
        dd: SymbolicDict,
        key: SymbolicValue,
    ) -> SymbolicValue:
        """Model defaultdict.__missing__(key).

        Called when key is not found.
        """
        from pysymex.core.types.scalars import SymbolicValue

        result, _ = SymbolicValue.symbolic(f"defaultdict_default_{key}")
        return result


class DequeModel:
    """Model for collections.deque.

    Double-ended queue with O(1) append/pop on both ends.
    """

    @staticmethod
    def model_init(
        state: VMState,
        iterable: SymbolicList | None = None,
        maxlen: int | None = None,
    ) -> SymbolicList:
        """Model deque() initialization.

        Args:
            state: Current VM state
            iterable: Optional initial elements
            maxlen: Maximum length (None = unbounded)

        Returns:
            A SymbolicList representing the deque
        """
        if iterable is not None:
            return iterable
        return SymbolicList.empty("deque")

    @staticmethod
    def model_append(deque: SymbolicList, x: SymbolicValue) -> None:
        """Model deque.append(x). Adds to right end."""
        pass

    @staticmethod
    def model_appendleft(deque: SymbolicList, x: SymbolicValue) -> None:
        """Model deque.appendleft(x). Adds to left end."""
        pass

    @staticmethod
    def model_pop(deque: SymbolicList) -> SymbolicValue:
        """Model deque.pop(). Removes and returns from right end.

        Raises IndexError if empty.
        """
        from pysymex.core.types.scalars import SymbolicValue

        result, _ = SymbolicValue.symbolic("deque_pop_result")
        return result

    @staticmethod
    def model_popleft(deque: SymbolicList) -> SymbolicValue:
        """Model deque.popleft(). Removes and returns from left end.

        Raises IndexError if empty.
        """
        from pysymex.core.types.scalars import SymbolicValue

        result, _ = SymbolicValue.symbolic("deque_popleft_result")
        return result

    @staticmethod
    def model_rotate(deque: SymbolicList, n: int = 1) -> None:
        """Model deque.rotate(n). Rotates n steps to the right."""
        pass

    @staticmethod
    def model_extend(deque: SymbolicList, iterable: SymbolicList) -> None:
        """Model deque.extend(iterable). Extends right side."""
        pass

    @staticmethod
    def model_extendleft(deque: SymbolicList, iterable: SymbolicList) -> None:
        """Model deque.extendleft(iterable). Extends left side."""
        pass

    @staticmethod
    def model_clear(deque: SymbolicList) -> None:
        """Model deque.clear(). Removes all elements."""
        pass


class OrderedDictModel:
    """Model for collections.OrderedDict.

    A dict that remembers insertion order.
    In Python 3.7+, regular dict also maintains order.
    """

    @staticmethod
    def model_init(state: VMState) -> SymbolicDict:
        """Model OrderedDict() initialization."""
        return SymbolicDict.empty("ordereddict")

    @staticmethod
    def model_move_to_end(
        _od: SymbolicDict,
        key: SymbolicValue,
        last: bool = True,
    ) -> None:
        """Model OrderedDict.move_to_end(key, last=True).

        Raises KeyError if key not present.
        """
        pass

    @staticmethod
    def model_popitem(
        _od: SymbolicDict,
        last: bool = True,
    ) -> tuple[SymbolicValue, SymbolicValue]:
        """Model OrderedDict.popitem(last=True).

        Returns and removes (key, value) pair.
        Raises KeyError if empty.
        """
        from pysymex.core.types.scalars import SymbolicValue

        key, _ = SymbolicValue.symbolic("popitem_key")
        value, _ = SymbolicValue.symbolic("popitem_value")
        return (key, value)


class ChainMapModel:
    """Model for collections.ChainMap.

    Groups multiple dicts for single-view lookup.
    """

    @staticmethod
    def model_init(
        state: VMState,
        *_maps: SymbolicDict,
    ) -> SymbolicDict:
        """Model ChainMap() initialization.

        Lookups search all maps in order.
        """
        return SymbolicDict.empty("chainmap")

    @staticmethod
    def model_new_child(
        cm: SymbolicDict,
        m: SymbolicDict | None = None,
    ) -> SymbolicDict:
        """Model ChainMap.new_child(m=None).

        Returns new ChainMap with m first, then current.
        """
        return SymbolicDict.empty("chainmap_child")


COLLECTIONS_MODELS = {
    "Counter": CounterModel,
    "defaultdict": DefaultDictModel,
    "deque": DequeModel,
    "OrderedDict": OrderedDictModel,
    "ChainMap": ChainMapModel,
}


def get_collections_model(name: str) -> type | None:
    """Get the model class for a collections type.

    Args:
        name: Name of the collections type (e.g., "Counter", "deque")

    Returns:
        The model class or None if not found
    """
    return COLLECTIONS_MODELS.get(name)


def register_collections_models() -> dict[str, type]:
    """Register all collections models.

    Returns:
        Dict mapping fully qualified names to model classes
    """
    return {
        "collections.Counter": CounterModel,
        "collections.defaultdict": DefaultDictModel,
        "collections.deque": DequeModel,
        "collections.OrderedDict": OrderedDictModel,
        "collections.ChainMap": ChainMapModel,
    }
