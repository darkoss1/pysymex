"""Models for the itertools module.

This module provides symbolic models for itertools functions:
- chain
- islice
- groupby
- product
- permutations
- combinations
- count
- cycle
- repeat

v0.3.0-alpha: Initial implementation
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Iterator

import z3

if TYPE_CHECKING:
    from pyspectre.core.types import SymbolicValue

from pyspectre.core.types import SymbolicList


def model_chain(*iterables: SymbolicList) -> SymbolicList:
    """Model itertools.chain(*iterables).

    Chains multiple iterables into a single iterator.
    The length is the sum of all input lengths.

    Args:
        *iterables: Iterables to chain together

    Returns:
        A SymbolicList representing the chained result
    """
    result = SymbolicList.empty("chain_result")

    if iterables:
        total_len = iterables[0].z3_len
        for it in iterables[1:]:
            total_len = total_len + it.z3_len
        result._z3_len = total_len

    return result


def model_chain_from_iterable(iterable: SymbolicList) -> SymbolicList:
    """Model itertools.chain.from_iterable(iterable).

    Chains iterables from a single iterable of iterables.
    """
    return SymbolicList.empty("chain_from_iterable_result")


def model_islice(
    iterable: SymbolicList,
    *args,  # start, stop, step or just stop
) -> SymbolicList:
    """Model itertools.islice(iterable, stop) or islice(iterable, start, stop[, step]).

    Returns selected elements from the iterable.

    Args:
        iterable: Source iterable
        *args: Slice arguments

    Returns:
        A SymbolicList with sliced elements
    """
    result = SymbolicList.empty("islice_result")

    if len(args) == 1:
        stop = args[0]
        if isinstance(stop, int):
            result._z3_len = z3.If(
                iterable.z3_len < stop,
                iterable.z3_len,
                z3.IntVal(stop),
            )
    elif len(args) >= 2:
        start, stop = args[0], args[1]
        step = args[2] if len(args) > 2 else 1
        if isinstance(start, int) and isinstance(stop, int) and isinstance(step, int):
            expected_len = max(0, (stop - start + step - 1) // step)
            result._z3_len = z3.IntVal(expected_len)

    return result


def model_groupby(
    iterable: SymbolicList,
    key: callable | None = None,
) -> SymbolicList:
    """Model itertools.groupby(iterable, key=None).

    Groups consecutive elements with the same key.

    Args:
        iterable: Iterable to group
        key: Key function (None = identity)

    Returns:
        A SymbolicList of (key, group) pairs
    """
    return SymbolicList.empty("groupby_result")


def model_product(*iterables: SymbolicList, repeat: int = 1) -> SymbolicList:
    """Model itertools.product(*iterables, repeat=1).

    Cartesian product of input iterables.
    Length is product of all input lengths.

    Args:
        *iterables: Iterables for product
        repeat: Number of repetitions

    Returns:
        A SymbolicList of tuples
    """
    result = SymbolicList.empty("product_result")

    if iterables:
        product_len = iterables[0].z3_len
        for it in iterables[1:]:
            product_len = product_len * it.z3_len
        for _ in range(repeat - 1):
            product_len = product_len * iterables[0].z3_len
        result._z3_len = product_len

    return result


def model_permutations(
    iterable: SymbolicList,
    r: int | None = None,
) -> SymbolicList:
    """Model itertools.permutations(iterable, r=None).

    Returns r-length permutations of elements.
    Length is n! / (n-r)! where n is len(iterable).

    Args:
        iterable: Source iterable
        r: Permutation length (None = full length)

    Returns:
        A SymbolicList of permutation tuples
    """
    result = SymbolicList.empty("permutations_result")
    return result


def model_combinations(
    iterable: SymbolicList,
    r: int,
) -> SymbolicList:
    """Model itertools.combinations(iterable, r).

    Returns r-length combinations of elements.
    Length is n! / (r! * (n-r)!) where n is len(iterable).

    Args:
        iterable: Source iterable
        r: Combination length

    Returns:
        A SymbolicList of combination tuples
    """
    result = SymbolicList.empty("combinations_result")
    return result


def model_combinations_with_replacement(
    iterable: SymbolicList,
    r: int,
) -> SymbolicList:
    """Model itertools.combinations_with_replacement(iterable, r).

    Returns r-length combinations with replacement.
    """
    return SymbolicList.empty("combinations_wr_result")


def model_count(start: int = 0, step: int = 1) -> Iterator[int]:
    """Model itertools.count(start=0, step=1).

    Returns an infinite iterator counting from start.
    """
    from pyspectre.core.types import SymbolicValue

    result, _ = SymbolicValue.symbolic("count")
    return result


def model_cycle(iterable: SymbolicList) -> SymbolicList:
    """Model itertools.cycle(iterable).

    Returns infinite iterator cycling through iterable.
    """
    result = SymbolicList.empty("cycle_result")
    result._is_infinite = True
    return result


def model_repeat(obj, times: int | None = None) -> SymbolicList:
    """Model itertools.repeat(obj, times=None).

    Returns iterator repeating obj.
    If times is None, repeats indefinitely.

    Args:
        obj: Object to repeat
        times: Number of times (None = infinite)

    Returns:
        A SymbolicList
    """
    result = SymbolicList.empty("repeat_result")
    if times is not None:
        result._z3_len = z3.IntVal(times)
    else:
        result._is_infinite = True
    return result


def model_accumulate(
    iterable: SymbolicList,
    func: callable | None = None,
    initial: object = None,
) -> SymbolicList:
    """Model itertools.accumulate(iterable, func=None, *, initial=None).

    Returns running accumulation of iterable.
    """
    result = SymbolicList.empty("accumulate_result")
    if initial is not None:
        result._z3_len = iterable.z3_len + 1
    else:
        result._z3_len = iterable.z3_len
    return result


def model_takewhile(
    predicate: callable,
    iterable: SymbolicList,
) -> SymbolicList:
    """Model itertools.takewhile(predicate, iterable).

    Takes elements while predicate is true.
    """
    result = SymbolicList.empty("takewhile_result")
    result._z3_len = z3.If(
        result._z3_len >= 0,
        result._z3_len,
        z3.IntVal(0),
    )
    return result


def model_dropwhile(
    predicate: callable,
    iterable: SymbolicList,
) -> SymbolicList:
    """Model itertools.dropwhile(predicate, iterable).

    Drops elements while predicate is true, then yields rest.
    """
    result = SymbolicList.empty("dropwhile_result")
    return result


def model_zip_longest(
    *iterables: SymbolicList,
    fillvalue=None,
) -> SymbolicList:
    """Model itertools.zip_longest(*iterables, fillvalue=None).

    Zips iterables, using fillvalue for shorter ones.
    Length is max of all input lengths.
    """
    result = SymbolicList.empty("zip_longest_result")

    if iterables:
        max_len = iterables[0].z3_len
        for it in iterables[1:]:
            max_len = z3.If(it.z3_len > max_len, it.z3_len, max_len)
        result._z3_len = max_len

    return result


ITERTOOLS_MODELS = {
    "chain": model_chain,
    "chain.from_iterable": model_chain_from_iterable,
    "islice": model_islice,
    "groupby": model_groupby,
    "product": model_product,
    "permutations": model_permutations,
    "combinations": model_combinations,
    "combinations_with_replacement": model_combinations_with_replacement,
    "count": model_count,
    "cycle": model_cycle,
    "repeat": model_repeat,
    "accumulate": model_accumulate,
    "takewhile": model_takewhile,
    "dropwhile": model_dropwhile,
    "zip_longest": model_zip_longest,
}


def get_itertools_model(name: str) -> callable | None:
    """Get the model function for an itertools function.

    Args:
        name: Name of the itertools function

    Returns:
        The model function or None if not found
    """
    return ITERTOOLS_MODELS.get(name)


def register_itertools_models() -> dict[str, callable]:
    """Register all itertools models.

    Returns:
        Dict mapping fully qualified names to model functions
    """
    return {f"itertools.{name}": model for name, model in ITERTOOLS_MODELS.items()}
