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

"""Thread-safe registry of parsed function and class contracts.

Maps decorated callables to :class:`~pysymex.contracts.types.FunctionContract` records
via weak references. Decorator functions in :mod:`pysymex.contracts.decorators` populate
this store at import time.
"""

from __future__ import annotations

import inspect
from pysymex.logger import get_logger
import threading
from collections.abc import Callable, Mapping
from types import MappingProxyType
from weakref import ReferenceType, ref

from pysymex.contracts.types import Contract, FunctionContract

logger = get_logger(__name__)

_contract_registry: dict[str, FunctionContract] = {}
_contract_owners: dict[str, ReferenceType[Callable[..., object]]] = {}
_registry_lock = threading.Lock()
_class_invariant_registry: dict[type[object], list[Contract]] = {}

# A read-only view of the active function contract registry mapping function keys to their contracts.
function_contracts: Mapping[str, FunctionContract] = MappingProxyType(_contract_registry)


def get_function_key(func: Callable[..., object]) -> str:
    """Compute the canonical registry key for a function.

    Args:
        func: The target function object.

    Returns:
        A unique string key combining the module name and function qualname.
    """
    module = getattr(func, "__module__", "<unknown>")
    qualname = getattr(func, "__qualname__", getattr(func, "__name__", repr(func)))
    return f"{module}.{qualname}"


def get_or_create_contract(func: Callable[..., object]) -> FunctionContract:
    """Get or create a FunctionContract associated with the given function.

    First checks if the function already has an active contract attached to its
    ``__contract__`` attribute. If not, queries the thread-safe global registry.

    Args:
        func: The target function object.

    Returns:
        The existing or newly initialized ``FunctionContract`` instance.

    Side Effects:
        Acquires ``_registry_lock`` and may update the global ``_contract_registry``
        and ``_contract_owners`` weak-reference maps.
    """
    existing = getattr(func, "__contract__", None)
    if isinstance(existing, FunctionContract):
        return existing

    key = get_function_key(func)
    with _registry_lock:
        existing = _contract_registry.get(key)
        owner = _contract_owners.get(key)
        if existing is not None and owner is not None and owner() is func:
            return existing
        contract = FunctionContract(function_name=getattr(func, "__name__", repr(func)))
        _contract_registry[key] = contract
        _contract_owners[key] = ref(func)
        return contract


def get_function_contract(func: Callable[..., object]) -> FunctionContract | None:
    """Retrieve the contract for a function, or ``None`` if it is undecorated.

    Checks the function's ``__contract__`` attribute first, falling back to the
    global registry view.

    Args:
        func: The target function object.

    Returns:
        The associated ``FunctionContract`` instance, or ``None`` if not found.

    Side Effects:
        Acquires ``_registry_lock``.
    """
    existing = getattr(func, "__contract__", None)
    if isinstance(existing, FunctionContract):
        return existing

    key = get_function_key(func)
    with _registry_lock:
        owner = _contract_owners.get(key)
        if owner is not None and owner() is func:
            return _contract_registry.get(key)
        return None


def get_line_number(func: Callable[..., object]) -> int | None:
    """Best-effort extraction of the function's source line number.

    Args:
        func: The target function object.

    Returns:
        The starting line number of the function definition, or ``None`` if
        source inspection fails.
    """
    try:
        source_lines = inspect.getsourcelines(func)
        return source_lines[1]
    except (OSError, TypeError):
        logger.debug("Failed to get source lines for %s", func, exc_info=True)
        return None


def get_class_invariants(cls: type[object]) -> list[Contract]:
    """Return the mutable list of invariants associated with a class.

    If no invariants have been registered yet, initializes an empty list.

    Args:
        cls: The target class object.

    Returns:
        A list of registered ``Contract`` invariant objects.
    """
    return _class_invariant_registry.setdefault(cls, [])
