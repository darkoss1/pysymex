"""
02: Common Runtime Bugs

This example demonstrates pysymex's ability to automatically detect common Python
runtime errors like index out-of-bounds, None attribute access, and missing keys.

To scan this example:
    pysymex scan examples/02_common_runtime_bugs.py
"""


def unsafe_array_access(index: int) -> int:
    """
    Index out-of-bounds error. The list has only 3 elements.
    If the symbolic index is less than 0 or greater than 2, a crash occurs.
    """
    items = [10, 20, 30]
    return items[index]


def safe_array_access(index: int) -> int:
    """
    Safely guarded array access.
    """
    items = [10, 20, 30]
    if 0 <= index < len(items):
        return items[index]
    return -1


def unsafe_none_dereference(is_authenticated: bool) -> str:
    """
    None dereference error. If is_authenticated is False,
    the user object is None, and accessing its attribute crashes.
    """
    class User:
        name = "Alice"

    user = User() if is_authenticated else None
    return user.name


def safe_none_dereference(is_authenticated: bool) -> str:
    """
    Safely guarded None check.
    """
    class User:
        name = "Alice"

    user = User() if is_authenticated else None
    if user is None:
        return "Guest"
    return user.name


def unsafe_dictionary_lookup(key: str) -> int:
    """
    KeyError. Accessing a dictionary with a key that may not exist.
    """
    config = {"port": 8080, "timeout": 30}
    return config[key]


def safe_dictionary_lookup(key: str) -> int:
    """
    Safely guarded dictionary lookup.
    """
    config = {"port": 8080, "timeout": 30}
    if key in config:
        return config[key]
    return 0
