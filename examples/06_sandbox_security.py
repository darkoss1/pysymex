"""
06: Sandbox Security Controls

This example demonstrates how pysymex enforces strict security boundaries
when scanning user-provided code, protecting the host system from unauthorized
operations such as filesystem access, socket networking, or arbitrary shell execution.

To scan this example:
    pysymex scan examples/06_sandbox_security.py
"""


def unsafe_file_leak(filepath: str) -> str:
    """
    An attempt to leak system files using Python's built-in open().
    The sandbox will block this operation, preventing unauthorized read access.
    """
    # The 'open' builtin is disabled/restricted inside the sandbox
    with open(filepath, "r") as f:
        return f.read()


def unsafe_network_connect(host: str, port: int) -> None:
    """
    An attempt to initiate sockets network connections, which is blocked
    by the sandbox networking security boundaries.
    """
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))


def unsafe_reflection_escape() -> object:
    """
    An attempt to perform reflective sandbox escape using dunder attributes
    (e.g., getting subclasses of object to find OS or subprocess modules).
    pysymex's hardened AST check and runtime wrappers block this access.
    """
    # Attempting to access __class__ or __subclasses__ is strictly blocked
    return ().__class__.__bases__[0].__subclasses__()
