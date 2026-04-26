# pysymex: Python Symbolic Execution & Formal Verification
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

"""Hardened harness script generation for sandbox backends.

This module generates self-contained Python scripts that execute inside
the sandbox subprocess.  The generated harness applies multiple layers
of defence **before** running the untrusted target code:

1. **Filename validation** — target filename arrives via ``sys.argv[1]``,
   never via string interpolation (prevents code injection).
2. **``sys.modules`` scrubbing** — dangerous modules loaded during Python
   startup are evicted *before* the import-hook is installed.
3. **Modern ``MetaPathFinder``** — uses ``find_spec`` (PEP 302 / PEP 451)
   **and** the legacy ``find_module`` fallback to block imports
   comprehensively.
4. **Restricted builtins** — the target code runs in a namespace where
   ``exec``, ``eval``, ``compile``, ``open``, ``__import__``, etc. are
   replaced with functions that unconditionally raise.
5. **AST pre-screening** — common introspection-attack patterns
   (``__subclasses__``, ``__globals__``, …) are detected *before*
   compilation and rejected.
"""

from __future__ import annotations

import textwrap
from typing import Final

from pysymex._constants import (
    SANDBOX_BLOCKED_MODULES,
    SANDBOX_DANGEROUS_BUILTINS,
    SANDBOX_SUSPICIOUS_PATTERNS,
)


def generate_harness_script(
    *,
    blocked_modules: frozenset[str] | None = None,
    allowed_imports: frozenset[str] | None = None,
    dangerous_builtins: frozenset[str] | None = None,
    suspicious_patterns: tuple[str, ...] | None = None,
    restrict_builtins: bool = True,
    enable_ast_prescreening: bool = True,
    install_audit_hook: bool = True,
    block_ast_imports: bool = False,
    install_seccomp: bool = False,
    seccomp_allowlist: tuple[int, ...] | None = None,
) -> str:
    """Return a self-contained Python harness script as a string.

    The script is written to the sandbox jail and executed as::

        python <harness_path> <target_filename>

    The *target_filename* is passed via ``sys.argv`` — **never** via
    f-string interpolation — to eliminate code-injection vectors.

    Args:
        blocked_modules: Top-level module names to block.  ``None`` uses
            :data:`SANDBOX_BLOCKED_MODULES`.
        dangerous_builtins: Builtin names to disable.  ``None`` uses
            :data:`SANDBOX_DANGEROUS_BUILTINS`.
        suspicious_patterns: String patterns that trigger AST
            pre-screening rejection.  ``None`` uses
            :data:`SANDBOX_SUSPICIOUS_PATTERNS`.
        restrict_builtins: Whether to replace dangerous builtins with
            stub functions that always raise.
        enable_ast_prescreening: Whether to scan source code for
            known introspection-attack signatures before compilation.
        install_audit_hook: Whether to install a runtime audit hook that
            rejects high-risk operations (filesystem writes, process spawn,
            networking, dynamic code loading).
        block_ast_imports: Whether to reject all ``import`` and
            ``from ... import ...`` statements found in target source.

    Returns:
        Complete, executable Python source code (UTF-8).
    """
    modules = blocked_modules if blocked_modules is not None else SANDBOX_BLOCKED_MODULES
    builtins_ = dangerous_builtins if dangerous_builtins is not None else SANDBOX_DANGEROUS_BUILTINS
    allowed = allowed_imports
    patterns = (
        suspicious_patterns if suspicious_patterns is not None else SANDBOX_SUSPICIOUS_PATTERNS
    )
    seccomp_syscalls = seccomp_allowlist if seccomp_allowlist is not None else ()

    blocked_repr: str = repr(modules)
    allowed_imports_repr: str = repr(allowed)
    builtins_repr: str = repr(builtins_)
    patterns_repr: str = repr(patterns)
    seccomp_install_repr: str = repr(install_seccomp)
    seccomp_allowlist_repr: str = repr(tuple(sorted(seccomp_syscalls)))

    return textwrap.dedent(f"""\
        # ===================================================================
        # PySymEx sandbox harness — auto-generated, do not edit
        # ===================================================================
        \"\"\"Hardened execution wrapper.

        Invocation: python _sandbox_harness.py <target_filename>
        \"\"\"
        import sys as _sys

        # ---------------------------------------------------------------
        # Phase 0 — Validate target filename (argv, not f-string)
        # ---------------------------------------------------------------
        if len(_sys.argv) < 2:
            _sys.exit("sandbox-harness: no target filename provided")
        _target: str = _sys.argv[1]

        # Reject path separators, traversal, and non-alphanum
        if ("/" in _target or "\\\\" in _target or ".." in _target
                or _target.startswith(".") or _target.startswith("-")):
            _sys.exit("sandbox-harness: invalid target filename")

        _safe_chars = frozenset(
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789_-."
        )
        if not all(ch in _safe_chars for ch in _target):
            _sys.exit("sandbox-harness: illegal characters in filename")

        # ---------------------------------------------------------------
        # Phase 0.5 - Install seccomp filter after namespace setup
        # ---------------------------------------------------------------
        _INSTALL_SECCOMP: bool = {seccomp_install_repr}
        _SECCOMP_ALLOWLIST: tuple[int, ...] = {seccomp_allowlist_repr}

        if _INSTALL_SECCOMP:
            import ctypes as _ctypes

            _PR_SET_SECCOMP = 22
            _SECCOMP_SET_MODE_FILTER = 1
            _SECCOMP_RET_KILL_PROCESS = 0x80000000
            _SECCOMP_RET_ALLOW = 0x7FFF0000
            _BPF_LD = 0x00
            _BPF_JMP = 0x05
            _BPF_RET = 0x06
            _BPF_W = 0x00
            _BPF_ABS = 0x20
            _BPF_JEQ = 0x10
            _BPF_K = 0x00
            _AUDIT_ARCH_X86_64 = 0xC000003E

            class _SockFilter(_ctypes.Structure):
                _fields_ = [
                    ("code", _ctypes.c_ushort),
                    ("jt", _ctypes.c_ubyte),
                    ("jf", _ctypes.c_ubyte),
                    ("k", _ctypes.c_uint),
                ]

            class _SockFprog(_ctypes.Structure):
                _fields_ = [
                    ("len", _ctypes.c_ushort),
                    ("filter", _ctypes.POINTER(_SockFilter)),
                ]

            def _stmt(_code: int, _k: int) -> tuple[int, int, int, int]:
                return (_code, 0, 0, _k)

            def _jump(
                _code: int,
                _k: int,
                _jt: int,
                _jf: int,
            ) -> tuple[int, int, int, int]:
                return (_code, _jt, _jf, _k)

            _ins: list[tuple[int, int, int, int]] = []
            _ins.append(_stmt(_BPF_LD | _BPF_W | _BPF_ABS, 4))
            _ins.append(
                _jump(
                    _BPF_JMP | _BPF_JEQ | _BPF_K,
                    _AUDIT_ARCH_X86_64,
                    0,
                    1,
                )
            )
            _ins.append(_stmt(_BPF_RET | _BPF_K, _SECCOMP_RET_KILL_PROCESS))
            _ins.append(_stmt(_BPF_LD | _BPF_W | _BPF_ABS, 0))

            _sorted = sorted(_SECCOMP_ALLOWLIST)
            _remaining = len(_sorted)
            for _nr in _sorted:
                _remaining -= 1
                _ins.append(
                    _jump(
                        _BPF_JMP | _BPF_JEQ | _BPF_K,
                        int(_nr),
                        _remaining,
                        0,
                    )
                )

            _ins.append(_stmt(_BPF_RET | _BPF_K, _SECCOMP_RET_KILL_PROCESS))
            _ins.append(_stmt(_BPF_RET | _BPF_K, _SECCOMP_RET_ALLOW))

            _libc = _ctypes.CDLL("libc.so.6", use_errno=True)
            _arr_t = _SockFilter * len(_ins)
            _arr = _arr_t(*(_SockFilter(_c, _jt, _jf, _k) for _c, _jt, _jf, _k in _ins))
            _prog = _SockFprog(len(_ins), _arr)
            _rc = _libc.prctl(
                _PR_SET_SECCOMP,
                _SECCOMP_SET_MODE_FILTER,
                _ctypes.byref(_prog),
                0,
                0,
            )
            if _rc != 0:
                _err = _ctypes.get_errno()
                raise OSError(_err, "prctl(PR_SET_SECCOMP) failed in harness")

        # ---------------------------------------------------------------
        # Phase 1 — Scrub sys.modules of blocked modules
        # ---------------------------------------------------------------
        _BLOCKED: frozenset[str] = {blocked_repr}
        _ALLOWED_IMPORTS: frozenset[str] | None = {allowed_imports_repr}

        for _mod_name in list(_sys.modules):
            _top = _mod_name.split(".")[0]
            if _top in _BLOCKED:
                del _sys.modules[_mod_name]

        # ---------------------------------------------------------------
        # Phase 2 — Install strict MetaPathFinder (find_spec + legacy)
        # ---------------------------------------------------------------
        import importlib.abc as _iabc
        import importlib.machinery as _imach
        from typing import Sequence

        class _StrictModuleBlocker(_iabc.MetaPathFinder):
            __slots__ = ("_blocked",)

            def __init__(
                self,
                blocked: frozenset[str],
            ) -> None:
                self._blocked = blocked

            def find_spec(
                self,
                fullname: str,
                path: Sequence[str] | None,
                target: object = None,
            ) -> _imach.ModuleSpec | None:
                top = fullname.split(".")[0]
                if top in self._blocked:
                    raise ImportError(
                        f"Module '{{fullname}}' is blocked in sandbox mode"
                    )
                return None

            # Legacy fallback for older code paths
            def find_module(  # pyright: ignore[reportDeprecated]
                self,
                fullname: str,
                path: Sequence[str] | None = None,
            ) -> "_StrictModuleBlocker | None":
                top = fullname.split(".")[0]
                if top in self._blocked:
                    return self
                return None

            def load_module(  # pyright: ignore[reportDeprecated]
                self,
                fullname: str,
            ) -> object:
                raise ImportError(
                    f"Module '{{fullname}}' is blocked in sandbox mode"
                )

        _sys.meta_path.insert(0, _StrictModuleBlocker(_BLOCKED))

        # ---------------------------------------------------------------
        # Phase 3 — Build restricted builtins dict
        # ---------------------------------------------------------------
        _RESTRICT_BUILTINS: bool = {restrict_builtins!r}
        _DANGEROUS_BUILTINS: frozenset[str] = {builtins_repr}

        import builtins as _builtins_mod

        def _disabled_builtin(*_a: object, **_kw: object) -> None:
            raise RuntimeError("This builtin is disabled in sandbox mode")

        _restricted_builtins: dict[str, object] = {{}}
        if _RESTRICT_BUILTINS:
            for _name in dir(_builtins_mod):
                if _name.startswith("_"):
                    continue
                if _name in _DANGEROUS_BUILTINS:
                    _restricted_builtins[_name] = _disabled_builtin
                else:
                    _restricted_builtins[_name] = getattr(_builtins_mod, _name)
            # Re-add __name__ and __doc__ for well-behaved code
            _restricted_builtins["__name__"] = "__main__"
        else:
            for _name in dir(_builtins_mod):
                _restricted_builtins[_name] = getattr(_builtins_mod, _name)

        # ---------------------------------------------------------------
        # Phase 4 — AST pre-screening for introspection attacks
        # ---------------------------------------------------------------
        _ENABLE_AST_PRESCREENING: bool = {enable_ast_prescreening!r}
        _BLOCK_AST_IMPORTS: bool = {block_ast_imports!r}
        _SUSPICIOUS_PATTERNS: tuple[str, ...] = {patterns_repr}

        with open(_target, "r", encoding="utf-8") as _fp:
            _source: str = _fp.read()

        if _ENABLE_AST_PRESCREENING:
            for _pat in _SUSPICIOUS_PATTERNS:
                if _pat in _source:
                    _sys.exit(
                        f"sandbox-harness: rejected — suspicious pattern "
                        f"'{{_pat}}' detected in source"
                    )

        if _BLOCK_AST_IMPORTS:
            import ast as _ast

            try:
                _tree = _ast.parse(_source, filename=_target, mode="exec")
            except SyntaxError:
                raise

            for _node in _ast.walk(_tree):
                if isinstance(_node, (_ast.Import, _ast.ImportFrom)):
                    _sys.exit("sandbox-harness: rejected — import statements are disabled")
        elif _ALLOWED_IMPORTS is not None:
            import ast as _ast

            try:
                _tree = _ast.parse(_source, filename=_target, mode="exec")
            except SyntaxError:
                raise

            for _node in _ast.walk(_tree):
                if isinstance(_node, _ast.Import):
                    for _alias in _node.names:
                        _top = _alias.name.split(".")[0]
                        if _top not in _ALLOWED_IMPORTS:
                            _sys.exit(
                                f"sandbox-harness: rejected — import '{{_alias.name}}' is not allowlisted"
                            )
                elif isinstance(_node, _ast.ImportFrom):
                    _mod = _node.module or ""
                    _top = _mod.split(".")[0]
                    if _top and _top not in _ALLOWED_IMPORTS:
                        _sys.exit(
                            f"sandbox-harness: rejected — import from '{{_mod}}' is not allowlisted"
                        )

        # ---------------------------------------------------------------
        # Phase 5 — Compile and execute in restricted namespace
        # ---------------------------------------------------------------
        _code_obj = compile(_source, _target, "exec")

        _INSTALL_AUDIT_HOOK: bool = {install_audit_hook!r}
        _AUDIT_BLOCKED_PREFIXES: tuple[str, ...] = (
            "ctypes.",
            "subprocess.",
            "os.system",
            "os.exec",
            "os.spawn",
            "os.startfile",
            "os.kill",
            "os.putenv",
            "os.unsetenv",
            "os.remove",
            "os.rename",
            "os.rmdir",
            "os.mkdir",
            "os.chmod",
            "os.chown",
            "os.truncate",
            "os.symlink",
            "os.link",
            "shutil.",
            "socket.",
            "winreg.",
            "urllib.",
            "http.",
            "ftplib.",
            "mmap.",
            "pty.",
            "code.__new__",
        )
        if _INSTALL_AUDIT_HOOK and hasattr(_sys, "addaudithook"):
            def _create_audit_hook():
                import os as _os
                _LOCAL_JAIL_DIR = _os.path.abspath(_os.getcwd()) + _os.sep
                _LOCAL_PY_PREFIX = _os.path.abspath(_sys.prefix) + _os.sep
                _LOCAL_PY_BASE_PREFIX = _os.path.abspath(_sys.base_prefix) + _os.sep
                _LOCAL_WIN_DIR = _os.environ.get("SystemRoot", "C:\\\\Windows")
                _AUDIT_PREFIXES = _AUDIT_BLOCKED_PREFIXES
                _BLOCKED_TOP_LEVEL = _BLOCKED

                def _sandbox_audit_hook(_event: str, _args: object) -> None:
                    for _prefix in _AUDIT_PREFIXES:
                        if _event == _prefix or _event.startswith(_prefix):
                            raise RuntimeError(
                                f"sandbox-harness: blocked runtime event '{{_event}}'"
                            )

                    # -------------------------------------------------------------
                    # Network explicitly dead-ended
                    # -------------------------------------------------------------
                    if _event in ("socket.connect", "socket.bind", "socket.socket", "urllib.Request"):
                        raise RuntimeError("sandbox-harness: network access is hard-blocked")

                    if _event == "import" and len(_args) >= 1:
                        _mod_to_import = _args[0]
                        if isinstance(_mod_to_import, str):
                            _top_mod = _mod_to_import.split(".")[0]
                            if _top_mod in _BLOCKED_TOP_LEVEL:
                                raise RuntimeError(f"sandbox-harness: blocked import of '{{_mod_to_import}}' via audit hook")

                    _is_write = False
                    _is_open = False
                    _path_arg = None

                    if _event == "open" and len(_args) >= 3:
                        _is_open = True
                        _mode = _args[1]
                        _flags = _args[2]
                        if isinstance(_mode, str):
                            if "w" in _mode or "a" in _mode or "+" in _mode or "x" in _mode:
                                _is_write = True
                                _path_arg = _args[0]
                            elif "r" in _mode:
                                _path_arg = _args[0]
                        elif isinstance(_flags, int):
                            if (_flags & 3) != 0 or (_flags & 64) or (_flags & 256) or (_flags & 512) or (_flags & 1024):
                                _is_write = True
                                _path_arg = _args[0]
                            else:
                                _path_arg = _args[0]
                    elif _event in ("os.remove", "os.rename", "os.rmdir", "os.mkdir", "os.truncate"):
                        _is_write = True
                        _path_arg = _args[0] if _args else None

                    if _path_arg:
                        try:
                            _path = _os.path.abspath(_os.fsdecode(_path_arg))
                            if _is_write:
                                if not _path.startswith(_LOCAL_JAIL_DIR):
                                    raise RuntimeError(f"sandbox-harness: blocked write to '{{_path}}' outside jail")
                            else:
                                # Read access validation
                                if not (_path.startswith(_LOCAL_JAIL_DIR) or _path.startswith(_LOCAL_PY_PREFIX) or _path.startswith(_LOCAL_PY_BASE_PREFIX) or _LOCAL_WIN_DIR.lower() in _path.lower()):
                                    raise RuntimeError(f"sandbox-harness: blocked read access to unauthorized path '{{_path}}'")
                        except Exception as e:
                            if "sandbox-harness" in str(e):
                                raise
                            raise RuntimeError("sandbox-harness: blocked invalid path access")

                    if _event == "os.rename" and len(_args) >= 2:
                        try:
                            _path2 = _os.path.abspath(_os.fsdecode(_args[1]))
                            if not _path2.startswith(_LOCAL_JAIL_DIR):
                                raise RuntimeError(f"sandbox-harness: blocked rename destination '{{_path2}}' outside jail")
                        except Exception:
                            raise RuntimeError("sandbox-harness: blocked invalid path access")

                return _sandbox_audit_hook

            _sys.addaudithook(_create_audit_hook())

        _namespace: dict[str, object] = {{
            "__builtins__": _restricted_builtins,
            "__name__": "__main__",
            "__file__": _target,
        }}

        # Clear all harness globals to completely defeat Traceback frame walking
        _KEEP = ('__builtins__', '__name__', '__file__', '__doc__', '_code_obj', '_namespace')
        for _k in list(globals().keys()):
            if _k not in _KEEP:
                del globals()[_k]

        exec(_code_obj, _namespace)
    """)


HARNESS_FILENAME: Final[str] = "_sandbox_harness.py"

__all__ = [
    "HARNESS_FILENAME",
    "generate_harness_script",
]
