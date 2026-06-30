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

from __future__ import annotations

import textwrap

_CONTRACT_SOURCE_TEMPLATE = r"""        class _EnumValue:
            def __init__(self, name):
                self.name = name

        class _SandboxSeverity:
            ERROR = _EnumValue("ERROR")
            WARNING = _EnumValue("WARNING")

        class _SandboxContractClause:
            def __init__(self, kind, predicate, message, severity, line_number):
                self.kind = _EnumValue(kind)
                self.predicate = predicate
                self.message = message
                self.severity = severity
                self.line_number = line_number
                if isinstance(predicate, str):
                    self.condition = predicate
                else:
                    self.condition = getattr(
                        predicate,
                        "__qualname__",
                        getattr(predicate, "__name__", repr(predicate)),
                    )

        class _SandboxFunctionContract:
            def __init__(self, function_name):
                self.function_name = function_name
                self.preconditions = []
                self.postconditions = []

        def _get_or_create_contract(func):
            contract = getattr(func, "__contract__", None)
            if contract is None:
                contract = _SandboxFunctionContract(getattr(func, "__name__", "<unknown>"))
                setattr(func, "__contract__", contract)
            return contract

        def _requires(predicate, message=None, *, severity=_SandboxSeverity.ERROR):
            def decorator(func):
                contract = _get_or_create_contract(func)
                condition = predicate if isinstance(predicate, str) else "<callable>"
                contract.preconditions.append(
                    _SandboxContractClause(
                        "REQUIRES",
                        predicate,
                        message or f"Precondition: {{condition}}",
                        severity,
                        None,
                    )
                )
                return func
            return decorator

        def _ensures(predicate, message=None, *, severity=_SandboxSeverity.ERROR):
            def decorator(func):
                contract = _get_or_create_contract(func)
                condition = predicate if isinstance(predicate, str) else "<callable>"
                contract.postconditions.append(
                    _SandboxContractClause(
                        "ENSURES",
                        predicate,
                        message or f"Postcondition: {{condition}}",
                        severity,
                        None,
                    )
                )
                return func
            return decorator

        def _identity_contract_decorator(*_args, **_kwargs):
            def decorator(obj):
                return obj
            return decorator

        _fake_pysymex = types.ModuleType("pysymex")
        _fake_contracts = types.ModuleType("pysymex.contracts")
        _fake_contracts_decorators = types.ModuleType("pysymex._internal.contracts.decorators")
        _fake_contracts_types = types.ModuleType("pysymex._internal.contracts.types")
        for _mod in (_fake_contracts, _fake_contracts_decorators):
            _mod.requires = _requires
            _mod.ensures = _ensures
            _mod.assumes = _identity_contract_decorator
            _mod.assigns = _identity_contract_decorator
            _mod.invariant = _identity_contract_decorator
            _mod.loop_invariant = _identity_contract_decorator
            _mod.pure = lambda obj: obj
            _mod.ContractSeverity = _SandboxSeverity
        _fake_contracts_types.ContractSeverity = _SandboxSeverity
        _fake_contracts.decorators = _fake_contracts_decorators
        _fake_contracts.types = _fake_contracts_types
        _fake_pysymex.contracts = _fake_contracts
        _FAKE_MODULES = {{
            "pysymex": _fake_pysymex,
            "pysymex.contracts": _fake_contracts,
            "pysymex._internal.contracts.decorators": _fake_contracts_decorators,
            "pysymex._internal.contracts.types": _fake_contracts_types,
        }}

        def _contract_aware_import(name, globals=None, locals=None, fromlist=(), level=0):
            if level == 0 and name in _FAKE_MODULES:
                return _FAKE_MODULES[name] if fromlist else _fake_pysymex
            return getattr(builtins, _IMPORT_ATTR)(name, globals, locals, fromlist, level)

        def _target_builtins():
            data = dict(vars(builtins))
            data[_IMPORT_ATTR] = _contract_aware_import
            return data
"""


def module_contract_source() -> str:
    """Render worker-side stand-ins for supported contract decorators.

    Returns:
        Python source that defines minimal contract/severity carriers, maps
        selected `pysymex.contracts` imports to those carriers, and provides a
        builtins dictionary using the contract-aware importer.

    Limitations:
        The generated source captures contract metadata for module extraction;
        it does not implement full runtime contract enforcement.

    """
    return textwrap.dedent(_CONTRACT_SOURCE_TEMPLATE).strip().replace("{{", "{").replace("}}", "}")
