from __future__ import annotations

import ast
from pathlib import Path

from pysymex.contracts.decorators import (
    assigns,
    assumes,
    ensures,
    get_function_contract,
    invariant,
    loop_invariant,
    pure,
    requires,
)
from pysymex.contracts.types import ContractKind, EffectKind


_CONTRACT_DECORATORS = {"requires", "ensures", "invariant", "pure", "assumes", "assigns"}


def _decorator_name(node: ast.expr) -> str | None:
    target = node.func if isinstance(node, ast.Call) else node
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return None


class TestDecorators:
    """Test suite for contracts/decorators.py."""

    def test_requires_decorator(self) -> None:
        """Verify that requires decorator creates a contract and adds a precondition."""

        @requires("x > 0")
        def my_func(x: int) -> int:
            return x

        contract = get_function_contract(my_func)
        assert contract is not None
        assert len(contract.preconditions) == 1
        assert contract.preconditions[0].kind == ContractKind.REQUIRES

    def test_ensures_decorator(self) -> None:
        """Verify that ensures decorator adds a postcondition."""

        @ensures("result() > 0")
        def my_func2(x: int) -> int:
            return x + 1

        contract = get_function_contract(my_func2)
        assert contract is not None
        assert len(contract.postconditions) == 1
        assert contract.postconditions[0].kind == ContractKind.ENSURES

    def test_invariant_decorator(self) -> None:
        """Verify that invariant decorator adds to class __invariants__."""

        @invariant("self.x > 0")
        class MyClass:
            pass

        invariants = getattr(MyClass, "__invariants__", None)
        assert invariants is not None
        assert len(invariants) == 1
        assert invariants[0].kind == ContractKind.INVARIANT

    def test_assumes_decorator(self) -> None:
        """Verify that assumes decorator adds an assumption."""

        @assumes("True")
        def my_func3() -> None:
            pass

        contract = get_function_contract(my_func3)
        assert contract is not None
        assert len(contract.assumptions) == 1
        assert contract.assumptions[0].kind == ContractKind.ASSUMES

    def test_assigns_decorator(self) -> None:
        """Verify that assigns decorator sets the assigns frozenset."""

        @assigns("self.x", "self.y")
        def my_func4() -> None:
            pass

        contract = get_function_contract(my_func4)
        assert contract is not None
        assert contract.assigns_set == frozenset({"self.x", "self.y"})

    def test_pure_decorator(self) -> None:
        """Verify that pure decorator sets effect type to PURE."""

        @pure
        def my_func5() -> int:
            return 1

        contract = get_function_contract(my_func5)
        assert contract is not None
        assert contract.effect_type == EffectKind.PURE

    def test_loop_invariant_helper(self) -> None:
        """Verify that loop_invariant returns a Contract object."""
        contract = loop_invariant("i < 10")
        assert contract.kind == ContractKind.LOOP_INVARIANT

    def test_get_function_contract(self) -> None:
        """Verify that get_function_contract retrieves the contract."""

        def undecorated() -> None:
            pass

        @requires("True")
        def decorated() -> None:
            pass

        assert get_function_contract(undecorated) is None
        assert get_function_contract(decorated) is not None

    def test_contract_verifier_package_export_is_lazy(self) -> None:
        """Verify the public package export works without eager solver import cycles."""
        from pysymex.contracts import ContractVerifier

        assert ContractVerifier.__name__ == "ContractVerifier"

    def test_production_contract_coverage_has_required_sites(self) -> None:
        """Verify production contract hardening keeps at least 50 meaningful sites."""
        repo_root = Path(__file__).resolve().parents[3]
        paths = [
            repo_root / "pysymex" / "accel" / "core_index.py",
            repo_root / "pysymex" / "accel" / "evaluator.py",
            repo_root / "pysymex" / "accel" / "types.py",
            repo_root / "pysymex" / "accel" / "worker.py",
            repo_root / "pysymex" / "core" / "solver" / "constraints.py",
            repo_root / "pysymex" / "core" / "solver" / "learner.py",
            repo_root / "pysymex" / "core" / "solver" / "unsat.py",
        ]

        decorated_functions = 0
        for path in paths:
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    names = {_decorator_name(decorator) for decorator in node.decorator_list}
                    if names & _CONTRACT_DECORATORS:
                        decorated_functions += 1

        assert decorated_functions >= 50
