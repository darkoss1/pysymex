"""Contract verification probe — mixed scenarios for manual ``pysymex contracts`` runs.

Run one function:

    python -m pysymex contracts examples/09_contracts_probe.py -f transfer \\
        --args balance:int amount:int

Or run the bundled harness:

    python examples/09_contracts_probe.py
"""

from __future__ import annotations

from pysymex.contracts import assigns, ensures, pure, requires


@requires("amount > 0")
@requires("balance >= amount")
@ensures("result() == old(balance) - old(amount)")
def transfer(balance: int, amount: int) -> int:
    """Simple scalar postcondition with ``old()`` — should verify."""
    return balance - amount


@requires("x >= 0")
@ensures("result() >= x")
def broken_increment(x: int) -> int:
    """Postcondition violated on feasible paths — should report violation."""
    if x == 3:
        return x - 1
    return x + 1


@requires("base > 0")
@ensures("result() > base")
def scale(base: int, factor: int) -> int:
    """Call-site precondition on nested helper — mixed nested obligations."""
    return base * _positive_double(factor)


@requires("value > 0")
@ensures("result() == value + value")
def _positive_double(value: int) -> int:
    return value + value


_counter = 0


@pure
@ensures("result() >= 0")
def read_counter() -> int:
    """``@pure`` should reject hidden mutation."""
    global _counter
    _counter += 1
    return _counter


@assigns()
@requires("x >= 0")
@ensures("result() == x")
def identity_no_writes(x: int) -> int:
    """Empty ``@assigns`` with only locals — should verify."""
    return x


def _run_harness() -> None:
    from pysymex._internal.execution.executors.verified.api import verify

    cases: list[tuple[str, object, dict[str, str]]] = [
        ("transfer", transfer, {"balance": "int", "amount": "int"}),
        ("broken_increment", broken_increment, {"x": "int"}),
        ("scale", scale, {"base": "int", "factor": "int"}),
        ("read_counter", read_counter, {}),
        ("identity_no_writes", identity_no_writes, {"x": "int"}),
    ]

    print("=== PySyMex contract probe ===")
    for name, func, symbolic_args in cases:
        result = verify(func, symbolic_args=symbolic_args, max_paths=100, max_iterations=1000)
        print(f"\n--- {name} ---")
        print(f"  paths_explored: {result.paths_explored}")
        print(f"  contracts_verified: {result.contracts_verified}")
        print(f"  contract_issues: {len(result.contract_issues)}")
        for issue in result.contract_issues[:5]:
            print(f"    [{issue.result.name}] {issue.message}")
        if len(result.contract_issues) > 5:
            print(f"    ... +{len(result.contract_issues) - 5} more")


if __name__ == "__main__":
    _run_harness()
