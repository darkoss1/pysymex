"""
Extreme test case with deep path explosion for timing comparison.
Designed to stress test symbolic execution engines.
"""


def _safe_floor_div(numerator: int, denominator: int) -> int:
    if denominator == 0:
        return 0
    return numerator // denominator


def deep_nested_conditionals(a: int, b: int, c: int, d: int, e: int, f: int, g: int, h: int) -> int:
    """
    8-way nested conditionals - exponential path explosion (2^8 = 256 paths).
    
    pre: True
    post: __return__ >= 0
    """
    score = 0
    if a > 0:
        score += 1
        if b > 0:
            score += 2
            if c > 0:
                score += 3
                if d > 0:
                    score += 5
                    if e > 0:
                        score += 8
                        if f > 0:
                            score += 13
                            if g > 0:
                                score += 21
                                if h > 0:
                                    score += 34
    return score


def nested_loops_with_conditions(matrix: list[list[int]], threshold: int) -> int:
    """
    Nested loops with conditions - cubic complexity with symbolic bounds.
    
    pre: len(matrix) >= 0 and threshold >= 0
    post: __return__ >= 0
    """
    total = 0
    for row in matrix:
        for cell in row:
            if isinstance(cell, list):
                for item in cell:
                    if item > threshold:
                        total += item
            elif cell > threshold:
                total += cell
    return total


def recursive_tree_depth(n: int, branching: int, depth: int) -> int:
    """
    Recursive tree traversal with configurable branching factor.
    Path explosion: branching^depth
    
    pre: n >= 0 and branching >= 2 and depth >= 0
    post: __return__ >= 0
    """
    if depth <= 0 or n <= 0:
        return max(0, n)
    if branching < 1:
        return 0
    total = 0
    for _ in range(branching):
        total += recursive_tree_depth(n - 1, branching, depth - 1)
    return total


def state_machine_transitions(state: int, inputs: list[int]) -> int:
    """
    State machine with many transitions - combinatorial explosion.
    
    pre: state >= 0 and len(inputs) >= 0
    post: __return__ >= 0
    """
    current_state = state
    for i, inp in enumerate(inputs):
        if current_state == 0:
            if inp > 0:
                current_state = 1
            elif inp < 0:
                current_state = 2
            else:
                current_state = 0
        elif current_state == 1:
            if inp > 10:
                current_state = 3
            elif inp < -10:
                current_state = 4
            else:
                current_state = 1
        elif current_state == 2:
            if inp % 2 == 0:
                current_state = 5
            else:
                current_state = 6
        elif current_state == 3:
            if i == len(inputs) - 1:
                return current_state
            current_state = 0
        elif current_state == 4:
            if i > 5:
                return current_state
            current_state = 1
        elif current_state == 5:
            current_state = 2
        else:  # state 6
            current_state = 0
    return current_state


def complex_string_pattern_matching(text: str, patterns: list[str]) -> int:
    """
    String pattern matching with multiple patterns - combinatorial explosion.
    
    pre: True
    post: __return__ >= 0
    """
    count = 0
    for pattern in patterns:
        if not pattern:
            continue
        start = 0
        while True:
            found_at = text.find(pattern, start)
            if found_at < 0:
                break
            count += 1
            start = found_at + 1
    return count


def interdependent_array_operations(arr: list[int], ops: list[str]) -> list[int]:
    """
    Array operations with interdependent conditions.
    
    pre: len(arr) >= 0 and len(ops) >= 0
    post: len(__return__) == len(arr) or len(__return__) == 1
    """
    updated: list[int] = []
    ops_iter = iter(ops)
    for value in arr:
        op = next(ops_iter, None)
        if op == "add":
            updated.append(value + 1)
        elif op == "sub":
            updated.append(max(0, value - 1))
        elif op == "mul":
            updated.append(value * 2)
        elif op == "div":
            updated.append(_safe_floor_div(100, value))
        else:
            updated.append(value)
    return updated


def symbolic_matrix_multiplication(A: list[list[int]], B: list[list[int]]) -> list[list[int]]:
    """
    Matrix multiplication with symbolic dimensions.
    
    pre: len(A) > 0 and len(B) > 0
    post: True
    """
    if not A or not B or not B[0]:
        return []
    if any(len(row) != len(A[0]) for row in A):
        return []
    if any(len(row) != len(B[0]) for row in B):
        return []
    if len(A[0]) != len(B):
        return []
    result = []
    columns = list(zip(*B))
    for row_a in A:
        out_row = []
        for col_b in columns:
            out_row.append(sum(a_val * b_val for a_val, b_val in zip(row_a, col_b)))
        result.append(out_row)
    return result


def deep_recursion_with_memoization(n: int, memo: dict[int, int] | None = None) -> int:
    """
    Deep recursion with memoization - can still explode without proper memo.
    
    pre: n >= 0
    post: __return__ >= 0
    """
    if memo is None:
        memo = {}
    if n in memo:
        return memo[n]
    if n <= 1:
        return max(0, n)
    result = deep_recursion_with_memoization(n - 1, memo) + deep_recursion_with_memoization(n - 2, memo)
    memo[n] = result
    return result


def complex_condition_chain(x: int, y: int, z: int, w: int, v: int, u: int, t: int, s: int, r: int, q: int) -> int:
    """
    Chain of 10 interdependent conditions.
    
    pre: True
    post: __return__ >= 0
    """
    score = 0
    if x + y == 100:
        score += 1
        if y + z == 50:
            score += 2
            if z + w == 25:
                score += 3
                if w + v == 12:
                    score += 5
                    if v + u == 6:
                        score += 8
                        if u + t == 3:
                            score += 13
                            if t + s == 1:
                                score += 21
                                if s + r == 0:
                                    score += 34
                                    if r + q == 0:
                                        score += 55
    return score


def symbolic_graph_traversal(adjacency: dict[int, list[int]], start: int, target: int) -> bool:
    """
    Graph traversal with symbolic graph structure.
    
    pre: start >= 0 and target >= 0
    post: isinstance(__return__, bool)
    """
    visited = set()
    stack = [start]
    while stack:
        node = stack.pop()
        if node == target:
            return True
        if node in visited:
            continue
        visited.add(node)
        if node in adjacency:
            for neighbor in adjacency[node]:
                if neighbor not in visited:
                    stack.append(neighbor)
    return False
