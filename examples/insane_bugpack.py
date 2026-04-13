"""Real-world scan bug pack used by benchmark validation.

Each function intentionally contains a bug that should be detectable.
"""


def bug_div_zero(x: int, y: int) -> int:
    if x > 10 and y < 0:
        return 1 // (x - x)
    return x + y


def bug_index_error(i: int, j: int) -> int:
    arr = [3, 5, 8]
    k = i + j
    if i > 2 and j > 2:
        return arr[k]
    return arr[0]


def bug_null_attr(v: int) -> int:
    maybe = None
    if v > 100:
        return maybe.missing  # type: ignore[attr-defined]
    return v


def level1_branch_div(a: int, b: int, c: int) -> int:
    score = 0
    if a > 0:
        score += 1
    else:
        score -= 1
    if b > 0:
        score += 2
    else:
        score -= 2
    if c > 0 and score > 0:
        return 10 // (score - score)
    return score


def level2_branch_index(a: int, b: int, c: int, d: int) -> int:
    arr = [2, 4, 6, 8]
    idx = 0
    if a > 3:
        idx += a
    if b > 3:
        idx += b
    if c > 3:
        idx += c
    if d > 3:
        idx += d
    if a > 3 and b > 3 and c > 3 and d > 3:
        return arr[idx]
    return arr[0]


def level3_branch_null(a: int, b: int, c: int, d: int, e: int) -> int:
    obj = None
    gate = 0
    for val in (a, b, c, d, e):
        if val > 1:
            gate += 1
        else:
            gate -= 1
    if gate >= 5:
        return obj.value  # type: ignore[attr-defined]
    return gate


def level4_nested_div(a: int, b: int, c: int, d: int, e: int, f: int) -> int:
    acc = 0
    for i in range(3):
        if a + i > b:
            acc += i + c
        else:
            acc -= i + d
        if e - i > f:
            acc += 2
        else:
            acc -= 2

    if a > 10 and b > 10 and c > 10 and d > 10 and e > 10 and f > 10:
        return 50 // (acc - acc)
    return acc


def level5_fanout_index(a: int, b: int, c: int, d: int, e: int, f: int, g: int) -> int:
    arr = [1, 3, 5]
    idx = 0
    for v in (a, b, c, d, e, f, g):
        if v > 4:
            idx += v
        else:
            idx -= 1
    if all(v > 4 for v in (a, b, c, d, e, f, g)):
        return arr[idx]
    return arr[1]


def insane_level_path_explosion(
    a: int,
    b: int,
    c: int,
    d: int,
    e: int,
    f: int,
    g: int,
    h: int,
) -> int:
    """Intentionally branch-heavy with a deep bug trigger."""
    s = 0
    if a > 0:
        s += a
    else:
        s -= a
    if b > 1:
        s += b
    else:
        s -= b
    if c > 2:
        s += c
    else:
        s -= c
    if d > 3:
        s += d
    else:
        s -= d
    if e > 4:
        s += e
    else:
        s -= e
    if f > 5:
        s += f
    else:
        s -= f
    if g > 6:
        s += g
    else:
        s -= g
    if h > 7:
        s += h
    else:
        s -= h

    if a > 20 and b > 20 and c > 20 and d > 20 and e > 20 and f > 20 and g > 20 and h > 20:
        ptr = None
        return ptr.boom  # type: ignore[attr-defined]

    return s
