# Precision Matrix Regression Suite

This suite runs 48 adversarial source files through the real `scan_file` pipeline. It contains 24
known-positive exception cases and 24 known-safe controls across arithmetic, strings, containers,
exceptions, loops, generators, and context managers.

The manifest is a test oracle only. Scanner execution receives the case path and scan budgets; it
never receives labels, categories, or expected issue kinds. Positive cases count as detected only
when the scanner emits the expected issue family. Any issue emitted for a negative case counts as a
false positive.

Run the matrix with:

```bash
uv run pytest tests/regression/precision_matrix/test_precision_matrix.py -q -s
```

The current regression floor covers every positive and safe case:

```text
TP >= 24
FN == 0
FP == 0
TN >= 24
```

The original generated baseline was `TP=19`, `FP=0`, `TN=24`, `FN=5`.

The generated `p03` fixture originally divided by `x - 5`, while its guards uniquely implied
`x == 7`; that version was safe. The permanent fixture uses the intended `x - 7` denominator and
the engine produces a solver witness `x=7, y=5` without special-case logic.

The generated `p04` fixture originally required `y % 5 == 2`, which made `x - 10 == 0`
impossible under `x + y == 19`. The permanent fixture uses the intended remainder `4`; the engine
produces a solver witness `x=10, y=9` through its existing integer modulo encoding.

The generated `p23` checksum was `650`, while the pinned witness `"ABCD"` has weighted checksum
`670`. The permanent fixture uses `670`; bounded equality-derived concrete preflight executes the
fully pinned short string before reporting the division by zero.

The generated `p24` low-byte constant was `0x83`, while the pinned witness `"AZ"` evaluates to
`0x19`. The permanent fixture uses `0x19`; the existing bounded bitvector encoding reports a
solver-backed witness and the safe pair remains clean.

Latest verified matrix on Python 3.12.13: `TP=24`, `FP=0`, `TN=24`, `FN=0`, precision, recall,
accuracy, and F1 all `1.000`, wall time `13.101s`.

An absent issue on a degraded or bounded scan is a benchmark observation, not a proof of safety.
The harness prints degraded passes so precision work cannot silently hide incomplete analysis.
