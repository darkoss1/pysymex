# Reports

Reporting presents evidence produced by scanning, execution, detectors, contracts, resources, and
the solver. It should not reinterpret a partial or inconclusive analysis as successful
verification.

## Method

1. Execution and scanning produce structured results.
2. Issue sinks normalize detector output into JSON-safe records.
3. Formatters render text, rich terminal, JSON, HTML, Markdown, SARIF, realtime, and reproduction
   views.
4. CLI command layers choose output format and exit behavior.
5. Diagnostic logs record solver uncertainty, degraded passes, sandbox failures, and lifecycle
   events where observability matters.

Reusable reporting modules own structured formatting and aggregate counters. CLI reporters own
interactive scan progress, status lines, and terminal summaries; scanner modules provide those
events only through the `pysymex._internal.scanner.protocols.ScanReporter` protocol.

## Report Contract

Reports should preserve:

- issue kind and message,
- source location and bytecode offset where available,
- counterexample or triggering input when present,
- path and resource statistics,
- solver statistics,
- fatal scan errors,
- degraded passes,
- sandbox and setup failures when they affect analysis.

No presentation layer should turn `degraded_passes`, sandbox denial, solver `UNKNOWN`, or timeout
into a clean safety claim.

## Formats

| Format | Purpose |
| --- | --- |
| Text and rich | Human terminal output. |
| JSON | Machine-readable scan and execution records. |
| HTML | Standalone browser report with issues and resource metrics. |
| Markdown | Documentation-friendly summaries. |
| SARIF | CI/code-scanning integration. |
| Realtime | Live scan and execution views. |
| Reproduction | Re-run oriented output data. |

## Evidence In Source

- Execution result formatting: `pysymex/_internal/reporting/formatters`
- CLI formatters: `pysymex/_internal/cli/formatters`
- SARIF: `pysymex/_internal/reporting/sarif`
- HTML: `pysymex/_internal/reporting/html`
- Scanner result types: `pysymex/_internal/scanner/types.py`
- Tests: `tests/unit/reporting`, `tests/unit/cli`

## Limits

General report generation should depend on structured result data, not teach execution result
models about presentation-specific methods.
