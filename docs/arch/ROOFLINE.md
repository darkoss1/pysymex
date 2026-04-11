# Roofline And Guardrails

This document defines performance guardrails for CHTD hardware acceleration and backend routing.

## Goals

- Keep backend selection deterministic and safe under constrained VRAM.
- Prevent regressions by tracking kernel-time trends and routing behavior.
- Preserve semantic parity across GPU, CPU, and reference backends.

## Routing Model

Runtime routing estimates total backend cost as:

$$
\text{cost}_{backend} \approx \text{compute}_{baseline} + \text{transfer}_{estimate}
$$

Where:

- `compute_baseline` is derived from `constraint.num_states * instruction_count` and backend throughput estimate.
- `transfer_estimate` applies to GPU only and uses the compiled constraint memory footprint.
- historical EWMA latency is blended in to adapt to observed runtime behavior.

## Memory Guardrails

For GPU routing, we apply a VRAM-aware max treewidth estimate using:

- `estimate_max_treewidth(device_memory_mb)` from [pysymex/accel/memory.py](../../pysymex/accel/memory.py)
- if a constraint exceeds this bound, dispatcher routes to CPU/reference fallback

This guardrail avoids out-of-memory behavior and keeps routing stable across devices.

## Telemetry Fields

The dispatcher exposes routing telemetry via `get_routing_stats()`:

- `selected_backend`
- `forced_backend`
- `routing_decisions`
- `latency_ewma_ms`
- `guardrail_fallbacks`

The executor exposes CHTD phase telemetry under:

- `ExecutionResult.solver_stats["chtd"]["phase_timers_seconds"]`
- `ExecutionResult.solver_stats["chtd"]["phase_counts"]`

## Recommended CI Checks

- Routing decisions should include at least one non-reference backend on acceleration-capable runners.
- `guardrail_fallbacks` should stay near zero for expected benchmark workloads.
- CHTD phase timers should be present and non-negative in benchmark output.
- Median wall time regression threshold should remain under 15% for fixed benchmark matrix.

