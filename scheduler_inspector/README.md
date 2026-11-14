# Scheduler Inspector 0.0.8

Read-only LinSpectacles applet for the running Linux CPU scheduler.

## Job

**Under what scheduling rules are threads competing for CPU, and what cumulative scheduler state does the kernel report?**

## Views

- **Threads** — thread identity, scheduling policy/class, nice or RT priority, CPU affinity, cumulative scheduler runtime/runqueue-wait/timeslices, deadline/uclamp attributes where exposed, and limited cgroup/sched_ext context.
- **CPUs** — version-aware `/proc/schedstat` per-CPU cumulative schedule/wakeup/runtime/wait/slice counters where available.
- **Domains** — scheduler-domain CPU spans and version-aware load-balancing counters; version 17 is decoded, unknown/older formats retain raw counters rather than guessing.
- **Scheduler Details…** — read-only global scheduler context including schedstats enablement, RT bandwidth/timeslice settings, utilization-clamp bounds, and sched_ext status/events where exposed.

## Shortcuts

- `F3` — show/hide Metadata Details
- `Ctrl+L` — Horizontal/Vertical layout
- `Shift+F5` — refresh the active inventory
- `Ctrl+/` — Options

## Boundaries

No CPU-utilization rates, background sampling, tracing, eBPF loading, perf, debugfs dependency, scheduler-control commands, affinity/nice/priority mutation, cgroup writes, sched_ext loading, or generic hardware-topology ownership.

## UI state

The active view, each view's search/filter state, column widths, and sort column/direction are persisted. Filtering preserves the selected record when it remains visible; otherwise the first valid visible record is selected and Metadata Details is rebuilt explicitly.
