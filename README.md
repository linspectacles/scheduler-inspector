# Scheduler Inspector

**Expose. Explore. Explain.**

Scheduler Inspector is a read-only Linux CPU scheduler inspector for per-thread scheduling policy/affinity, scheduler accounting, per-CPU schedstat state, scheduling domains and global sched_ext/scheduler context.

Current release: **0.0.8**

Repository: <https://github.com/linspectacles/scheduler-inspector>

<p align="center">
  <a href="https://github.com/brunonlinespace/brunonlinespace/blob/main/linspectacles/scheduler-inspector.png">
    <img
      src="https://raw.githubusercontent.com/brunonlinespace/brunonlinespace/main/linspectacles/scheduler-inspector.png"
      alt="Scheduler Inspector screenshot"
      width="900"
    >
  </a>
</p>

## What Scheduler Inspector is

Scheduler Inspector answers: **under what scheduling rules are threads competing for CPU, and what cumulative scheduler state does the kernel report?**

The applet intentionally reports cumulative scheduler counters and policy state rather than manufacturing CPU-utilisation rates from one snapshot. Thread, CPU and scheduler-domain views remain separate because they answer different scheduler questions.

## Highlights

- **Threads** view with TID/PID/process/user identity, policy, priority/nice and CPU affinity.
- Cumulative per-thread runtime, runqueue wait and timeslices from `/proc/<tid>/schedstat`.
- Deadline and utilization-clamp attributes where exposed through scheduler APIs.
- Limited cgroup and `sched_ext` thread context where exposed.
- **CPUs** view from version-aware `/proc/schedstat`.
- Per-CPU cumulative schedule, idle-schedule, wakeup, runtime, wait and slice state where available.
- **Domains** view with CPU spans and load-balancing counters.
- Version 17 schedstat domains are decoded; unknown/older formats retain raw counters instead of guessing.
- **Scheduler Details…** for global schedstats, RT bandwidth/timeslice, utilization-clamp and sched_ext context.
- No scheduler mutation, tracing, eBPF loading or background sampling.

## Views

### Threads

Threads are enumerated through `/proc/<pid>/task/*`. Scheduling policy/priority and affinity use direct scheduler APIs where possible, with procfs providing identity, accounting and fallback/context information.

### CPUs and Domains

`/proc/schedstat` provides versioned cumulative per-CPU and scheduler-domain information. The parser treats format version as meaningful: known fields are decoded when the format is understood, while unsupported formats remain raw rather than receiving speculative labels.

### Scheduler Details

A separate read-only dialog exposes global scheduler context from sources such as `/proc/sys/kernel/sched_*`, `/sys/kernel/sched_ext/*` and CPU online/possible state where available. It is not a fourth inventory.

## Data sources

Important sources include:

- scheduler APIs such as `sched_getaffinity()`
- `/proc/<pid>/task/*`
- `/proc/<tid>/schedstat`, `status`, `stat`, `comm` and `cgroup`
- `/proc/schedstat`
- selected `/proc/sys/kernel/sched_*` runtime state
- `/sys/kernel/sched_ext/*` where exposed
- `/sys/devices/system/cpu/{online,possible}`

## Interface and export

The active view, each view’s search/filter state, column widths and sort order are persisted. Filtering keeps the selected record when still visible; otherwise selection and Metadata Details are rebuilt from a valid visible row. Options provides Appearance, Sources, Export and About.

## Read-only guarantees

Scheduler Inspector does not change affinity, nice/priority, RT policy, cgroups or sched_ext state. It does not load eBPF, use perf/debugfs tracing, calculate rates or run a background monitor.

## Useful keyboard shortcuts

| Command | Shortcut |
| --- | --- |
| Show / hide Metadata Details | `F3` |
| Toggle Horizontal / Vertical details layout | `Ctrl+L` |
| Refresh active inventory / snapshot | `Shift+F5` |
| Options | `Ctrl+/` |

The in-application interface remains authoritative for context-specific actions that do not have a global shortcut.

## Running from source

The current source is directly runnable on Linux. Runtime requirements are deliberately kept separate from distribution packaging:

- Python 3.
- PyQt6 for the graphical interface.
- Linux with procfs; some scheduler attributes/context depend on kernel version and interfaces exposed by the running system.

A local virtual environment is a straightforward way to run the applet without installing its Python GUI dependency into the system Python environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install PyQt6
python3 linspectacles_scheduler_inspector/standalone.py
```

If PyQt6 is already provided by the Python environment you intend to use, the virtual-environment step is optional.

The standalone launcher is the canonical direct source entrypoint in this source package.

## LinSpectacles Hub

This applet can run independently, but it can also be installed and used inside **[LinSpectacles Hub](https://github.com/linspectacles/linspectacles-hub)**.

LinSpectacles Hub is the optional workbench for the LinSpectacles applet family. It provides shared applet discovery, navigation and management while each inspector remains independently runnable.

To install a portable or user applet through the Hub, open **Configuration... → Applets** and add the applet ZIP. Once discovered, the applet can be enabled and opened from the Hub navigation.

System-installed applets are discovered by the Hub from its system applet store and remain managed by the system package manager.

## Source layout and LinSpectacles integration

The applet source is contained in:

```text
linspectacles_scheduler_inspector/
├── __init__.py
├── standalone.py
├── LICENSE
├── applet.json
├── README.md
└── scheduler_inspector/
    ├── README.md
    ├── _support.py
    ├── applet.py
    ├── icon.png
    └── scheduler_data.py
```

`applet.json` provides the LinSpectacles applet identity and entrypoint metadata, while `create_applet()` in `applet.py` provides the host-loadable widget factory. `standalone.py` launches the same applet as an independent window.

## Configuration

UI preferences are stored through Qt `QSettings` under the `brunonlinespace` organisation and the applet’s application name. The exact persisted presentation fields depend on the applet, but are limited to UI/inspection presentation state such as view/filter choices, columns, sorting, splitter/layout state and Metadata Details where implemented.

The applet does not use configuration persistence as a path to modify the inspected Linux subsystem.

## Scope

Scheduler Inspector owns scheduler policy/accounting/domain state. Hardware topology, cgroup controller state and live CPU utilisation remain separate LinSpectacles concerns.

## License

GNU General Public License v3.0 or later. See [`LICENSE`](LICENSE).

## Links

- LinSpectacles organisation: <https://github.com/linspectacles/>
- LinSpectacles Hub: <https://github.com/linspectacles/linspectacles-hub>
- Repository: <https://github.com/linspectacles/scheduler-inspector>
- Issues: <https://github.com/linspectacles/scheduler-inspector/issues>

<p align="center">
  <a href="https://github.com/linspectacles/scheduler-inspector">
    <img
      src="scheduler_inspector/icon.png"
      alt="Scheduler Inspector"
      width="256"
    >
  </a>
</p>
