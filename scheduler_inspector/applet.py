#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles - Linux Inspection Suite
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

APPLET_ID = "linspectacles-scheduler-inspector"
APPLET_NAME = "Scheduler Inspector"
APPLET_VERSION = "0.0.8"
APPLET_AUTHOR = "brunonlinespace"

from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import QSettings, Qt, QUrl
from PyQt6.QtGui import QColor, QKeySequence, QPixmap, QShortcut, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ._support import BaseInspectorTab, NumericTableWidgetItem, export_records_dialog, metadata_font_qss
from .scheduler_data import (
    POLICY_NAMES,
    collect_scheduler_details,
    collect_schedstat,
    collect_threads,
    decode_domain_v17,
    format_ns,
)


_VIEW_ORDER = ("threads", "cpus", "domains")
_VIEW_SPECS = {
    "threads": {
        "label": "Threads",
        "counter": "Total Threads",
        "columns": [
            ("tid", "TID", 90, "right"),
            ("process", "Process", 190, "left"),
            ("pid", "PID", 90, "right"),
            ("user", "User", 130, "left"),
            ("policy", "Policy", 140, "left"),
            ("priority_nice", "Priority / Nice", 135, "left"),
            ("affinity", "Affinity", 145, "left"),
            ("runtime", "Runtime", 120, "right"),
            ("wait", "Runqueue Wait", 135, "right"),
            ("slices", "Slices", 100, "right"),
        ],
        "filter_label": "Policy:",
        "filters": ["All", "SCHED_OTHER", "SCHED_BATCH", "SCHED_IDLE", "SCHED_FIFO", "SCHED_RR", "SCHED_DEADLINE", "SCHED_EXT", "Unknown"],
    },
    "cpus": {
        "label": "CPUs",
        "counter": "Total Scheduler CPUs",
        "columns": [
            ("cpu", "CPU", 90, "right"),
            ("schedule_calls", "Schedule Calls", 130, "right"),
            ("idle_schedules", "Idle Schedules", 130, "right"),
            ("wakeups", "Wakeups", 120, "right"),
            ("local_wakeups", "Local Wakeups", 125, "right"),
            ("runtime", "Runtime", 120, "right"),
            ("wait", "Runqueue Wait", 135, "right"),
            ("slices", "Slices", 100, "right"),
        ],
        "filter_label": "Status:",
        "filters": ["All", "Active", "Zero-slices"],
    },
    "domains": {
        "label": "Domains",
        "counter": "Total Scheduler Domains",
        "columns": [
            ("cpu", "CPU", 90, "right"),
            ("level", "Level", 90, "right"),
            ("name", "Name", 170, "left"),
            ("cpu_span", "CPU Span", 190, "left"),
            ("balance_calls", "Balance Calls", 130, "right"),
            ("move_failures", "Failed Moves", 120, "right"),
            ("cross_cpu_wakeups", "Cross-CPU Wakeups", 145, "right"),
        ],
        "filter_label": "Format:",
        "filters": ["All", "Decoded", "Raw-only"],
    },
}


def _detail_canvas(owner):
    widget = QTextEdit()
    widget.setReadOnly(True)
    widget.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
    font = getattr(owner, "_metadata_font", None)
    font_rule = metadata_font_qss(font) if font is not None else ""
    if font is not None:
        widget.setFont(font)
        widget.document().setDefaultFont(font)
        widget.setCurrentFont(font)
    widget.setStyleSheet(
        "QTextEdit { "
        f"{font_rule} "
        "background-color: #151719; color: #dcdcdc; border: 1px solid #333333; "
        "}"
    )
    return widget


def _formats():
    key = QTextCharFormat()
    key.setForeground(QColor("#9cdcfe"))
    key.setFontWeight(600)
    value = QTextCharFormat()
    value.setForeground(QColor("#dcdcdc"))
    return key, value


def _append_heading(widget, text):
    key, value = _formats()
    cursor = widget.textCursor()
    cursor.movePosition(QTextCursor.MoveOperation.End)
    if cursor.position() > 0:
        cursor.insertText("\n", value)
    cursor.insertText(str(text) + "\n", key)
    widget.setTextCursor(cursor)


def _append_property(widget, key_text, value_text):
    key, value = _formats()
    cursor = widget.textCursor()
    cursor.movePosition(QTextCursor.MoveOperation.End)
    cursor.insertText(f"{key_text}: ", key)
    cursor.insertText(str(value_text if value_text not in (None, "") else "Not reported") + "\n", value)
    widget.setTextCursor(cursor)


def _populate_sources(widget):
    widget.clear()
    groups = [
        (
            "Thread Scheduling",
            [
                "sched_getattr() when available; portable sched_getscheduler()/sched_getparam()/getpriority() fallback",
                "sched_getaffinity() with /proc/<tid>/status Cpus_allowed_list as a read-only fallback",
                "/proc/<pid>/task/*",
                "/proc/<tid>/schedstat",
                "/proc/<tid>/status",
                "/proc/<tid>/stat",
                "/proc/<tid>/comm",
                "Scheduling policy, nice/RT priority, deadline/uclamp attributes, CPU affinity, cumulative runtime/runqueue-wait/timeslices and process/thread identity.",
            ],
        ),
        (
            "Scheduler CPUs and Domains",
            [
                "/proc/schedstat",
                "Per-CPU cumulative scheduler counters and scheduler-domain topology/counters when the kernel exposes schedstats.",
                "Scheduler-domain counter semantics are decoded only for the known version-17 layout; other versions retain raw counters rather than guessed labels.",
            ],
        ),
        (
            "Optional Thread Context",
            [
                "/proc/<tid>/cgroup",
                "/proc/<tid>/sched (ext.enabled only when present)",
                "Cgroup path and sched_ext task state are contextual evidence; Scheduler Inspector does not inspect cgroup controllers or trace scheduler events.",
            ],
        ),
        (
            "Scheduler Details",
            [
                "/proc/sys/kernel/sched_schedstats",
                "/proc/sys/kernel/sched_autogroup_enabled",
                "/proc/sys/kernel/sched_rr_timeslice_ms",
                "/proc/sys/kernel/sched_rt_period_us",
                "/proc/sys/kernel/sched_rt_runtime_us",
                "/proc/sys/kernel/sched_util_clamp_*",
                "/sys/kernel/sched_ext/{state,enable_seq,root/ops,root/events}",
                "/sys/devices/system/cpu/{online,possible}",
                "These are read-only context values. The applet never writes scheduler tunables or loads a sched_ext scheduler.",
            ],
        ),
        (
            "Boundaries",
            [
                "No CPU-utilization percentages or background sampling; cumulative scheduler counters are shown as snapshots.",
                "No ps, chrt, taskset, top, perf, debugfs dependency, tracefs, eBPF loading, systemd-run or scheduler-control command is used.",
                "No nice, priority, affinity, cgroup, sysctl or sched_ext setting is modified.",
            ],
        ),
    ]
    for heading, lines in groups:
        _append_heading(widget, heading)
        for line in lines:
            _append_property(widget, "Source" if line.startswith("/") else "Note", line)
    cursor = widget.textCursor()
    cursor.movePosition(QTextCursor.MoveOperation.Start)
    widget.setTextCursor(cursor)
    widget.verticalScrollBar().setValue(0)


class SchedulerDetailsDialog(QDialog):
    def __init__(self, owner, snapshot):
        super().__init__(owner)
        self.owner = owner
        self.snapshot = snapshot or {}
        self.setWindowTitle("Scheduler Details — Scheduler Inspector")
        self.resize(920, 690)
        root = QVBoxLayout(self)
        self.text = _detail_canvas(owner)
        root.addWidget(self.text, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)
        self._populate()

    def _populate(self):
        s = self.snapshot
        self.text.clear()
        _append_heading(self.text, "CPU Scope")
        _append_property(self.text, "Online CPUs", s.get("online_cpus") or "Not reported")
        _append_property(self.text, "Possible CPUs", s.get("possible_cpus") or "Not reported")

        _append_heading(self.text, "Scheduler Statistics")
        _append_property(self.text, "Available", "Yes" if s.get("schedstat_available") else "No")
        _append_property(self.text, "Format Version", s.get("schedstat_version") if s.get("schedstat_version") is not None else "Not reported")
        _append_property(self.text, "Kernel Timestamp", s.get("schedstat_timestamp") if s.get("schedstat_timestamp") is not None else "Not reported")
        if s.get("schedstat_error"):
            _append_property(self.text, "Read Error", s.get("schedstat_error"))

        _append_heading(self.text, "Scheduler Runtime Settings")
        labels = {
            "sched_schedstats": "Scheduler Statistics Enabled",
            "sched_autogroup_enabled": "Autogroup Enabled",
            "sched_rr_timeslice_ms": "Round-Robin Timeslice (ms)",
            "sched_rt_period_us": "Real-time Period (µs)",
            "sched_rt_runtime_us": "Real-time Runtime (µs)",
            "sched_util_clamp_min": "System Utilization Clamp Min",
            "sched_util_clamp_max": "System Utilization Clamp Max",
            "sched_util_clamp_min_rt_default": "RT Default Utilization Clamp Min",
        }
        for key, label in labels.items():
            item = (s.get("settings") or {}).get(key, {})
            if item.get("available"):
                _append_property(self.text, label, item.get("value"))
            else:
                _append_property(self.text, label, "Not exposed")

        _append_heading(self.text, "sched_ext")
        ext = s.get("sched_ext") or {}
        _append_property(self.text, "Supported", "Yes" if ext.get("supported") else "No")
        if ext.get("supported"):
            _append_property(self.text, "State", ext.get("state") or "Not reported")
            _append_property(self.text, "Scheduler Ops", ext.get("ops") or "Not reported")
            _append_property(self.text, "Enable Sequence", ext.get("enable_seq") or "Not reported")
            events = ext.get("events") or []
            if events:
                _append_heading(self.text, "sched_ext Events")
                for name, value in events:
                    _append_property(self.text, name, value)

        _append_heading(self.text, "Source")
        _append_property(self.text, "Acquired", datetime.fromtimestamp(float(s.get("acquired_epoch") or 0)).isoformat(sep=" ", timespec="seconds") if s.get("acquired_epoch") else "Not reported")
        _append_property(self.text, "Primary", "/proc/schedstat and direct scheduler APIs")
        _append_property(self.text, "Optional", "/proc/sys/kernel/sched_* and /sys/kernel/sched_ext/*")
        _append_property(self.text, "Interpretation", "All settings are displayed read-only. Absence means not exposed by this kernel, not a failure or a default value.")
        cursor = self.text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        self.text.setTextCursor(cursor)
        self.text.verticalScrollBar().setValue(0)


class SchedulerOptionsDialog(QDialog):
    def __init__(self, owner):
        super().__init__(owner)
        self.owner = owner
        self.setWindowTitle("Options — Scheduler Inspector")
        self.resize(940, 690)
        root = QVBoxLayout(self)
        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        appearance = QWidget()
        layout = QVBoxLayout(appearance)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)
        heading = QLabel("Record details")
        font = heading.font(); font.setBold(True); heading.setFont(font)
        layout.addWidget(heading)
        note = QLabel("Choose how the scheduler inventory and Metadata Details are arranged.")
        note.setWordWrap(True); layout.addWidget(note)
        row = QHBoxLayout(); row.addWidget(QLabel("Record details layout:"))
        self.orientation = QComboBox(); self.orientation.addItems(["Horizontal", "Vertical"])
        self.orientation.setCurrentText(owner.details_orientation.title())
        self.orientation.currentTextChanged.connect(lambda text: owner.set_details_orientation(str(text).lower(), persist=True))
        row.addWidget(self.orientation); row.addStretch(1); layout.addLayout(row)
        self.show_metadata = QCheckBox("Show Metadata Details panel (F3)")
        self.show_metadata.setChecked(owner.metadata_panel_visible)
        self.show_metadata.toggled.connect(lambda checked: owner.set_metadata_panel_visible(bool(checked), persist=True))
        layout.addWidget(self.show_metadata)
        shortcuts = QLabel(
            "Shortcuts: F3 hides/restores Metadata Details; Shift+F5 refreshes the active inventory; "
            "Ctrl+L toggles Horizontal/Vertical; Ctrl+/ opens Options."
        )
        shortcuts.setWordWrap(True); layout.addWidget(shortcuts); layout.addStretch(1)
        tabs.addTab(appearance, "Appearance")

        sources = QWidget(); sources_layout = QVBoxLayout(sources)
        sources_layout.setContentsMargins(12, 12, 12, 12); sources_layout.setSpacing(10)
        sources_heading = QLabel("Data Sources")
        sources_font = sources_heading.font(); sources_font.setBold(True); sources_font.setPointSize(max(11, sources_font.pointSize())); sources_heading.setFont(sources_font)
        sources_layout.addWidget(sources_heading)
        sources_note = QLabel("Direct Linux interfaces used by this read-only scheduler inspector. Context sources are optional enrichment.")
        sources_note.setWordWrap(True); sources_layout.addWidget(sources_note)
        self.sources_text = _detail_canvas(owner); _populate_sources(self.sources_text)
        sources_layout.addWidget(self.sources_text, 1)
        tabs.addTab(sources, "Sources")

        export = QWidget(); export_layout = QVBoxLayout(export)
        export_layout.setContentsMargins(12, 12, 12, 12); export_layout.setSpacing(10)
        export_heading = QLabel("Export")
        export_font = export_heading.font(); export_font.setBold(True); export_heading.setFont(export_font)
        export_layout.addWidget(export_heading)
        export_note = QLabel("Export uses data already collected in this session; unopened views and Scheduler Details are not scanned in the background.")
        export_note.setWordWrap(True); export_layout.addWidget(export_note)
        self.export_checks = {}
        for key in _VIEW_ORDER:
            checkbox = QCheckBox(_VIEW_SPECS[key]["label"]); checkbox.setChecked(True)
            self.export_checks[key] = checkbox; export_layout.addWidget(checkbox)
        self.export_scheduler_details = QCheckBox("Scheduler Details (if already collected)"); self.export_scheduler_details.setChecked(True)
        export_layout.addWidget(self.export_scheduler_details)
        self.export_metadata = QCheckBox("Metadata Details"); export_layout.addWidget(self.export_metadata)
        export_layout.addStretch(1)
        export_row = QHBoxLayout(); export_row.addStretch(1)
        export_button = QPushButton("Export Selected Views...")
        export_button.clicked.connect(self._export); export_row.addWidget(export_button); export_layout.addLayout(export_row)
        tabs.addTab(export, "Export")

        # About — follows Interrupts Inspector authority, with LinSpectacles identity.
        about = QWidget()
        about_layout = QVBoxLayout(about)
        about_layout.setContentsMargins(24, 20, 24, 18)
        about_layout.setSpacing(8)

        icon_label = QLabel()
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setFixedSize(112, 112)
        icon_path = Path(__file__).resolve().parent / "icon.png"
        if icon_path.is_file():
            pix = QPixmap(str(icon_path))
            if not pix.isNull():
                icon_label.setPixmap(
                    pix.scaled(
                        112,
                        112,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                )
        about_layout.addWidget(icon_label, alignment=Qt.AlignmentFlag.AlignHCenter)

        name = QLabel("<h2 style='margin:0'>Scheduler Inspector</h2>")
        name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(name)

        version = QLabel(f"Version {APPLET_VERSION}")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(version)

        slogan = QLabel("<b>Expose. Explore. Explain.</b>")
        slogan.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(slogan)

        desc = QLabel(
            "A read-only LinSpectacles applet for inspecting per-thread scheduling policy and affinity, "
            "cumulative scheduler accounting, per-CPU schedstat state, scheduler domains, and "
            "sched_ext/global scheduler context."
        )
        desc.setWordWrap(True)
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(desc)

        details = QLabel(
            "<b>Build:</b> Standalone LinSpectacles applet<br>"
            "<b>Organisation ID:</b> "
            "<a href='https://github.com/linspectacles/'>linspectacles</a><br>"
            f"<b>Applet ID:</b> {APPLET_ID}"
        )
        details.setWordWrap(True)
        details.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextBrowserInteraction
            | Qt.TextInteractionFlag.TextSelectableByMouse
        )
        details.setOpenExternalLinks(True)
        details.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(details)

        copyright_label = QLabel(
            "Copyright © 2026 "
            "<a href='https://github.com/brunonlinespace'>brunonlinespace</a>"
        )
        copyright_label.setOpenExternalLinks(True)
        copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(copyright_label)

        license_label = QLabel("Licensed under GNU GPLv3 or later.")
        license_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(license_label)

        readme_url = QUrl.fromLocalFile(
            str(Path(__file__).resolve().parent.parent / "README.md")
        ).toString()
        license_url = QUrl.fromLocalFile(
            str(Path(__file__).resolve().parent.parent / "LICENSE")
        ).toString()
        links = QLabel(
            f"<a href='{readme_url}'>README</a> "
            "&nbsp;·&nbsp; "
            f"<a href='{license_url}'>License</a> "
            "&nbsp;·&nbsp; "
            "<a href='https://github.com/linspectacles/scheduler-inspector'>Repository</a>"
        )
        links.setOpenExternalLinks(True)
        links.setAlignment(Qt.AlignmentFlag.AlignCenter)
        about_layout.addWidget(links)
        about_layout.addStretch(1)
        tabs.addTab(about, "About")

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject); root.addWidget(buttons)

    def _export(self):
        selected = [key for key, checkbox in self.export_checks.items() if checkbox.isChecked()]
        self.owner.export_selected_views(
            selected,
            include_metadata=self.export_metadata.isChecked(),
            include_scheduler_details=self.export_scheduler_details.isChecked(),
            parent=self,
        )


class SchedulerInspectorTab(BaseInspectorTab):
    NUMERIC_COLUMNS = {"tid", "pid", "slices"}
    BYTE_COLUMNS = set()

    def __init__(self, parent=None):
        spec = _VIEW_SPECS["threads"]
        super().__init__(spec["counter"], spec["columns"], spec["filters"], parent)
        self.export_title = APPLET_NAME
        self._settings = QSettings("brunonlinespace", "Scheduler Inspector")
        self._datasets = {key: [] for key in _VIEW_ORDER}
        self._snapshots = {key: None for key in _VIEW_ORDER}
        self._loaded_views = set()
        self._current_view = "threads"
        self._host_column_callback = None
        self._host_hidden_all = set()
        self._scheduler_details_snapshot = None
        self._restoring_view_state = False
        self._view_sort_state = {}

        self.view_label = QLabel("View:")
        self.view_label.setStyleSheet("font-weight: 600;")
        self.view_combo = QComboBox(); self.view_combo.addItems([_VIEW_SPECS[key]["label"] for key in _VIEW_ORDER]); self.view_combo.setMinimumWidth(150)
        refresh_index = self.dash_layout.indexOf(self.refresh_btn)
        self.dash_layout.insertWidget(refresh_index, self.view_label)
        self.dash_layout.insertWidget(refresh_index + 1, self.view_combo)
        self.scheduler_details_btn = QPushButton("Scheduler Details...")
        self.dash_layout.insertWidget(refresh_index + 2, self.scheduler_details_btn)
        self.view_combo.currentTextChanged.connect(self._view_changed)
        self.scheduler_details_btn.clicked.connect(self.show_scheduler_details)

        self.refresh_btn.setText("Refresh")
        self.export_btn.setText("Options...")
        try:
            self.export_btn.clicked.disconnect()
        except TypeError:
            pass
        self.export_btn.clicked.connect(self.show_options)
        self.export_btn.setEnabled(True)

        self.details_orientation = "horizontal"
        self.metadata_panel_visible = True
        self._saved_active_view = "threads"
        self.table.horizontalHeader().sectionResized.connect(self._column_width_changed)
        self._load_ui_state()
        self._install_shortcuts()

        initial_view = self._saved_active_view if self._saved_active_view in _VIEW_SPECS else "threads"
        self.view_combo.blockSignals(True)
        self.view_combo.setCurrentText(_VIEW_SPECS[initial_view]["label"])
        self.view_combo.blockSignals(False)
        self._configure_view(initial_view, refresh=False)
        self.load_modules()

    def apply_host_settings(self, settings=None, column_visibility_callback=None):
        settings = settings or {}
        super().apply_host_settings({"metadata_font": settings.get("metadata_font", ""), "hidden_columns": []}, None)
        self._host_column_callback = column_visibility_callback if callable(column_visibility_callback) else None
        self._host_hidden_all = {str(item) for item in settings.get("hidden_columns", [])}
        self.column_visibility.set_changed_callback(self._column_visibility_changed)
        self._apply_view_hidden_columns()

    def _view_prefix(self, view=None):
        return str(view or self._current_view)

    def _visibility_columns(self):
        prefix = self._view_prefix()
        return [(f"{prefix}:{cid}", label, width, align) for cid, label, width, align in self.columns]

    def _apply_view_hidden_columns(self):
        if not hasattr(self, "column_visibility"):
            return
        self.column_visibility.columns = self._visibility_columns()
        prefix = self._view_prefix() + ":"
        current = [item for item in self._host_hidden_all if item.startswith(prefix)]
        self.column_visibility.apply_hidden(current)

    def _column_visibility_changed(self, hidden_current):
        prefix = self._view_prefix() + ":"
        self._host_hidden_all = {item for item in self._host_hidden_all if not item.startswith(prefix)}
        self._host_hidden_all.update(str(item) for item in hidden_current)
        if callable(self._host_column_callback):
            self._host_column_callback(sorted(self._host_hidden_all))

    def _install_shortcuts(self):
        self._metadata_shortcut = QShortcut(QKeySequence("F3"), self)
        self._metadata_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self._metadata_shortcut.activated.connect(self.toggle_metadata_panel)
        self._layout_shortcut = QShortcut(QKeySequence("Ctrl+L"), self)
        self._layout_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self._layout_shortcut.activated.connect(self.toggle_details_orientation)
        self._refresh_shortcut = QShortcut(QKeySequence("Shift+F5"), self)
        self._refresh_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self._refresh_shortcut.activated.connect(self.load_modules)
        self._options_shortcut = QShortcut(QKeySequence("Ctrl+/"), self)
        self._options_shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self._options_shortcut.activated.connect(self.show_options)

    @staticmethod
    def _setting_bool(value, default=False):
        if value is None:
            return bool(default)
        if isinstance(value, str):
            return value.strip().lower() not in {"0", "false", "no", "off", ""}
        return bool(value)

    def _state_key(self, view, name):
        return f"views/{view}/{name}"

    def _load_ui_state(self):
        orientation = str(self._settings.value("details_orientation", "horizontal") or "horizontal").lower()
        self.set_details_orientation(orientation if orientation in {"horizontal", "vertical"} else "horizontal", persist=False)
        visible = self._settings.value("metadata_panel_visible", True)
        self.set_metadata_panel_visible(self._setting_bool(visible, True), persist=False)
        active_view = str(self._settings.value("active_view", "threads") or "threads")
        self._saved_active_view = active_view if active_view in _VIEW_SPECS else "threads"

    def _load_sort_state(self, view):
        if view in self._view_sort_state:
            return self._view_sort_state[view]
        valid_columns = {column[0] for column in _VIEW_SPECS[view]["columns"]}
        column = str(self._settings.value(self._state_key(view, "sort_column"), "") or "")
        if column not in valid_columns:
            column = ""
        descending = self._setting_bool(
            self._settings.value(self._state_key(view, "sort_descending"), False),
            False,
        )
        state = {"column": column, "descending": descending}
        self._view_sort_state[view] = state
        return state

    def _stored_column_widths(self, view):
        raw = self._settings.value(self._state_key(view, "column_widths"), "")
        if raw in (None, ""):
            return []
        if isinstance(raw, str):
            parts = raw.split(",")
        elif isinstance(raw, (list, tuple)):
            parts = raw
        else:
            parts = [raw]
        widths = []
        for value in parts:
            try:
                widths.append(max(30, min(4000, int(value))))
            except (TypeError, ValueError):
                return []
        return widths

    def _save_column_widths(self, view=None):
        view = view or self._current_view
        if view not in _VIEW_SPECS or view != self._current_view:
            return
        widths = [self.table.horizontalHeader().sectionSize(index) for index in range(len(self.columns))]
        self._settings.setValue(self._state_key(view, "column_widths"), ",".join(str(width) for width in widths))

    def _column_width_changed(self, *_):
        if self._restoring_view_state:
            return
        self._save_column_widths()
        self._settings.sync()

    def _save_current_view_state(self):
        view = self._current_view
        if view not in _VIEW_SPECS or self._restoring_view_state:
            return
        self._settings.setValue(self._state_key(view, "filter"), self.category_dropdown.currentText())
        self._settings.setValue(self._state_key(view, "search"), self.search_entry.text())
        self._save_column_widths(view)
        state = self._load_sort_state(view)
        self._settings.setValue(self._state_key(view, "sort_column"), state["column"])
        self._settings.setValue(self._state_key(view, "sort_descending"), bool(state["descending"]))
        self._settings.sync()

    def _restore_view_state(self, view):
        spec = _VIEW_SPECS[view]
        self._restoring_view_state = True
        try:
            widths = self._stored_column_widths(view)
            if len(widths) == len(self.columns):
                for index, width in enumerate(widths):
                    self.table.setColumnWidth(index, width)

            saved_filter = str(
                self._settings.value(self._state_key(view, "filter"), spec["filters"][0])
                or spec["filters"][0]
            )
            self.category_dropdown.blockSignals(True)
            if saved_filter in spec["filters"]:
                self.category_dropdown.setCurrentText(saved_filter)
            else:
                self.category_dropdown.setCurrentIndex(0)
            self.category_dropdown.blockSignals(False)

            saved_search = str(self._settings.value(self._state_key(view, "search"), "") or "")
            self.search_entry.blockSignals(True)
            self.search_entry.setText(saved_search)
            self.search_entry.blockSignals(False)

            state = self._load_sort_state(view)
            header = self.table.horizontalHeader()
            if state["column"]:
                column_ids = [column[0] for column in self.columns]
                section = column_ids.index(state["column"])
                header.setSortIndicatorShown(True)
                order = Qt.SortOrder.DescendingOrder if state["descending"] else Qt.SortOrder.AscendingOrder
                header.setSortIndicator(section, order)
            else:
                header.setSortIndicatorShown(False)
        finally:
            self._restoring_view_state = False

    def set_metadata_panel_visible(self, visible, *, persist=True):
        self.metadata_panel_visible = bool(visible)
        panel = self.splitter.widget(1)
        if panel is not None:
            panel.setVisible(self.metadata_panel_visible)
        if persist:
            self._settings.setValue("metadata_panel_visible", self.metadata_panel_visible)
            self._settings.sync()

    def toggle_metadata_panel(self):
        self.set_metadata_panel_visible(not self.metadata_panel_visible, persist=True)

    def set_details_orientation(self, orientation, *, persist=True):
        orientation = str(orientation or "horizontal").lower()
        if orientation not in {"horizontal", "vertical"}:
            orientation = "horizontal"
        self.details_orientation = orientation
        panel = self.splitter.widget(1)
        panel_layout = panel.layout() if panel is not None else None
        if orientation == "vertical":
            self.splitter.setOrientation(Qt.Orientation.Vertical)
            if panel_layout is not None: panel_layout.setContentsMargins(0, 8, 0, 0)
            self.splitter.setSizes([430, 330])
        else:
            self.splitter.setOrientation(Qt.Orientation.Horizontal)
            if panel_layout is not None: panel_layout.setContentsMargins(8, 0, 0, 0)
            self.splitter.setSizes([500, 700])
        if persist:
            self._settings.setValue("details_orientation", orientation); self._settings.sync()

    def toggle_details_orientation(self):
        self.set_details_orientation("vertical" if self.details_orientation == "horizontal" else "horizontal", persist=True)

    def _view_key_from_label(self, label):
        for key in _VIEW_ORDER:
            if _VIEW_SPECS[key]["label"] == label:
                return key
        return "threads"

    def _view_changed(self, label):
        key = self._view_key_from_label(label)
        if key == self._current_view:
            return
        self._save_current_view_state()
        self._configure_view(key, refresh=False)
        self._settings.setValue("active_view", key)
        self._settings.sync()
        if key not in self._loaded_views:
            self.load_modules()
        else:
            self.modules_data = list(self._datasets[key])
            self._apply_saved_sort(key)
            self.filter_modules()
            self.set_status(f"Showing collected {_VIEW_SPECS[key]['label']} data.")

    def _configure_view(self, key, *, refresh=False):
        if key not in _VIEW_SPECS:
            key = "threads"
        self._current_view = key
        spec = _VIEW_SPECS[key]
        self.total_label_text = spec["counter"]
        self.columns = list(spec["columns"])
        self.stats_label.setText(f"{self.total_label_text}: {len(self._datasets.get(key, []))}")
        self._restoring_view_state = True
        try:
            self.table.setSortingEnabled(False); self.table.clearContents(); self.table.setRowCount(0)
            self.table.setColumnCount(len(self.columns)); self.table.setHorizontalHeaderLabels([col[1] for col in self.columns])
            for index, (_cid, _label, width, _align) in enumerate(self.columns):
                self.table.setColumnWidth(index, width)
            self._apply_view_hidden_columns()
            self.category_label.setText(spec["filter_label"])
            self.category_dropdown.blockSignals(True)
            self.category_dropdown.clear(); self.category_dropdown.addItems(spec["filters"]); self.category_dropdown.setCurrentIndex(0)
            self.category_dropdown.blockSignals(False)
            self.search_entry.setPlaceholderText(f"Search {spec['label'].lower()}...")
            self.clear_info()
        finally:
            self._restoring_view_state = False
        self._restore_view_state(key)
        if refresh:
            self.load_modules()

    def _sort_key(self, column_id, record):
        if column_id in self.NUMERIC_COLUMNS:
            value = record.get(column_id, 0)
            return value if isinstance(value, (int, float)) else 0
        return str(record.get(column_id, "")).lower()

    def _sort_modules(self, column_id, descending):
        try:
            self.modules_data.sort(
                key=lambda record: self._sort_key(column_id, record),
                reverse=bool(descending),
            )
        except Exception:
            self.modules_data.sort(
                key=lambda record: str(record.get(column_id, "")).lower(),
                reverse=bool(descending),
            )

    def _apply_saved_sort(self, view=None):
        view = view or self._current_view
        state = self._load_sort_state(view)
        if not state["column"]:
            return
        self._sort_modules(state["column"], state["descending"])
        self._datasets[view] = list(self.modules_data)

    def sort_by(self, column_id):
        valid_columns = {column[0] for column in self.columns}
        if column_id not in valid_columns:
            return
        state = self._load_sort_state(self._current_view)
        descending = not state["descending"] if state["column"] == column_id else False
        state["column"] = column_id
        state["descending"] = descending
        self._sort_modules(column_id, descending)
        self._datasets[self._current_view] = list(self.modules_data)

        section = [column[0] for column in self.columns].index(column_id)
        header = self.table.horizontalHeader()
        header.setSortIndicatorShown(True)
        order = Qt.SortOrder.DescendingOrder if descending else Qt.SortOrder.AscendingOrder
        header.setSortIndicator(section, order)

        self._settings.setValue(self._state_key(self._current_view, "sort_column"), column_id)
        self._settings.setValue(self._state_key(self._current_view, "sort_descending"), descending)
        self._settings.sync()
        self.filter_modules()

    def load_modules(self):
        key = self._current_view
        self.set_status(f"Scanning {_VIEW_SPECS[key]['label']}...")
        QApplication.processEvents()
        try:
            if key == "threads":
                snapshot = collect_threads()
                records = list(snapshot.get("records", []))
            else:
                snapshot = collect_schedstat()
                records = list(snapshot.get("cpus" if key == "cpus" else "domains", []))
        except Exception as exc:
            self.set_status(f"Failed to read {_VIEW_SPECS[key]['label']}: {exc}")
            return
        self._snapshots[key] = snapshot
        if not snapshot.get("available", False):
            self._datasets[key] = []
            self._loaded_views.add(key)
            self.modules_data = []
            self.stats_label.setText(f"{self.total_label_text}: 0")
            self.filter_modules()
            self.set_status(f"{_VIEW_SPECS[key]['label']} unavailable: {snapshot.get('error') or 'source unavailable'}")
            return
        self._datasets[key] = records; self._loaded_views.add(key); self.modules_data = list(records)
        self._apply_saved_sort(key)
        self.stats_label.setText(f"{self.total_label_text}: {len(records)}")
        self.filter_modules()
        if key == "threads":
            vanished = int(snapshot.get("vanished", 0) or 0)
            inaccessible = int(snapshot.get("inaccessible", 0) or 0)
            partial = int(snapshot.get("partial", 0) or 0)
            suffix = f" · {vanished} vanished · {inaccessible} inaccessible · {partial} partial" if any((vanished, inaccessible, partial)) else ""
            self.set_status(f"Refreshed Threads: {len(records)} thread(s){suffix}.")
        else:
            malformed = int(snapshot.get("malformed_lines", 0) or 0)
            version = snapshot.get("version")
            suffix = f" · schedstat v{version}" if version is not None else ""
            if malformed:
                suffix += f" · {malformed} malformed line(s) skipped"
            self.set_status(f"Refreshed {_VIEW_SPECS[key]['label']}: {len(records)} record(s){suffix}.")

    def _record_matches_filter(self, record, selected):
        if selected == "All":
            return True
        if self._current_view == "threads":
            policy = str(record.get("policy") or "Unknown")
            return policy == selected if selected != "Unknown" else policy == "Unknown" or policy.startswith("Policy ")
        if self._current_view == "cpus":
            slices = record.get("slices")
            active = isinstance(slices, int) and slices > 0
            return active if selected == "Active" else not active
        if self._current_view == "domains":
            decoded = bool(record.get("decoded"))
            return decoded if selected == "Decoded" else not decoded
        return True

    def _searchable_values(self, record):
        excluded = {"raw_fields", "raw_counters", "cgroup_memberships"}
        return [value for key, value in record.items() if not str(key).startswith("_") and key not in excluded]

    def _numeric_item(self, cid, record, display):
        raw_map = {
            "tid": "tid", "pid": "pid", "slices": "slices", "cpu": "cpu", "level": "level",
            "schedule_calls": "schedule_calls", "idle_schedules": "idle_schedules", "wakeups": "wakeups",
            "local_wakeups": "local_wakeups", "runtime": "runtime_ns", "wait": "wait_ns",
            "balance_calls": "balance_calls", "move_failures": "move_failures", "cross_cpu_wakeups": "cross_cpu_wakeups",
        }
        raw_key = raw_map.get(cid)
        raw = record.get(raw_key) if raw_key else None
        if isinstance(raw, int):
            return NumericTableWidgetItem(str(display), raw)
        from PyQt6.QtWidgets import QTableWidgetItem
        return QTableWidgetItem(str(display))

    def _record_identity(self, record, view=None):
        if not record:
            return None
        view = view or self._current_view
        if view == "threads":
            return ("thread", record.get("tid"), record.get("starttime_ticks"))
        if view == "cpus":
            return ("cpu", record.get("cpu"))
        if view == "domains":
            return (
                "domain",
                record.get("cpu"),
                record.get("level"),
                record.get("name"),
                record.get("cpu_span"),
            )
        return None

    def filter_modules(self, *_):
        selected_identity = self._record_identity(self.current_record(), self._current_view)
        query = self.search_entry.text().strip().lower()
        selected = self.category_dropdown.currentText()

        if not self._restoring_view_state:
            self._settings.setValue(self._state_key(self._current_view, "filter"), selected)
            self._settings.setValue(self._state_key(self._current_view, "search"), self.search_entry.text())
            self._settings.sync()

        matches = []
        for record in self.modules_data:
            if not self._record_matches_filter(record, selected):
                continue
            if query and not any(query in str(value).lower() for value in self._searchable_values(record)):
                continue
            matches.append(record)

        target_row = 0
        if selected_identity is not None:
            for index, record in enumerate(matches):
                if self._record_identity(record, self._current_view) == selected_identity:
                    target_row = index
                    break

        blocked = self.table.blockSignals(True)
        try:
            self.clear_info()
            self.table.clearSelection()
            self.table.setSortingEnabled(False)
            self.table.setRowCount(len(matches))
            for row, record in enumerate(matches):
                for col_index, (cid, _label, _width, alignment) in enumerate(self.columns):
                    value = record.get(cid, "")
                    item = self._numeric_item(cid, record, value)
                    if col_index == 0:
                        item.setData(Qt.ItemDataRole.UserRole, record)
                    if alignment == "right":
                        item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                    else:
                        item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
                    self.table.setItem(row, col_index, item)

            if matches:
                self.table.setCurrentCell(target_row, 0)
                self.table.selectRow(target_row)
            else:
                self.table.setCurrentCell(-1, -1)
        finally:
            self.table.blockSignals(blocked)

        # As in the Hardware Topology authority, details are rendered explicitly
        # after a rebuilt inventory rather than relying on Qt selection signals.
        self.clear_info()
        if matches:
            self._render_record_details(matches[target_row], self._current_view)

        cursor = self.info_text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        self.info_text.setTextCursor(cursor)
        self.info_text.verticalScrollBar().setValue(0)
        if query or selected != "All":
            self.filter_status_lbl.setText(f"(Showing {len(matches)} of {len(self.modules_data)} items)")
        else:
            self.filter_status_lbl.clear()

    def on_module_select(self):
        record = self.current_record()
        if record:
            self._render_record_details(record, self._current_view)
            cursor = self.info_text.textCursor(); cursor.movePosition(QTextCursor.MoveOperation.Start); self.info_text.setTextCursor(cursor); self.info_text.verticalScrollBar().setValue(0)

    def _render_record_details(self, record, view):
        self.clear_info()
        if view == "threads":
            self._render_thread_details(record)
        elif view == "cpus":
            self._render_cpu_details(record)
        else:
            self._render_domain_details(record)

    def _render_thread_details(self, record):
        self.append_info("--- Thread ---\n")
        for label, key in (
            ("TID", "tid"), ("Thread Name", "thread_name"), ("Process", "process"), ("PID / TGID", "pid"),
            ("User", "user"), ("UID", "uid"), ("State", "state"), ("Last CPU", "last_cpu"), ("Start Time (clock ticks)", "starttime_ticks"),
        ):
            self.append_key_value(label, record.get(key, "Not reported"))

        self.append_info("\n--- Scheduling ---\n")
        for label, key in (
            ("Policy", "policy"), ("Priority / Nice", "priority_nice"), ("Nice", "nice"), ("Static / RT Priority", "rt_priority"),
            ("Flags", "sched_flags_text"), ("Attribute Source", "attribute_source"),
        ):
            value = record.get(key)
            self.append_key_value(label, value if value not in (None, "") else "Not reported")
        if record.get("attribute_error"):
            self.append_key_value("Attribute Fallback / Error", record.get("attribute_error"))

        if record.get("policy") == "SCHED_DEADLINE" or any(record.get(key) not in (None, 0) for key in ("deadline_runtime_ns", "deadline_deadline_ns", "deadline_period_ns")):
            self.append_info("\n--- Deadline Parameters ---\n")
            self.append_key_value("Runtime", format_ns(record.get("deadline_runtime_ns")) if record.get("deadline_runtime_ns") is not None else "Not reported")
            self.append_key_value("Deadline", format_ns(record.get("deadline_deadline_ns")) if record.get("deadline_deadline_ns") is not None else "Not reported")
            self.append_key_value("Period", format_ns(record.get("deadline_period_ns")) if record.get("deadline_period_ns") is not None else "Not reported")

        self.append_info("\n--- Utilization Clamp ---\n")
        util_min = record.get("util_min")
        util_max = record.get("util_max")
        self.append_key_value("Minimum", util_min if util_min is not None else "Not reported")
        self.append_key_value("Maximum", util_max if util_max is not None else "Not reported")
        self.append_info("Utilization-clamp values use the kernel's 0..1024 fixed-point scale when reported.\n")

        self.append_info("\n--- CPU Affinity ---\n")
        self.append_key_value("Allowed CPUs", record.get("affinity") or "Not reported")
        self.append_key_value("CPU Count", record.get("affinity_count", 0))
        self.append_key_value("Source", record.get("affinity_source") or "Not reported")
        if record.get("affinity_error"):
            self.append_key_value("Fallback Reason", record.get("affinity_error"))

        self.append_info("\n--- Scheduler Accounting ---\n")
        self.append_key_value("Runtime", record.get("runtime", "Not reported"))
        self.append_key_value("Runqueue Wait", record.get("wait", "Not reported"))
        self.append_key_value("Timeslices", record.get("slices", "Not reported"))
        self.append_key_value("Voluntary Context Switches", record.get("voluntary_context_switches") if record.get("voluntary_context_switches") is not None else "Not reported")
        self.append_key_value("Involuntary Context Switches", record.get("involuntary_context_switches") if record.get("involuntary_context_switches") is not None else "Not reported")
        self.append_info("Runtime, runqueue wait and timeslices are cumulative scheduler accounting, not current CPU utilization or a live wait duration.\n")

        if record.get("unified_cgroup") or record.get("cgroup_memberships"):
            self.append_info("\n--- Cgroup Context ---\n")
            self.append_key_value("Unified Cgroup", record.get("unified_cgroup") or "Not reported")
            for index, line in enumerate(record.get("cgroup_memberships") or [], 1):
                self.append_key_value(f"Membership {index}", line)
            self.append_info("Cgroup membership is contextual only; controller hierarchy and limits belong to Cgroups inspection.\n")

        if record.get("sched_ext_enabled"):
            self.append_info("\n--- sched_ext Context ---\n")
            self.append_key_value("ext.enabled", record.get("sched_ext_enabled"))
            self.append_info("This is kernel-reported task context only; Scheduler Inspector does not load, control or trace sched_ext schedulers.\n")

        self.append_info("\n--- Source ---\n")
        self.append_key_value("Thread Inventory", "/proc/<pid>/task/*")
        self.append_key_value("Scheduling Attributes", record.get("attribute_source") or "direct scheduler APIs")
        self.append_key_value("Affinity", record.get("affinity_source") or "sched_getaffinity()")
        self.append_key_value("Accounting", "/proc/<tid>/schedstat")
        self.append_key_value("Identity / Context", "/proc/<tid>/{status,stat,comm,cgroup}")

    def _render_cpu_details(self, record):
        self.append_info("--- Scheduler CPU ---\n")
        self.append_key_value("CPU", record.get("cpu", "Not reported"))
        self.append_key_value("schedstat Format Version", record.get("format_version", "Not reported"))
        self.append_key_value("Decoded", "Yes" if record.get("decoded") else "No — raw counters retained")
        if record.get("decoded"):
            for label, key in (
                ("sched_yield Calls", "yield_calls"), ("Schedule Calls", "schedule_calls"), ("Idle Schedules", "idle_schedules"),
                ("Wakeups", "wakeups"), ("Local Wakeups", "local_wakeups"), ("Runtime", "runtime"), ("Runqueue Wait", "wait"), ("Timeslices", "slices"),
            ):
                self.append_key_value(label, record.get(key, "Not reported"))
        self.append_info("\n--- Raw schedstat CPU Fields ---\n")
        for index, value in enumerate(record.get("raw_fields") or [], 1):
            self.append_key_value(f"Field {index}", value)
        self.append_info("\n--- Source ---\n")
        self.append_key_value("Primary", "/proc/schedstat")
        self.append_info("Counters are cumulative. Scheduler Inspector does not convert them into rates or CPU percentages.\n")

    def _render_domain_details(self, record):
        self.append_info("--- Scheduler Domain ---\n")
        for label, key in (
            ("CPU", "cpu"), ("Level", "level"), ("Name", "name"), ("CPU Span", "cpu_span"), ("CPU Mask", "cpu_mask"),
            ("schedstat Format Version", "format_version"),
        ):
            self.append_key_value(label, record.get(key, "Not reported"))
        self.append_key_value("Decoded", "Yes" if record.get("decoded") else "No — raw counters retained")
        if record.get("decoded"):
            self.append_info("\n--- Summary ---\n")
            self.append_key_value("Balance Calls", record.get("balance_calls", 0))
            self.append_key_value("Failed Moves", record.get("move_failures", 0))
            self.append_key_value("Cross-CPU Wakeups", record.get("cross_cpu_wakeups", 0))
            groups = decode_domain_v17(record.get("raw_counters")) or {}
            for heading, values in groups.items():
                self.append_info(f"\n--- {heading} ---\n")
                for label, value in values.items():
                    self.append_key_value(label, value)
        else:
            self.append_info("\n--- Raw Domain Counters ---\n")
            for index, value in enumerate(record.get("raw_counters") or [], 1):
                self.append_key_value(f"Counter {index}", value)
            self.append_info("This schedstat domain format is not decoded by this release; raw values are preserved rather than assigned guessed semantics.\n")
        self.append_info("\n--- Source ---\n")
        self.append_key_value("Primary", "/proc/schedstat")
        self.append_info("A scheduler domain describes a CPU span across which the kernel balances runnable work; this is scheduler topology, not hardware topology.\n")

    def show_scheduler_details(self):
        try:
            self._scheduler_details_snapshot = collect_scheduler_details()
        except Exception as exc:
            QMessageBox.warning(self, "Scheduler Details", f"Unable to collect scheduler details:\n{exc}")
            return
        SchedulerDetailsDialog(self, self._scheduler_details_snapshot).exec()

    def show_options(self):
        SchedulerOptionsDialog(self).exec()

    def metadata_details_for_export(self, view, record):
        original = self.info_text
        temporary = QTextEdit(); self.info_text = temporary
        try:
            self._render_record_details(record, view)
            return temporary.toPlainText()
        finally:
            self.info_text = original

    def export_selected_views(self, selected, *, include_metadata=False, include_scheduler_details=False, parent=None):
        selected = list(selected or [])
        if not selected and not include_scheduler_details:
            QMessageBox.information(parent or self, "Export", "Select at least one Scheduler Inspector view to export.")
            return
        flat = []
        for key in _VIEW_ORDER:
            if key not in selected:
                continue
            spec = _VIEW_SPECS[key]
            records = self._datasets[key] if key in self._loaded_views else []
            if not records:
                flat.append({"view": spec["label"], "record": "", "field": "Status", "value": "No collected data."})
                continue
            for index, record in enumerate(records, 1):
                for cid, label, _width, _align in spec["columns"]:
                    flat.append({"view": spec["label"], "record": str(index), "field": label, "value": record.get(cid, "")})
                if include_metadata:
                    flat.append({"view": spec["label"], "record": str(index), "field": "Metadata Details", "value": self.metadata_details_for_export(key, record)})
        if include_scheduler_details:
            if self._scheduler_details_snapshot:
                s = self._scheduler_details_snapshot
                flat.extend([
                    {"view": "Scheduler Details", "record": "", "field": "Online CPUs", "value": s.get("online_cpus", "")},
                    {"view": "Scheduler Details", "record": "", "field": "Possible CPUs", "value": s.get("possible_cpus", "")},
                    {"view": "Scheduler Details", "record": "", "field": "schedstat Version", "value": s.get("schedstat_version", "")},
                    {"view": "Scheduler Details", "record": "", "field": "sched_ext State", "value": (s.get("sched_ext") or {}).get("state", "")},
                    {"view": "Scheduler Details", "record": "", "field": "sched_ext Ops", "value": (s.get("sched_ext") or {}).get("ops", "")},
                ])
                for name, item in (s.get("settings") or {}).items():
                    flat.append({"view": "Scheduler Details", "record": "", "field": name, "value": item.get("value") if item.get("available") else "Not exposed"})
            else:
                flat.append({"view": "Scheduler Details", "record": "", "field": "Status", "value": "Not collected in this session."})
        path = export_records_dialog(parent or self, APPLET_NAME, flat, columns=[("view", "View"), ("record", "Record"), ("field", "Field"), ("value", "Value")])
        if path is not None:
            self.set_status(f"Exported selected Scheduler Inspector views to {path}")


def create_applet(parent=None):
    return SchedulerInspectorTab(parent=parent)


def run_standalone():
    import sys
    from PyQt6.QtGui import QIcon
    from PyQt6.QtWidgets import QApplication, QMainWindow
    from ._support import STANDALONE_STYLESHEET

    app = QApplication(sys.argv); app.setApplicationName(APPLET_NAME); app.setOrganizationName(APPLET_AUTHOR); app.setStyleSheet(STANDALONE_STYLESHEET)
    icon_path = Path(__file__).resolve().parent / "icon.png"
    if icon_path.is_file(): app.setWindowIcon(QIcon(str(icon_path)))
    window = QMainWindow(); window.setWindowTitle(f"{APPLET_NAME} {APPLET_VERSION} — LinSpectacles Applet")
    if icon_path.is_file(): window.setWindowIcon(QIcon(str(icon_path)))
    window.setCentralWidget(create_applet()); window.resize(1320, 780); window.show()
    return app.exec()
