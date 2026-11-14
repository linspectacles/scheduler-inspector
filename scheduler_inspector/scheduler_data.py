#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# LinSpectacles - Linux Inspection Suite
# Copyright (C) 2026 brunonlinespace
# GPL-3.0-or-later

from __future__ import annotations

import ctypes
import errno
import os
import pwd
import re
import time
from pathlib import Path

PROC = Path('/proc')
SYS = Path('/sys')

POLICY_NAMES = {
    0: 'SCHED_OTHER',
    1: 'SCHED_FIFO',
    2: 'SCHED_RR',
    3: 'SCHED_BATCH',
    5: 'SCHED_IDLE',
    6: 'SCHED_DEADLINE',
    7: 'SCHED_EXT',
}

SCHED_FLAG_NAMES = (
    (0x01, 'RESET_ON_FORK'),
    (0x02, 'RECLAIM'),
    (0x04, 'DL_OVERRUN'),
    (0x08, 'KEEP_POLICY'),
    (0x10, 'KEEP_PARAMS'),
    (0x20, 'UTIL_CLAMP_MIN'),
    (0x40, 'UTIL_CLAMP_MAX'),
)


class SchedAttr(ctypes.Structure):
    _fields_ = [
        ('size', ctypes.c_uint32),
        ('sched_policy', ctypes.c_uint32),
        ('sched_flags', ctypes.c_uint64),
        ('sched_nice', ctypes.c_int32),
        ('sched_priority', ctypes.c_uint32),
        ('sched_runtime', ctypes.c_uint64),
        ('sched_deadline', ctypes.c_uint64),
        ('sched_period', ctypes.c_uint64),
        ('sched_util_min', ctypes.c_uint32),
        ('sched_util_max', ctypes.c_uint32),
    ]


_LIBC = ctypes.CDLL(None, use_errno=True)
_HAS_SCHED_GETATTR = hasattr(_LIBC, 'sched_getattr')
if _HAS_SCHED_GETATTR:
    _LIBC.sched_getattr.argtypes = [ctypes.c_int, ctypes.POINTER(SchedAttr), ctypes.c_uint, ctypes.c_uint]
    _LIBC.sched_getattr.restype = ctypes.c_int


_UID_CACHE = {}


def _read_text(path: Path, default=''):
    try:
        return path.read_text(errors='replace').strip()
    except (OSError, UnicodeError):
        return default


def _read_int(path: Path, default=None):
    raw = _read_text(path, '')
    try:
        return int(raw, 0)
    except (TypeError, ValueError):
        return default


def _uid_name(uid):
    if uid is None:
        return ''
    if uid in _UID_CACHE:
        return _UID_CACHE[uid]
    try:
        name = pwd.getpwuid(int(uid)).pw_name
    except Exception:
        name = str(uid)
    _UID_CACHE[uid] = name
    return name


def format_cpu_set(cpus):
    values = sorted({int(cpu) for cpu in (cpus or [])})
    if not values:
        return ''
    ranges = []
    start = prev = values[0]
    for cpu in values[1:]:
        if cpu == prev + 1:
            prev = cpu
            continue
        ranges.append(str(start) if start == prev else f'{start}-{prev}')
        start = prev = cpu
    ranges.append(str(start) if start == prev else f'{start}-{prev}')
    return ','.join(ranges)


def parse_cpu_list(text):
    cpus = set()
    for chunk in str(text or '').split(','):
        chunk = chunk.strip()
        if not chunk:
            continue
        if '-' in chunk:
            try:
                left, right = chunk.split('-', 1)
                start, end = int(left), int(right)
                if end >= start:
                    cpus.update(range(start, end + 1))
            except ValueError:
                continue
        else:
            try:
                cpus.add(int(chunk))
            except ValueError:
                pass
    return cpus


def parse_cpumask(mask):
    text = str(mask or '').strip().lower().replace(',', '')
    if text.startswith('0x'):
        text = text[2:]
    if not text:
        return set()
    try:
        value = int(text, 16)
    except ValueError:
        return set()
    cpus = set()
    bit = 0
    while value:
        if value & 1:
            cpus.add(bit)
        value >>= 1
        bit += 1
    return cpus


def format_ns(value):
    try:
        ns = int(value)
    except (TypeError, ValueError):
        return 'Not reported'
    if ns < 1_000:
        return f'{ns} ns'
    if ns < 1_000_000:
        return f'{ns / 1_000:.3f} µs'
    if ns < 1_000_000_000:
        return f'{ns / 1_000_000:.3f} ms'
    seconds = ns / 1_000_000_000
    if seconds < 60:
        return f'{seconds:.3f} s'
    minutes = int(seconds // 60)
    seconds -= minutes * 60
    if minutes < 60:
        return f'{minutes}m {seconds:.3f}s'
    hours = minutes // 60
    minutes %= 60
    return f'{hours}h {minutes}m {seconds:.3f}s'


def _parse_status(path: Path):
    result = {}
    try:
        for line in path.read_text(errors='replace').splitlines():
            if ':' not in line:
                continue
            key, value = line.split(':', 1)
            result[key.strip()] = value.strip()
    except OSError:
        return result
    return result


def _parse_stat(path: Path):
    try:
        raw = path.read_text(errors='replace').strip()
    except OSError:
        return None
    close = raw.rfind(')')
    open_ = raw.find('(')
    if open_ <= 0 or close <= open_:
        return None
    try:
        pid = int(raw[:open_].strip())
    except ValueError:
        return None
    comm = raw[open_ + 1:close]
    tail = raw[close + 1:].strip().split()
    if len(tail) < 20:
        return None
    def field(number, default=''):
        index = number - 3
        return tail[index] if 0 <= index < len(tail) else default
    try:
        starttime = int(field(22, '0'))
    except ValueError:
        starttime = 0
    try:
        processor = int(field(39, '-1'))
    except ValueError:
        processor = -1
    try:
        nice = int(field(19, '0'))
    except ValueError:
        nice = 0
    try:
        priority = int(field(18, '0'))
    except ValueError:
        priority = 0
    return {
        'pid': pid,
        'comm': comm,
        'state': field(3, ''),
        'priority_stat': priority,
        'nice_stat': nice,
        'starttime_ticks': starttime,
        'last_cpu': processor,
    }


def _read_schedstat(path: Path):
    raw = _read_text(path, '')
    parts = raw.split()
    if len(parts) < 3:
        return None
    try:
        return tuple(int(part) for part in parts[:3])
    except ValueError:
        return None


def _decode_flags(value):
    try:
        flags = int(value)
    except (TypeError, ValueError):
        return ''
    names = [name for bit, name in SCHED_FLAG_NAMES if flags & bit]
    known = 0
    for bit, _name in SCHED_FLAG_NAMES:
        known |= bit
    unknown = flags & ~known
    if unknown:
        names.append(f'UNKNOWN(0x{unknown:x})')
    return ', '.join(names) if names else 'None'


def _get_sched_attr(tid):
    if _HAS_SCHED_GETATTR:
        attr = SchedAttr()
        attr.size = ctypes.sizeof(SchedAttr)
        ctypes.set_errno(0)
        rc = _LIBC.sched_getattr(int(tid), ctypes.byref(attr), ctypes.sizeof(attr), 0)
        if rc == 0:
            return {
                'available': True,
                'source': 'sched_getattr()',
                'policy_num': int(attr.sched_policy),
                'flags': int(attr.sched_flags),
                'flags_text': _decode_flags(attr.sched_flags),
                'nice': int(attr.sched_nice),
                'priority': int(attr.sched_priority),
                'deadline_runtime_ns': int(attr.sched_runtime),
                'deadline_deadline_ns': int(attr.sched_deadline),
                'deadline_period_ns': int(attr.sched_period),
                'util_min': int(attr.sched_util_min),
                'util_max': int(attr.sched_util_max),
                'error': '',
            }
        err = ctypes.get_errno()
        if err not in (errno.ENOSYS, errno.EINVAL):
            # Keep the errno as context, then try portable fallbacks below.
            fallback_error = os.strerror(err) if err else 'sched_getattr failed'
        else:
            fallback_error = os.strerror(err) if err else 'sched_getattr unavailable'
    else:
        fallback_error = 'sched_getattr symbol unavailable'

    policy = None
    priority = None
    nice = None
    errors = []
    try:
        policy = int(os.sched_getscheduler(int(tid)))
    except Exception as exc:
        errors.append(f'sched_getscheduler: {exc}')
    try:
        priority = int(os.sched_getparam(int(tid)).sched_priority)
    except Exception as exc:
        errors.append(f'sched_getparam: {exc}')
    try:
        nice = int(os.getpriority(os.PRIO_PROCESS, int(tid)))
    except Exception as exc:
        errors.append(f'getpriority: {exc}')

    return {
        'available': policy is not None,
        'source': 'sched_getscheduler()/sched_getparam()/getpriority() fallback',
        'policy_num': policy,
        'flags': None,
        'flags_text': 'Not reported',
        'nice': nice,
        'priority': priority,
        'deadline_runtime_ns': None,
        'deadline_deadline_ns': None,
        'deadline_period_ns': None,
        'util_min': None,
        'util_max': None,
        'error': '; '.join([fallback_error] + errors),
    }


def _get_affinity(tid, status=None):
    try:
        cpus = set(os.sched_getaffinity(int(tid)))
        return cpus, 'sched_getaffinity()', ''
    except Exception as exc:
        text = (status or {}).get('Cpus_allowed_list', '')
        cpus = parse_cpu_list(text)
        return cpus, '/proc/<tid>/status Cpus_allowed_list', str(exc)


def _read_cgroups(tid):
    lines = []
    unified = ''
    raw = _read_text(PROC / str(tid) / 'cgroup', '')
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        lines.append(line)
        parts = line.split(':', 2)
        if len(parts) == 3 and parts[0] == '0' and parts[1] == '':
            unified = parts[2]
    return unified, lines


def _read_sched_ext_enabled(tid):
    path = PROC / str(tid) / 'sched'
    try:
        for line in path.read_text(errors='replace').splitlines():
            stripped = line.strip()
            if stripped.startswith('ext.enabled') and ':' in stripped:
                return stripped.split(':', 1)[1].strip()
    except OSError:
        pass
    return ''


def _policy_display(policy_num):
    if policy_num is None:
        return 'Unknown'
    return POLICY_NAMES.get(int(policy_num), f'Policy {policy_num}')


def _priority_display(policy, nice, priority):
    if policy in {'SCHED_FIFO', 'SCHED_RR'}:
        return f'RT {priority}' if priority is not None else 'RT'
    if policy == 'SCHED_DEADLINE':
        return 'Deadline'
    if nice is None:
        return 'Not reported'
    return f'nice {nice}'


def collect_threads(proc_root=PROC):
    records = []
    vanished = 0
    inaccessible = 0
    partial = 0
    pids = []
    try:
        pids = sorted(int(p.name) for p in proc_root.iterdir() if p.name.isdigit())
    except OSError as exc:
        return {'available': False, 'error': str(exc), 'records': [], 'vanished': 0, 'inaccessible': 0, 'partial': 0}

    for pid in pids:
        process_dir = proc_root / str(pid)
        process_name = _read_text(process_dir / 'comm', '') or str(pid)
        task_dir = process_dir / 'task'
        try:
            tids = sorted(int(p.name) for p in task_dir.iterdir() if p.name.isdigit())
        except FileNotFoundError:
            vanished += 1
            continue
        except PermissionError:
            inaccessible += 1
            continue
        except OSError:
            partial += 1
            continue

        for tid in tids:
            tdir = proc_root / str(tid)
            try:
                stat_before = _parse_stat(tdir / 'stat')
                if not stat_before:
                    partial += 1
                    continue
                status = _parse_status(tdir / 'status')
                thread_name = _read_text(tdir / 'comm', '') or stat_before.get('comm') or str(tid)
                uid = None
                uid_text = status.get('Uid', '')
                if uid_text:
                    try:
                        uid = int(uid_text.split()[0])
                    except (ValueError, IndexError):
                        uid = None
                user = _uid_name(uid)
                attr = _get_sched_attr(tid)
                policy = _policy_display(attr.get('policy_num'))
                cpus, affinity_source, affinity_error = _get_affinity(tid, status)
                schedstat = _read_schedstat(tdir / 'schedstat')
                runtime_ns = wait_ns = slices = None
                if schedstat:
                    runtime_ns, wait_ns, slices = schedstat
                unified_cgroup, cgroup_lines = _read_cgroups(tid)
                ext_enabled = _read_sched_ext_enabled(tid)
                stat_after = _parse_stat(tdir / 'stat')
                if not stat_after or stat_after.get('starttime_ticks') != stat_before.get('starttime_ticks'):
                    vanished += 1
                    continue

                try:
                    voluntary = int(status.get('voluntary_ctxt_switches', ''))
                except (TypeError, ValueError):
                    voluntary = None
                try:
                    involuntary = int(status.get('nonvoluntary_ctxt_switches', ''))
                except (TypeError, ValueError):
                    involuntary = None

                state_text = status.get('State', stat_before.get('state', ''))
                record = {
                    'tid': tid,
                    'process': process_name,
                    'pid': pid,
                    'thread_name': thread_name,
                    'user': user,
                    'uid': uid if uid is not None else '',
                    'state': state_text,
                    'policy': policy,
                    'policy_num': attr.get('policy_num'),
                    'priority_nice': _priority_display(policy, attr.get('nice'), attr.get('priority')),
                    'nice': attr.get('nice'),
                    'rt_priority': attr.get('priority'),
                    'sched_flags': attr.get('flags'),
                    'sched_flags_text': attr.get('flags_text'),
                    'deadline_runtime_ns': attr.get('deadline_runtime_ns'),
                    'deadline_deadline_ns': attr.get('deadline_deadline_ns'),
                    'deadline_period_ns': attr.get('deadline_period_ns'),
                    'util_min': attr.get('util_min'),
                    'util_max': attr.get('util_max'),
                    'attribute_source': attr.get('source'),
                    'attribute_error': attr.get('error'),
                    'affinity': format_cpu_set(cpus),
                    'affinity_count': len(cpus),
                    'affinity_source': affinity_source,
                    'affinity_error': affinity_error,
                    'runtime': format_ns(runtime_ns) if runtime_ns is not None else 'Not reported',
                    'runtime_ns': runtime_ns,
                    'wait': format_ns(wait_ns) if wait_ns is not None else 'Not reported',
                    'wait_ns': wait_ns,
                    'slices': slices if slices is not None else '',
                    'last_cpu': stat_after.get('last_cpu', -1),
                    'starttime_ticks': stat_after.get('starttime_ticks', 0),
                    'voluntary_context_switches': voluntary,
                    'involuntary_context_switches': involuntary,
                    'unified_cgroup': unified_cgroup,
                    'cgroup_memberships': cgroup_lines,
                    'sched_ext_enabled': ext_enabled,
                }
                records.append(record)
                if not attr.get('available', False) or schedstat is None or not cpus:
                    partial += 1
            except FileNotFoundError:
                vanished += 1
            except PermissionError:
                inaccessible += 1
            except OSError:
                partial += 1

    records.sort(key=lambda rec: (int(rec.get('pid', 0)), int(rec.get('tid', 0))))
    return {
        'available': True,
        'error': '',
        'records': records,
        'vanished': vanished,
        'inaccessible': inaccessible,
        'partial': partial,
        'acquired_monotonic': time.monotonic(),
    }


def _parse_schedstat_lines(text):
    lines = [line.strip() for line in str(text or '').splitlines() if line.strip()]
    version = None
    timestamp = None
    cpu_rows = []
    domain_rows = []
    current_cpu = None
    malformed = 0

    for line in lines:
        parts = line.split()
        if not parts:
            continue
        if parts[0] == 'version' and len(parts) >= 2:
            try:
                version = int(parts[1])
            except ValueError:
                malformed += 1
            continue
        if parts[0] == 'timestamp' and len(parts) >= 2:
            try:
                timestamp = int(parts[1])
            except ValueError:
                timestamp = parts[1]
            continue
        if parts[0].startswith('cpu') and parts[0][3:].isdigit():
            current_cpu = int(parts[0][3:])
            raw_fields = parts[1:]
            values = []
            ok = True
            for field in raw_fields:
                try:
                    values.append(int(field))
                except ValueError:
                    ok = False
                    break
            if not ok:
                malformed += 1
                continue
            decoded = version in {14, 15, 16, 17} and len(values) >= 9
            row = {
                'cpu': current_cpu,
                'format_version': version if version is not None else '',
                'decoded': decoded,
                'raw_fields': values,
                'yield_calls': values[0] if decoded else None,
                'schedule_calls': values[2] if decoded else None,
                'idle_schedules': values[3] if decoded else None,
                'wakeups': values[4] if decoded else None,
                'local_wakeups': values[5] if decoded else None,
                'runtime_ns': values[6] if decoded else None,
                'wait_ns': values[7] if decoded else None,
                'slices': values[8] if decoded else None,
            }
            row.update({
                'runtime': format_ns(row['runtime_ns']) if row['runtime_ns'] is not None else 'Raw only',
                'wait': format_ns(row['wait_ns']) if row['wait_ns'] is not None else 'Raw only',
            })
            cpu_rows.append(row)
            continue
        if parts[0].startswith('domain') and parts[0][6:].isdigit() and current_cpu is not None:
            level = int(parts[0][6:])
            name = ''
            mask = ''
            counters_start = 1
            if version == 17 and len(parts) >= 4:
                name = parts[1]
                mask = parts[2]
                counters_start = 3
            elif len(parts) >= 3:
                mask = parts[1]
                counters_start = 2
            counters = []
            ok = True
            for field in parts[counters_start:]:
                try:
                    counters.append(int(field))
                except ValueError:
                    ok = False
                    break
            if not ok:
                malformed += 1
                continue
            cpus = parse_cpumask(mask)
            decoded = version == 17 and len(counters) >= 45
            balance_calls = move_failures = cross_cpu_wakeups = None
            if decoded:
                balance_calls = counters[0] + counters[11] + counters[22]
                move_failures = counters[2] + counters[13] + counters[24] + counters[34]
                cross_cpu_wakeups = counters[42]
            domain_rows.append({
                'cpu': current_cpu,
                'level': level,
                'name': name or f'Domain {level}',
                'cpu_span': format_cpu_set(cpus) or mask,
                'cpu_mask': mask,
                'balance_calls': balance_calls if balance_calls is not None else '',
                'move_failures': move_failures if move_failures is not None else '',
                'cross_cpu_wakeups': cross_cpu_wakeups if cross_cpu_wakeups is not None else '',
                'format_version': version if version is not None else '',
                'decoded': decoded,
                'raw_counters': counters,
            })
            continue
        # Unknown lines are ignored rather than poisoning the snapshot.

    return {
        'version': version,
        'timestamp': timestamp,
        'cpus': cpu_rows,
        'domains': domain_rows,
        'malformed_lines': malformed,
    }


def collect_schedstat(path=PROC / 'schedstat'):
    try:
        text = Path(path).read_text(errors='replace')
    except OSError as exc:
        return {
            'available': False,
            'error': str(exc),
            'version': None,
            'timestamp': None,
            'cpus': [],
            'domains': [],
            'malformed_lines': 0,
        }
    data = _parse_schedstat_lines(text)
    data.update({'available': True, 'error': ''})
    return data


_V17_PHASE_FIELDS = (
    'Balance calls',
    'No balance needed',
    'Move failures',
    'Imbalance load',
    'Imbalance utilization',
    'Imbalance tasks',
    'Imbalance misfit',
    'Detach task calls',
    'Detach cache-hot',
    'No busier queue',
    'No busier group',
)


def decode_domain_v17(counters):
    values = list(counters or [])
    if len(values) < 45:
        return None
    groups = {}
    for name, offset in (('Busy', 0), ('Idle', 11), ('Newly Idle', 22)):
        groups[name] = {label: values[offset + index] for index, label in enumerate(_V17_PHASE_FIELDS)}
    groups['Active Load Balance'] = {
        'Calls': values[33],
        'Move failures': values[34],
        'Successful moves': values[35],
    }
    groups['Exec Balance (unused)'] = {'Calls': values[36], 'Balanced': values[37], 'Pushed': values[38]}
    groups['Fork Balance (unused)'] = {'Calls': values[39], 'Balanced': values[40], 'Pushed': values[41]}
    groups['Wakeup / Passive Balance'] = {
        'Cross-CPU wakeups': values[42],
        'Moved to waking CPU (cache-cold)': values[43],
        'Passive balance starts': values[44],
    }
    return groups


def _read_optional_kernel_setting(name):
    path = PROC / 'sys' / 'kernel' / name
    if not path.exists():
        return {'available': False, 'path': str(path), 'value': '', 'error': 'Not exposed by this kernel.'}
    try:
        value = path.read_text(errors='replace').strip()
        return {'available': True, 'path': str(path), 'value': value, 'error': ''}
    except OSError as exc:
        return {'available': False, 'path': str(path), 'value': '', 'error': str(exc)}


def collect_scheduler_details():
    settings = {}
    for name in (
        'sched_schedstats',
        'sched_autogroup_enabled',
        'sched_rr_timeslice_ms',
        'sched_rt_period_us',
        'sched_rt_runtime_us',
        'sched_util_clamp_min',
        'sched_util_clamp_max',
        'sched_util_clamp_min_rt_default',
    ):
        settings[name] = _read_optional_kernel_setting(name)

    online = _read_text(SYS / 'devices/system/cpu/online', '')
    possible = _read_text(SYS / 'devices/system/cpu/possible', '')

    sched_ext_root = SYS / 'kernel/sched_ext'
    sched_ext = {
        'supported': sched_ext_root.exists(),
        'state': '',
        'enable_seq': '',
        'ops': '',
        'events': [],
    }
    if sched_ext['supported']:
        sched_ext['state'] = _read_text(sched_ext_root / 'state', '')
        sched_ext['enable_seq'] = _read_text(sched_ext_root / 'enable_seq', '')
        sched_ext['ops'] = _read_text(sched_ext_root / 'root/ops', '')
        events_raw = _read_text(sched_ext_root / 'root/events', '')
        events = []
        for line in events_raw.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                events.append((parts[0], parts[1]))
        sched_ext['events'] = events

    schedstat = collect_schedstat()
    return {
        'acquired_epoch': time.time(),
        'online_cpus': online,
        'possible_cpus': possible,
        'schedstat_available': schedstat.get('available', False),
        'schedstat_version': schedstat.get('version'),
        'schedstat_timestamp': schedstat.get('timestamp'),
        'schedstat_error': schedstat.get('error', ''),
        'settings': settings,
        'sched_ext': sched_ext,
    }
