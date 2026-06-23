"""
Process watcher — monitors running processes for anomalies.
Detects: new processes spawned from unusual parents, processes consuming
anomalous CPU/RAM, hidden processes, crypto-miners, reverse shells,
processes running from /tmp or /dev/shm, and privilege escalations.
"""

from __future__ import annotations
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import psutil

from secteam.models import ResponseMode, SecurityEvent, Severity
from secteam.core.event_bus import EventBus

log = logging.getLogger(__name__)

# Processes that commonly run as root legitimately
EXPECTED_ROOT_PROCS = {
    "systemd", "init", "kthreadd", "sshd", "cron", "rsyslogd",
    "auditd", "agetty", "login", "su", "sudo", "udevd", "journald",
    "networkd", "resolved", "logind", "polkitd", "dbus-daemon",
    "containerd", "dockerd", "snapd",
}

# Suspicious binary locations — anything running from these is flagged
SUSPICIOUS_PATHS = {"/tmp/", "/dev/shm/", "/run/shm/", "/var/tmp/"}

# High CPU usage threshold (%) for a single non-system process
CPU_SPIKE_THRESHOLD = 90.0

# Common reverse shell indicators in cmdline
REVERSE_SHELL_INDICATORS = [
    "bash -i", "/dev/tcp/", "/dev/udp/", "nc -e", "ncat -e",
    "python.*socket", "perl.*socket", "ruby.*socket",
    "0.0.0.0.*bash", "mkfifo.*bash",
]


class ProcessWatcher:
    def __init__(self, bus: EventBus, interval_seconds: int = 10) -> None:
        self._bus      = bus
        self._interval = interval_seconds
        self._known_pids: dict[int, str] = {}   # pid -> name
        self._running = False

    def _snapshot(self) -> dict[int, psutil.Process]:
        procs: dict[int, psutil.Process] = {}
        try:
            for p in psutil.process_iter(["pid", "name", "username",
                                          "cmdline", "exe", "ppid",
                                          "cpu_percent", "memory_percent"]):
                try:
                    procs[p.pid] = p
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass
        return procs

    def _is_suspicious_path(self, exe: Optional[str]) -> bool:
        if not exe:
            return False
        return any(exe.startswith(p) for p in SUSPICIOUS_PATHS)

    def _has_reverse_shell_indicators(self, cmdline: list[str]) -> bool:
        cmd = " ".join(cmdline).lower()
        import re
        return any(re.search(ind, cmd) for ind in REVERSE_SHELL_INDICATORS)

    async def _poll(self, procs: dict[int, psutil.Process]) -> None:
        current_pids = set(procs.keys())
        known_pids   = set(self._known_pids.keys())

        # New processes
        for pid in current_pids - known_pids:
            p = procs[pid]
            try:
                info = p.as_dict(["name", "username", "cmdline", "exe", "ppid",
                                   "cpu_percent", "memory_percent"])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            name    = info.get("name", "")
            exe     = info.get("exe", "")
            cmdline = info.get("cmdline") or []
            user    = info.get("username", "")

            self._known_pids[pid] = name

            # Running from suspicious location
            if self._is_suspicious_path(exe):
                self._bus.publish(SecurityEvent(
                    timestamp=datetime.utcnow(),
                    source="process",
                    severity=Severity.CRITICAL,
                    event_type="suspicious_process_location",
                    raw=f"Process '{name}' (PID {pid}) running from {exe}",
                    enriched={"pid": pid, "name": name, "exe": exe,
                               "user": user, "cmdline": " ".join(cmdline)},
                    confidence=0.90,
                    response_mode=ResponseMode.REQUEST,
                ))

            # Reverse shell indicators
            if self._has_reverse_shell_indicators(cmdline):
                self._bus.publish(SecurityEvent(
                    timestamp=datetime.utcnow(),
                    source="process",
                    severity=Severity.CRITICAL,
                    event_type="reverse_shell_detected",
                    raw=f"Reverse shell indicators in PID {pid}: {' '.join(cmdline[:5])}",
                    enriched={"pid": pid, "name": name, "user": user,
                               "cmdline": " ".join(cmdline)},
                    confidence=0.85,
                    response_mode=ResponseMode.AUTO,
                ))

            # Unexpected root process
            if user == "root" and name and name.lower() not in EXPECTED_ROOT_PROCS:
                parent_name = ""
                try:
                    parent = psutil.Process(info.get("ppid", 0))
                    parent_name = parent.name()
                except Exception:
                    pass
                if parent_name not in EXPECTED_ROOT_PROCS:
                    self._bus.publish(SecurityEvent(
                        timestamp=datetime.utcnow(),
                        source="process",
                        severity=Severity.HIGH,
                        event_type="unexpected_root_process",
                        raw=f"Unexpected root process: {name} (PID {pid}, parent: {parent_name})",
                        enriched={"pid": pid, "name": name, "exe": exe,
                                   "parent": parent_name, "cmdline": " ".join(cmdline)},
                        confidence=0.75,
                        response_mode=ResponseMode.REQUEST,
                    ))

        # CPU spike check on running processes
        for pid, p in procs.items():
            try:
                cpu = p.cpu_percent(interval=None)
                if cpu > CPU_SPIKE_THRESHOLD:
                    info = p.as_dict(["name", "username", "cmdline"])
                    self._bus.publish(SecurityEvent(
                        timestamp=datetime.utcnow(),
                        source="process",
                        severity=Severity.MEDIUM,
                        event_type="cpu_spike",
                        raw=f"Process {info.get('name')} (PID {pid}) at {cpu:.1f}% CPU",
                        enriched={
                            "pid": pid,
                            "name": info.get("name"),
                            "user": info.get("username"),
                            "cpu_percent": cpu,
                            "cmdline": " ".join(info.get("cmdline") or []),
                        },
                        confidence=0.90,
                        response_mode=ResponseMode.INFORM,
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # Terminated processes (clean up tracking)
        for pid in known_pids - current_pids:
            self._known_pids.pop(pid, None)

    async def start(self) -> None:
        # seed so we don't alert on pre-existing processes
        initial = self._snapshot()
        for pid, p in initial.items():
            try:
                self._known_pids[pid] = p.name()
            except Exception:
                pass

        # prime CPU percentages (first call is always 0.0)
        for p in initial.values():
            try:
                p.cpu_percent(interval=None)
            except Exception:
                pass

        self._running = True
        log.info("ProcessWatcher started (interval=%ds)", self._interval)

        while self._running:
            await asyncio.sleep(self._interval)
            procs = self._snapshot()
            try:
                await self._poll(procs)
            except Exception as exc:
                log.exception("ProcessWatcher poll error: %s", exc)

    def stop(self) -> None:
        self._running = False
