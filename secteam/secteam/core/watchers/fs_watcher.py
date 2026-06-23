"""
Filesystem watcher — uses inotify to watch critical paths for unauthorized
modifications.  Detects: config file changes, new SUID files, changes to
binaries in system dirs, new files in /tmp and /dev/shm, and cron changes.
"""

from __future__ import annotations
import asyncio
import hashlib
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from secteam.models import ResponseMode, SecurityEvent, Severity
from secteam.core.event_bus import EventBus

log = logging.getLogger(__name__)


CRITICAL_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/hosts",
    "/etc/crontab",
    "/etc/pam.d",
    "/etc/security",
    "/etc/apt/sources.list",
    "/etc/apt/sources.list.d",
    "/etc/systemd/system",
    "/etc/init.d",
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/usr/lib",
    "/boot",
    "/root/.ssh",
    "/home",
]

WATCHED_FOR_NEW_FILES = [
    "/tmp",
    "/dev/shm",
    "/var/tmp",
    "/run",
]

SYSTEM_BIN_DIRS = {"/usr/bin", "/usr/sbin", "/bin", "/sbin"}


def _sha256(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _is_suid(path: str) -> bool:
    try:
        return bool(os.stat(path).st_mode & 0o4000)
    except Exception:
        return False


class SecteamFSHandler(FileSystemEventHandler):
    def __init__(self, bus: EventBus, checksums: dict[str, str]) -> None:
        super().__init__()
        self._bus       = bus
        self._checksums = checksums   # path -> known sha256

    def _is_binary_changed(self, path: str) -> bool:
        return any(path.startswith(d) for d in SYSTEM_BIN_DIRS)

    def _publish(self, event: SecurityEvent) -> None:
        self._bus.publish(event)

    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        path = event.src_path
        new_hash = _sha256(path)
        old_hash = self._checksums.get(path)

        if new_hash and old_hash and new_hash == old_hash:
            return   # metadata-only change (access time etc.)

        if new_hash:
            self._checksums[path] = new_hash

        severity = Severity.HIGH
        mode     = ResponseMode.REQUEST

        if self._is_binary_changed(path):
            severity = Severity.CRITICAL
            mode     = ResponseMode.AUTO

        self._publish(SecurityEvent(
            timestamp=datetime.utcnow(),
            source="filesystem",
            severity=severity,
            event_type="config_or_binary_modified",
            raw=f"File modified: {path}",
            enriched={
                "path": path,
                "old_hash": old_hash,
                "new_hash": new_hash,
                "is_system_binary": self._is_binary_changed(path),
            },
            confidence=0.95,
            response_mode=mode,
        ))

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        path  = event.src_path
        ppath = Path(path)

        # New executable in /tmp, /dev/shm etc.
        if any(path.startswith(w) for w in WATCHED_FOR_NEW_FILES):
            try:
                executable = os.access(path, os.X_OK)
            except Exception:
                executable = False

            self._publish(SecurityEvent(
                timestamp=datetime.utcnow(),
                source="filesystem",
                severity=Severity.HIGH if executable else Severity.MEDIUM,
                event_type="new_file_in_tmp",
                raw=f"New {'executable ' if executable else ''}file in {ppath.parent}: {ppath.name}",
                enriched={
                    "path": path,
                    "executable": executable,
                    "size": ppath.stat().st_size if ppath.exists() else None,
                },
                confidence=0.90,
                response_mode=ResponseMode.REQUEST if executable else ResponseMode.INFORM,
            ))

        # New SUID file anywhere
        if _is_suid(path):
            self._publish(SecurityEvent(
                timestamp=datetime.utcnow(),
                source="filesystem",
                severity=Severity.CRITICAL,
                event_type="new_suid_file",
                raw=f"New SUID file created: {path}",
                enriched={"path": path, "hash": _sha256(path)},
                confidence=0.98,
                response_mode=ResponseMode.REQUEST,
            ))

        # New authorized_keys file
        if "authorized_keys" in path:
            self._publish(SecurityEvent(
                timestamp=datetime.utcnow(),
                source="filesystem",
                severity=Severity.HIGH,
                event_type="ssh_authorized_keys_changed",
                raw=f"SSH authorized_keys file created/modified: {path}",
                enriched={"path": path},
                confidence=0.95,
                response_mode=ResponseMode.REQUEST,
            ))

    def on_deleted(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        path = event.src_path
        if path in self._checksums:
            self._publish(SecurityEvent(
                timestamp=datetime.utcnow(),
                source="filesystem",
                severity=Severity.HIGH,
                event_type="critical_file_deleted",
                raw=f"Critical file deleted: {path}",
                enriched={"path": path, "last_hash": self._checksums.get(path)},
                confidence=0.95,
                response_mode=ResponseMode.REQUEST,
            ))
            self._checksums.pop(path, None)


class FilesystemWatcher:
    def __init__(self, bus: EventBus, baseline_checksums: dict[str, str] | None = None) -> None:
        self._bus       = bus
        self._checksums = dict(baseline_checksums or {})
        self._observer  = Observer()

    async def start(self) -> None:
        handler = SecteamFSHandler(self._bus, self._checksums)
        watched = set()

        all_paths = CRITICAL_PATHS + WATCHED_FOR_NEW_FILES
        for path_str in all_paths:
            p = Path(path_str)
            if not p.exists():
                continue
            watch_dir = str(p) if p.is_dir() else str(p.parent)
            if watch_dir not in watched:
                recursive = p.is_dir() and path_str not in WATCHED_FOR_NEW_FILES
                self._observer.schedule(handler, watch_dir, recursive=recursive)
                watched.add(watch_dir)

        self._observer.start()
        log.info("FilesystemWatcher started — watching %d paths", len(watched))

        # Run in background thread (watchdog is thread-based)
        while self._observer.is_alive():
            await asyncio.sleep(1)

    def stop(self) -> None:
        self._observer.stop()
        self._observer.join()
