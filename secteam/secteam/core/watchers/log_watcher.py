"""
Log watcher — tails journald and key log files in real time.
Parses each line into a structured SecurityEvent and publishes to the EventBus.

Handles: auth.log / journald auth, UFW logs, fail2ban, auditd, AppArmor,
         syslog, and any IDS log files present on the system.
"""

from __future__ import annotations
import asyncio
import logging
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

from secteam.models import ResponseMode, SecurityEvent, Severity
from secteam.core.event_bus import EventBus

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Pattern library — maps regex → event metadata
# ─────────────────────────────────────────────────────────────────────────────

class LogPattern:
    def __init__(self, pattern: str, event_type: str, severity: Severity,
                 response_mode: ResponseMode, extract: Optional[dict] = None):
        self.re          = re.compile(pattern, re.IGNORECASE)
        self.event_type  = event_type
        self.severity    = severity
        self.response_mode = response_mode
        self.extract     = extract or {}   # named group -> enriched field name


AUTH_PATTERNS: list[LogPattern] = [
    LogPattern(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d\.]+) port (?P<port>\d+)",
        "failed_login", Severity.MEDIUM, ResponseMode.INFORM,
        {"user": "username", "ip": "src_ip", "port": "src_port"},
    ),
    LogPattern(
        r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d\.]+)",
        "successful_login", Severity.INFO, ResponseMode.INFORM,
        {"method": "auth_method", "user": "username", "ip": "src_ip"},
    ),
    LogPattern(
        r"Invalid user (?P<user>\S+) from (?P<ip>[\d\.]+)",
        "invalid_user_login", Severity.MEDIUM, ResponseMode.INFORM,
        {"user": "username", "ip": "src_ip"},
    ),
    LogPattern(
        r"sudo:\s+(?P<user>\S+)\s+:.*COMMAND=(?P<cmd>.+)",
        "sudo_command", Severity.INFO, ResponseMode.INFORM,
        {"user": "username", "cmd": "command"},
    ),
    LogPattern(
        r"pam_unix.*authentication failure.*user=(?P<user>\S+)",
        "pam_auth_failure", Severity.MEDIUM, ResponseMode.INFORM,
        {"user": "username"},
    ),
    LogPattern(
        r"session opened for user root",
        "root_session_opened", Severity.HIGH, ResponseMode.REQUEST,
        {},
    ),
    LogPattern(
        r"useradd.*name=(?P<user>\S+)",
        "user_created", Severity.HIGH, ResponseMode.REQUEST,
        {"user": "username"},
    ),
    LogPattern(
        r"usermod.*-G.*(?P<user>\S+)",
        "user_group_changed", Severity.HIGH, ResponseMode.REQUEST,
        {"user": "username"},
    ),
    LogPattern(
        r"passwd.*password changed for (?P<user>\S+)",
        "password_changed", Severity.MEDIUM, ResponseMode.INFORM,
        {"user": "username"},
    ),
]

UFW_PATTERNS: list[LogPattern] = [
    LogPattern(
        r"\[UFW BLOCK\].*SRC=(?P<src>[\d\.]+).*DST=(?P<dst>[\d\.]+).*DPT=(?P<dpt>\d+)",
        "ufw_block", Severity.LOW, ResponseMode.INFORM,
        {"src": "src_ip", "dst": "dst_ip", "dpt": "dst_port"},
    ),
    LogPattern(
        r"\[UFW ALLOW\].*SRC=(?P<src>[\d\.]+).*DST=(?P<dst>[\d\.]+).*DPT=(?P<dpt>\d+)",
        "ufw_allow", Severity.INFO, ResponseMode.INFORM,
        {"src": "src_ip", "dst": "dst_ip", "dpt": "dst_port"},
    ),
]

FAIL2BAN_PATTERNS: list[LogPattern] = [
    LogPattern(
        r"Ban (?P<ip>[\d\.]+)",
        "fail2ban_ban", Severity.MEDIUM, ResponseMode.INFORM,
        {"ip": "banned_ip"},
    ),
    LogPattern(
        r"Unban (?P<ip>[\d\.]+)",
        "fail2ban_unban", Severity.INFO, ResponseMode.INFORM,
        {"ip": "unbanned_ip"},
    ),
    LogPattern(
        r"Found (?P<ip>[\d\.]+) - (?P<time>\S+) (?P<count>\d+) times",
        "fail2ban_found", Severity.LOW, ResponseMode.INFORM,
        {"ip": "src_ip"},
    ),
]

AUDITD_PATTERNS: list[LogPattern] = [
    LogPattern(
        r"type=EXECVE.*argc=(?P<argc>\d+).*a0=\"(?P<cmd>[^\"]+)\"",
        "auditd_execve", Severity.INFO, ResponseMode.INFORM,
        {"argc": "arg_count", "cmd": "command"},
    ),
    LogPattern(
        r"type=USER_AUTH.*res=failed.*acct=\"(?P<user>[^\"]+)\"",
        "auditd_auth_fail", Severity.MEDIUM, ResponseMode.INFORM,
        {"user": "username"},
    ),
    LogPattern(
        r"type=SYSCALL.*key=\"(?P<key>[^\"]+)\"",
        "auditd_syscall_watch", Severity.MEDIUM, ResponseMode.INFORM,
        {"key": "audit_key"},
    ),
    LogPattern(
        r"type=PATH.*name=\"(?P<path>[^\"]+)\".*nametype=(?P<ntype>\S+)",
        "auditd_path_access", Severity.INFO, ResponseMode.INFORM,
        {"path": "file_path", "ntype": "access_type"},
    ),
]

APPARMOR_PATTERNS: list[LogPattern] = [
    LogPattern(
        r"apparmor.*DENIED.*profile=\"(?P<profile>[^\"]+)\".*name=\"(?P<name>[^\"]+)\"",
        "apparmor_denial", Severity.HIGH, ResponseMode.INFORM,
        {"profile": "aa_profile", "name": "resource"},
    ),
]

IDS_PATTERNS: list[LogPattern] = [
    # Suricata EVE-style alert in syslog
    LogPattern(
        r"Suricata.*\[(?P<gid>\d+):(?P<sid>\d+):\d+\].*\{(?P<proto>\S+)\}.*(?P<src>[\d\.]+):\d+.*(?P<dst>[\d\.]+):\d+",
        "suricata_alert", Severity.HIGH, ResponseMode.REQUEST,
        {"gid": "gid", "sid": "sid", "proto": "protocol", "src": "src_ip", "dst": "dst_ip"},
    ),
    LogPattern(
        r"snort.*\[\*\*\].*\[\d+:\d+:\d+\].*(?P<msg>.+)\[\*\*\]",
        "snort_alert", Severity.HIGH, ResponseMode.REQUEST,
        {"msg": "alert_message"},
    ),
]

# All patterns grouped by source
SOURCE_PATTERNS: dict[str, list[LogPattern]] = {
    "auth":     AUTH_PATTERNS,
    "ufw":      UFW_PATTERNS,
    "fail2ban": FAIL2BAN_PATTERNS,
    "auditd":   AUDITD_PATTERNS,
    "apparmor": APPARMOR_PATTERNS,
    "ids":      IDS_PATTERNS,
}


def classify_line(line: str, source: str) -> Optional[SecurityEvent]:
    """Try to match a log line against patterns for the given source."""
    patterns = SOURCE_PATTERNS.get(source, [])
    # also try IDS patterns against any source
    if source not in ("ids",):
        patterns = patterns + IDS_PATTERNS

    for pattern in patterns:
        m = pattern.re.search(line)
        if m:
            enriched = {}
            for group_name, field_name in pattern.extract.items():
                try:
                    enriched[field_name] = m.group(group_name)
                except IndexError:
                    pass

            return SecurityEvent(
                source=source,
                severity=pattern.severity,
                event_type=pattern.event_type,
                raw=line.strip(),
                enriched=enriched,
                confidence=0.85,
                response_mode=pattern.response_mode,
            )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Watcher implementations
# ─────────────────────────────────────────────────────────────────────────────

class JournaldWatcher:
    """Tails journald in real time via `journalctl -f --output=short-iso`."""

    UNIT_SOURCE_MAP = {
        "sshd":     "auth",
        "sudo":     "auth",
        "su":       "auth",
        "ufw":      "ufw",
        "fail2ban": "fail2ban",
        "auditd":   "auditd",
        "suricata": "ids",
        "snort":    "ids",
    }

    def __init__(self, bus: EventBus) -> None:
        self._bus = bus
        self._proc: Optional[asyncio.subprocess.Process] = None

    async def start(self) -> None:
        self._proc = await asyncio.create_subprocess_exec(
            "journalctl", "-f", "--output=short-iso", "--no-pager",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        log.info("JournaldWatcher started")
        assert self._proc.stdout
        async for raw_line in self._proc.stdout:
            line = raw_line.decode("utf-8", errors="replace")
            source = self._detect_source(line)
            event = classify_line(line, source)
            if event:
                event.timestamp = datetime.utcnow()
                self._bus.publish(event)

    def _detect_source(self, line: str) -> str:
        line_lower = line.lower()
        for keyword, source in self.UNIT_SOURCE_MAP.items():
            if keyword in line_lower:
                return source
        if "ufw" in line_lower or "kernel" in line_lower and "dpt=" in line_lower:
            return "ufw"
        if "apparmor" in line_lower:
            return "apparmor"
        return "syslog"

    async def stop(self) -> None:
        if self._proc:
            self._proc.terminate()


class FileLogWatcher:
    """Tails a specific log file using tail -F (handles rotation)."""

    def __init__(self, bus: EventBus, path: str, source: str) -> None:
        self._bus    = bus
        self._path   = path
        self._source = source
        self._proc: Optional[asyncio.subprocess.Process] = None

    async def start(self) -> None:
        if not Path(self._path).exists():
            log.debug("Log file not found, skipping: %s", self._path)
            return

        self._proc = await asyncio.create_subprocess_exec(
            "tail", "-F", "-n", "0", self._path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        log.info("FileLogWatcher started: %s [%s]", self._path, self._source)
        assert self._proc.stdout
        async for raw_line in self._proc.stdout:
            line = raw_line.decode("utf-8", errors="replace")
            event = classify_line(line, self._source)
            if event:
                event.source = f"{self._source}:{self._path}"
                self._bus.publish(event)

    async def stop(self) -> None:
        if self._proc:
            self._proc.terminate()


class LogWatcherManager:
    """Starts and manages all log watchers based on what's present."""

    FILE_WATCHERS = [
        ("/var/log/auth.log",              "auth"),
        ("/var/log/ufw.log",               "ufw"),
        ("/var/log/fail2ban.log",          "fail2ban"),
        ("/var/log/audit/audit.log",       "auditd"),
        ("/var/log/snort/alert",           "ids"),
        ("/var/log/suricata/fast.log",     "ids"),
        ("/var/log/suricata/eve.json",     "ids"),
        ("/var/log/ossec/logs/alerts.log", "ids"),
        ("/var/log/syslog",                "syslog"),
    ]

    def __init__(self, bus: EventBus) -> None:
        self._bus      = bus
        self._watchers = []

    async def start_all(self) -> None:
        tasks = []

        # Always start journald watcher
        j = JournaldWatcher(self._bus)
        self._watchers.append(j)
        tasks.append(asyncio.create_task(j.start()))

        # Start file watchers for any logs that exist
        for path, source in self.FILE_WATCHERS:
            if Path(path).exists():
                w = FileLogWatcher(self._bus, path, source)
                self._watchers.append(w)
                tasks.append(asyncio.create_task(w.start()))

        log.info("Started %d log watchers", len(self._watchers))
        await asyncio.gather(*tasks, return_exceptions=True)

    async def stop_all(self) -> None:
        for w in self._watchers:
            await w.stop()
