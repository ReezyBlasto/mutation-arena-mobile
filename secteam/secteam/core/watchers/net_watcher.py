"""
Network watcher — polls active connections and listening ports every N seconds.
Detects: new listening ports, suspicious outbound connections, connections to
known bad IPs, unusual traffic volumes, and connection count spikes.
"""

from __future__ import annotations
import asyncio
import logging
from datetime import datetime
from typing import Optional

import psutil

from secteam.models import ResponseMode, SecurityEvent, Severity
from secteam.core.event_bus import EventBus

log = logging.getLogger(__name__)

# IPs known to be malicious — seeded here, expanded by threat intel at runtime
KNOWN_BAD_IPS: set[str] = set()

# Ports that are normal to be open; anything else gets flagged
EXPECTED_LISTENING_PORTS: set[int] = set()


class NetworkWatcher:
    def __init__(self, bus: EventBus, interval_seconds: int = 15) -> None:
        self._bus      = bus
        self._interval = interval_seconds
        self._known_ports: set[tuple[int, str]] = set()   # (port, proto)
        self._known_connections: set[tuple] = set()
        self._connection_counts: dict[str, int] = {}      # src_ip -> count
        self._running = False

    def add_known_bad_ip(self, ip: str) -> None:
        KNOWN_BAD_IPS.add(ip)

    def set_expected_ports(self, ports: set[int]) -> None:
        EXPECTED_LISTENING_PORTS.update(ports)

    def _current_ports(self) -> set[tuple[int, str]]:
        ports = set()
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "LISTEN" or conn.type == psutil.socket.SOCK_DGRAM:
                    if conn.laddr:
                        proto = "tcp" if conn.type == psutil.socket.SOCK_STREAM else "udp"
                        ports.add((conn.laddr.port, proto))
        except psutil.AccessDenied:
            pass
        return ports

    def _current_connections(self) -> list[psutil.sconn]:
        try:
            return psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            return []

    async def _poll(self) -> None:
        current_ports = self._current_ports()

        # New listening port
        new_ports = current_ports - self._known_ports
        for port, proto in new_ports:
            if EXPECTED_LISTENING_PORTS and port not in EXPECTED_LISTENING_PORTS:
                severity = Severity.HIGH
                mode     = ResponseMode.REQUEST
            else:
                severity = Severity.INFO
                mode     = ResponseMode.INFORM

            # find owning process
            proc_name: Optional[str] = None
            proc_pid:  Optional[int] = None
            try:
                for conn in psutil.net_connections(kind="inet"):
                    if conn.laddr and conn.laddr.port == port and conn.pid:
                        proc_name = psutil.Process(conn.pid).name()
                        proc_pid  = conn.pid
                        break
            except Exception:
                pass

            self._bus.publish(SecurityEvent(
                timestamp=datetime.utcnow(),
                source="network",
                severity=severity,
                event_type="new_listening_port",
                raw=f"New {proto.upper()} port {port} opened",
                enriched={
                    "port": port,
                    "protocol": proto,
                    "process": proc_name,
                    "pid": proc_pid,
                },
                confidence=0.95,
                response_mode=mode,
            ))

        # Closed port (informational)
        closed_ports = self._known_ports - current_ports
        for port, proto in closed_ports:
            self._bus.publish(SecurityEvent(
                timestamp=datetime.utcnow(),
                source="network",
                severity=Severity.INFO,
                event_type="port_closed",
                raw=f"{proto.upper()} port {port} is no longer listening",
                enriched={"port": port, "protocol": proto},
                confidence=0.95,
                response_mode=ResponseMode.INFORM,
            ))

        self._known_ports = current_ports

        # Outbound connections to known-bad IPs
        conns = self._current_connections()
        ip_counts: dict[str, int] = {}

        for conn in conns:
            if not conn.raddr:
                continue
            remote_ip = conn.raddr.ip
            ip_counts[remote_ip] = ip_counts.get(remote_ip, 0) + 1

            if remote_ip in KNOWN_BAD_IPS:
                proc_name = None
                try:
                    if conn.pid:
                        proc_name = psutil.Process(conn.pid).name()
                except Exception:
                    pass
                self._bus.publish(SecurityEvent(
                    timestamp=datetime.utcnow(),
                    source="network",
                    severity=Severity.CRITICAL,
                    event_type="connection_to_known_bad_ip",
                    raw=f"Connection to known-bad IP {remote_ip}",
                    enriched={
                        "dst_ip": remote_ip,
                        "dst_port": conn.raddr.port,
                        "process": proc_name,
                        "pid": conn.pid,
                    },
                    confidence=0.95,
                    response_mode=ResponseMode.AUTO,
                    iocs=[remote_ip],
                ))

        # Connection count spike (possible scan / DDoS from single source)
        for ip, count in ip_counts.items():
            prev = self._connection_counts.get(ip, 0)
            if count > 50 and count > prev * 3:
                self._bus.publish(SecurityEvent(
                    timestamp=datetime.utcnow(),
                    source="network",
                    severity=Severity.HIGH,
                    event_type="connection_spike",
                    raw=f"Connection spike from {ip}: {count} connections",
                    enriched={"src_ip": ip, "count": count, "previous": prev},
                    confidence=0.80,
                    response_mode=ResponseMode.REQUEST,
                    iocs=[ip],
                ))

        self._connection_counts = ip_counts

    async def start(self) -> None:
        # seed known ports so we don't alert on pre-existing state
        self._known_ports = self._current_ports()
        self._running = True
        log.info("NetworkWatcher started (interval=%ds)", self._interval)

        while self._running:
            try:
                await self._poll()
            except Exception as exc:
                log.exception("NetworkWatcher poll error: %s", exc)
            await asyncio.sleep(self._interval)

    def stop(self) -> None:
        self._running = False
