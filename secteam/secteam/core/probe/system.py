"""
Full system inventory probe.  Discovers every package, service, port, user,
cron job, firewall rule, SUID file, kernel hardening param, and security tool
present on the system.  Result becomes the ground truth that all agents operate from.
"""

from __future__ import annotations
import grp
import hashlib
import os
import pwd
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

import psutil

from secteam.models import (
    CronJob, FirewallRule, InstalledPackage, KernelHardening,
    ListeningPort, RunningService, SecurityTool, ToolStatus,
    SuidFile, SystemInventory, SystemUser,
)
from secteam.core.probe.hardware import probe_hardware


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 30) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def _run_root(cmd: list[str], timeout: int = 30) -> str:
    """Try with sudo if not already root."""
    if os.geteuid() == 0:
        return _run(cmd, timeout)
    return _run(["sudo", "-n"] + cmd, timeout)


def _sha256(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Packages
# ─────────────────────────────────────────────────────────────────────────────

def _probe_packages() -> list[InstalledPackage]:
    out = _run(["dpkg-query", "-W",
                "--showformat=${Package}\t${Version}\t${Architecture}\t${Description}\n"])
    packages = []
    for line in out.splitlines():
        parts = line.split("\t", 3)
        if len(parts) >= 3:
            packages.append(InstalledPackage(
                name=parts[0],
                version=parts[1],
                architecture=parts[2],
                description=parts[3].splitlines()[0] if len(parts) > 3 else None,
            ))
    return packages


# ─────────────────────────────────────────────────────────────────────────────
# Services
# ─────────────────────────────────────────────────────────────────────────────

def _probe_services() -> list[RunningService]:
    out = _run(["systemctl", "list-units", "--type=service",
                "--all", "--no-pager", "--no-legend",
                "--output=json"])
    services = []

    if out.startswith("["):
        import json
        try:
            units = json.loads(out)
            for u in units:
                services.append(RunningService(
                    name=u.get("unit", "").replace(".service", ""),
                    state=u.get("active", "unknown"),
                    enabled=u.get("load", "") == "loaded",
                    description=u.get("description"),
                ))
            return services
        except Exception:
            pass

    # fallback: parse plain text output
    out = _run(["systemctl", "list-units", "--type=service", "--all",
                "--no-pager", "--no-legend"])
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            name = parts[0].replace(".service", "")
            state = parts[2]
            desc = " ".join(parts[4:]) if len(parts) > 4 else None
            services.append(RunningService(
                name=name, state=state, enabled=True, description=desc))

    return services


# ─────────────────────────────────────────────────────────────────────────────
# Ports
# ─────────────────────────────────────────────────────────────────────────────

def _probe_ports() -> list[ListeningPort]:
    ports: list[ListeningPort] = []
    seen: set[tuple] = set()

    for conn in psutil.net_connections(kind="inet"):
        if conn.status != "LISTEN" and conn.type != psutil.socket.SOCK_DGRAM:
            continue
        if conn.laddr:
            key = (conn.laddr.port, conn.type)
            if key in seen:
                continue
            seen.add(key)
            proto = "tcp" if conn.type == psutil.socket.SOCK_STREAM else "udp"
            proc_name = None
            try:
                if conn.pid:
                    proc_name = psutil.Process(conn.pid).name()
            except Exception:
                pass
            ports.append(ListeningPort(
                port=conn.laddr.port,
                protocol=proto,
                address=conn.laddr.ip,
                process=proc_name,
                pid=conn.pid,
            ))

    return sorted(ports, key=lambda p: p.port)


# ─────────────────────────────────────────────────────────────────────────────
# Users
# ─────────────────────────────────────────────────────────────────────────────

def _has_sudo(username: str) -> bool:
    try:
        groups = [g.gr_name for g in grp.getgrall() if username in g.gr_mem]
        if "sudo" in groups or "wheel" in groups or "admin" in groups:
            return True
        sudoers_out = _run_root(["grep", "-r", username, "/etc/sudoers", "/etc/sudoers.d/"])
        return bool(sudoers_out.strip())
    except Exception:
        return False


def _last_login(username: str) -> Optional[str]:
    out = _run(["lastlog", "-u", username])
    lines = out.splitlines()
    if len(lines) >= 2:
        return lines[1].strip()
    return None


def _probe_users() -> list[SystemUser]:
    users = []
    for p in pwd.getpwall():
        if p.pw_uid < 1000 and p.pw_uid != 0:
            continue   # skip system accounts except root
        if p.pw_shell in ("/bin/false", "/usr/sbin/nologin", "/sbin/nologin"):
            continue
        users.append(SystemUser(
            username=p.pw_name,
            uid=p.pw_uid,
            gid=p.pw_gid,
            home=p.pw_dir,
            shell=p.pw_shell,
            sudo_access=_has_sudo(p.pw_name),
            last_login=_last_login(p.pw_name),
        ))
    return users


# ─────────────────────────────────────────────────────────────────────────────
# Cron
# ─────────────────────────────────────────────────────────────────────────────

def _probe_crons() -> list[CronJob]:
    jobs = []

    # /etc/crontab
    for path in ["/etc/crontab"] + list(Path("/etc/cron.d").glob("*") if Path("/etc/cron.d").exists() else []):
        try:
            for line in Path(path).read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 7:
                    jobs.append(CronJob(
                        owner=parts[5],
                        schedule=" ".join(parts[:5]),
                        command=" ".join(parts[6:]),
                        source=str(path),
                    ))
        except Exception:
            continue

    # User crontabs
    for user in pwd.getpwall():
        if user.pw_uid < 1000 and user.pw_uid != 0:
            continue
        out = _run(["crontab", "-l", "-u", user.pw_name])
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 6:
                jobs.append(CronJob(
                    owner=user.pw_name,
                    schedule=" ".join(parts[:5]),
                    command=" ".join(parts[5:]),
                    source=f"crontab:{user.pw_name}",
                ))

    # Systemd timers
    out = _run(["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"])
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 6:
            jobs.append(CronJob(
                owner="systemd",
                schedule=parts[0],
                command=parts[5] if len(parts) > 5 else parts[-1],
                source="systemd-timer",
            ))

    return jobs


# ─────────────────────────────────────────────────────────────────────────────
# Firewall
# ─────────────────────────────────────────────────────────────────────────────

def _probe_firewall() -> list[FirewallRule]:
    rules = []

    # UFW
    ufw_out = _run_root(["ufw", "status", "numbered"])
    for line in ufw_out.splitlines():
        m = re.match(r"\[\s*(\d+)\]\s+(.+?)\s+(ALLOW|DENY|REJECT)\s+(IN|OUT|FWD)?\s*(.*)", line)
        if m:
            rules.append(FirewallRule(
                number=int(m.group(1)),
                action=m.group(3),
                direction=m.group(4) or "IN",
                comment=m.group(5).strip() or None,
            ))

    # iptables fallback
    if not rules and shutil.which("iptables"):
        ipt_out = _run_root(["iptables", "-L", "-n", "--line-numbers"])
        for line in ipt_out.splitlines():
            parts = line.split()
            if parts and parts[0].isdigit() and len(parts) >= 4:
                rules.append(FirewallRule(
                    number=int(parts[0]),
                    action=parts[1],
                    direction="IN",
                    protocol=parts[2] if parts[2] != "all" else None,
                    from_addr=parts[4] if len(parts) > 4 else None,
                    to_addr=parts[5] if len(parts) > 5 else None,
                ))

    return rules


# ─────────────────────────────────────────────────────────────────────────────
# SUID files
# ─────────────────────────────────────────────────────────────────────────────

KNOWN_SAFE_SUID = {
    "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
    "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/gpasswd",
    "/usr/bin/newgrp", "/usr/sbin/pppd", "/bin/ping",
    "/usr/bin/pkexec", "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/bin/mount", "/usr/bin/umount",
}


def _probe_suid() -> list[SuidFile]:
    out = _run_root(["find", "/", "-xdev", "-type", "f",
                     "-perm", "/4000", "-o", "-perm", "/2000"],
                    timeout=60)
    files = []
    for path in out.splitlines():
        path = path.strip()
        if not path:
            continue
        try:
            stat = os.stat(path)
            perms = oct(stat.st_mode)[-4:]
            owner = pwd.getpwuid(stat.st_uid).pw_name
        except Exception:
            perms, owner = "????", "unknown"
        files.append(SuidFile(
            path=path,
            owner=owner,
            permissions=perms,
            known_safe=path in KNOWN_SAFE_SUID,
        ))
    return files


# ─────────────────────────────────────────────────────────────────────────────
# Kernel hardening
# ─────────────────────────────────────────────────────────────────────────────

def _sysctl(key: str) -> Optional[str]:
    out = _run(["sysctl", "-n", key])
    return out if out else None


def _probe_kernel_hardening() -> KernelHardening:
    raw: dict[str, str] = {}
    keys = [
        "kernel.randomize_va_space",
        "kernel.perf_event_paranoid",
        "kernel.kptr_restrict",
        "kernel.dmesg_restrict",
        "kernel.yama.ptrace_scope",
        "fs.suid_dumpable",
        "fs.protected_hardlinks",
        "fs.protected_symlinks",
        "net.ipv4.tcp_syncookies",
        "net.ipv4.ip_forward",
        "net.ipv4.conf.all.accept_redirects",
        "net.ipv4.conf.all.send_redirects",
        "net.ipv4.conf.all.rp_filter",
        "net.ipv4.conf.default.rp_filter",
        "kernel.nmi_watchdog",
    ]
    for k in keys:
        v = _sysctl(k)
        if v is not None:
            raw[k] = v

    return KernelHardening(
        aslr_enabled=raw.get("kernel.randomize_va_space", "0") == "2",
        ptrace_scope=int(raw.get("kernel.yama.ptrace_scope", "0")),
        suid_dumpable=int(raw.get("fs.suid_dumpable", "2")),
        nmi_watchdog=raw.get("kernel.nmi_watchdog", "1") == "1",
        randomize_va_space=int(raw.get("kernel.randomize_va_space", "0")),
        tcp_syncookies=raw.get("net.ipv4.tcp_syncookies", "0") == "1",
        ip_forward=raw.get("net.ipv4.ip_forward", "0") == "1",
        accept_redirects=raw.get("net.ipv4.conf.all.accept_redirects", "1") == "1",
        send_redirects=raw.get("net.ipv4.conf.all.send_redirects", "1") == "1",
        raw=raw,
    )


# ─────────────────────────────────────────────────────────────────────────────
# World-writable directories
# ─────────────────────────────────────────────────────────────────────────────

def _probe_world_writable() -> list[str]:
    out = _run_root(
        ["find", "/", "-xdev", "-type", "d", "-perm", "-0002",
         "!", "-perm", "-1000"],
        timeout=60,
    )
    return [p.strip() for p in out.splitlines() if p.strip()]


# ─────────────────────────────────────────────────────────────────────────────
# Config checksums (critical files)
# ─────────────────────────────────────────────────────────────────────────────

CRITICAL_CONFIGS = [
    "/etc/ssh/sshd_config",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/hosts",
    "/etc/hosts.allow",
    "/etc/hosts.deny",
    "/etc/pam.d/common-auth",
    "/etc/pam.d/sshd",
    "/etc/security/limits.conf",
    "/etc/sysctl.conf",
    "/etc/ufw/ufw.conf",
    "/etc/fail2ban/jail.local",
    "/etc/audit/auditd.conf",
    "/etc/apparmor.d",
]


def _probe_config_checksums() -> dict[str, str]:
    checksums: dict[str, str] = {}
    for path in CRITICAL_CONFIGS:
        if Path(path).is_file():
            h = _sha256(path)
            if h:
                checksums[path] = h
    return checksums


# ─────────────────────────────────────────────────────────────────────────────
# Security tool detection
# ─────────────────────────────────────────────────────────────────────────────

SECURITY_TOOL_CATALOG: list[dict] = [
    dict(
        name="ufw", display_name="Uncomplicated Firewall", category="firewall",
        binary="/usr/sbin/ufw", config="/etc/ufw/ufw.conf",
        log="/var/log/ufw.log", install="apt install ufw",
        priority=1,
        why="Host-based firewall — blocks unauthorized inbound/outbound traffic.",
        unlocks="apply_firewall_rule, block_ip, list_firewall_rules actions",
    ),
    dict(
        name="fail2ban", display_name="Fail2Ban", category="hids",
        binary="/usr/bin/fail2ban-server", config="/etc/fail2ban/jail.local",
        log="/var/log/fail2ban.log", install="apt install fail2ban",
        priority=1,
        why="Automatically bans IPs with repeated auth failures. Critical for SSH-exposed systems.",
        unlocks="ban_ip, unban_ip, list_bans, fail2ban_status actions",
    ),
    dict(
        name="auditd", display_name="Linux Audit Daemon", category="audit",
        binary="/sbin/auditd", config="/etc/audit/auditd.conf",
        log="/var/log/audit/audit.log", install="apt install auditd audispd-plugins",
        priority=2,
        why="Kernel-level syscall auditing — required for compliance and forensics.",
        unlocks="query_audit_log, set_audit_rule, forensic_timeline actions",
    ),
    dict(
        name="lynis", display_name="Lynis Security Audit", category="hardening",
        binary="/usr/sbin/lynis", config=None,
        log="/var/log/lynis.log", install="apt install lynis",
        priority=2,
        why="CIS benchmark auditor — gives a scored hardening report with actionable findings.",
        unlocks="cis_audit, lynis_scan, hardening_score actions",
    ),
    dict(
        name="rkhunter", display_name="Rootkit Hunter", category="hids",
        binary="/usr/bin/rkhunter", config="/etc/rkhunter.conf",
        log="/var/log/rkhunter.log", install="apt install rkhunter",
        priority=2,
        why="Scans for rootkits, backdoors, and local exploits. Essential for post-compromise detection.",
        unlocks="rootkit_scan, rkhunter_update actions",
    ),
    dict(
        name="chkrootkit", display_name="chkrootkit", category="hids",
        binary="/usr/sbin/chkrootkit", config=None,
        log=None, install="apt install chkrootkit",
        priority=3,
        why="Second rootkit scanner — different signatures from rkhunter, better together.",
        unlocks="chkrootkit_scan action",
    ),
    dict(
        name="aide", display_name="AIDE (Intrusion Detection)", category="hids",
        binary="/usr/bin/aide", config="/etc/aide/aide.conf",
        log="/var/log/aide/aide.log", install="apt install aide",
        priority=2,
        why="File integrity monitoring — detects unauthorized changes to system files.",
        unlocks="integrity_check, aide_init, aide_update actions",
    ),
    dict(
        name="snort", display_name="Snort NIDS", category="ids",
        binary="/usr/sbin/snort", config="/etc/snort/snort.conf",
        log="/var/log/snort", install="apt install snort",
        priority=3,
        why="Network intrusion detection — deep packet inspection with rule-based alerting.",
        unlocks="parse_snort_alert, snort_status actions",
    ),
    dict(
        name="suricata", display_name="Suricata IDS/IPS", category="ids",
        binary="/usr/bin/suricata", config="/etc/suricata/suricata.yaml",
        log="/var/log/suricata", install="apt install suricata",
        priority=2,
        why="Multi-threaded IDS/IPS with EVE JSON output — better performance than Snort on modern hardware.",
        unlocks="parse_eve_log, suricata_alert, suricata_status actions",
    ),
    dict(
        name="clamav", display_name="ClamAV", category="av",
        binary="/usr/bin/clamscan", config="/etc/clamav/clamd.conf",
        log="/var/log/clamav", install="apt install clamav clamav-daemon",
        priority=3,
        why="Antivirus scanner — useful for scanning uploads and detecting known malware.",
        unlocks="av_scan, clam_update actions",
    ),
    dict(
        name="apparmor", display_name="AppArmor", category="mac",
        binary="/sbin/apparmor_parser", config="/etc/apparmor.d",
        log=None, install="apt install apparmor apparmor-utils apparmor-profiles",
        priority=1,
        why="Mandatory access control — confines programs to a limited set of resources.",
        unlocks="apparmor_status, enforce_profile, apparmor_log actions",
    ),
    dict(
        name="unattended-upgrades", display_name="Unattended Upgrades", category="patch",
        binary="/usr/bin/unattended-upgrade", config="/etc/apt/apt.conf.d/50unattended-upgrades",
        log="/var/log/unattended-upgrades", install="apt install unattended-upgrades",
        priority=2,
        why="Automatic security patch application — keeps the system patched without manual intervention.",
        unlocks="patch_status, force_upgrade actions",
    ),
    dict(
        name="needrestart", display_name="needrestart", category="patch",
        binary="/usr/sbin/needrestart", config="/etc/needrestart/needrestart.conf",
        log=None, install="apt install needrestart",
        priority=3,
        why="Detects services that need restart after library updates — prevents stale vulnerable processes.",
        unlocks="check_needrestart action",
    ),
    dict(
        name="debsums", display_name="debsums", category="integrity",
        binary="/usr/bin/debsums", config=None,
        log=None, install="apt install debsums",
        priority=2,
        why="Verifies installed package file checksums against dpkg database — detects tampered binaries.",
        unlocks="verify_package_integrity action",
    ),
    dict(
        name="ossec", display_name="OSSEC HIDS", category="hids",
        binary="/var/ossec/bin/ossec-control", config="/var/ossec/etc/ossec.conf",
        log="/var/ossec/logs/alerts", install="apt install ossec-hids",
        priority=3,
        why="Host-based IDS with log analysis, rootcheck, and active response capabilities.",
        unlocks="ossec_alert, ossec_status actions",
    ),
    dict(
        name="wazuh-agent", display_name="Wazuh Agent", category="siem",
        binary="/var/ossec/bin/wazuh-control", config="/var/ossec/etc/ossec.conf",
        log="/var/ossec/logs", install="see https://documentation.wazuh.com",
        priority=3,
        why="SIEM agent — centralizes log collection, vulnerability detection, and compliance checking.",
        unlocks="wazuh_alert, wazuh_vuln_report actions",
    ),
    dict(
        name="logwatch", display_name="Logwatch", category="audit",
        binary="/usr/sbin/logwatch", config="/etc/logwatch/conf",
        log=None, install="apt install logwatch",
        priority=4,
        why="Daily log summary reports — surfaces anomalies from all system logs in digest form.",
        unlocks="logwatch_report action",
    ),
]


def _detect_security_tools() -> list[SecurityTool]:
    tools = []
    for spec in SECURITY_TOOL_CATALOG:
        binary = spec.get("binary")
        present = bool(binary and (Path(binary).exists() or shutil.which(Path(binary).name)))

        version = None
        running = False
        status = ToolStatus.MISSING

        if present:
            # check if it's a service and if it's running
            svc_name = spec["name"]
            svc_out = _run(["systemctl", "is-active", svc_name])
            running = svc_out.strip() == "active"

            # try to get version
            for flag in ["--version", "-V", "version"]:
                v_out = _run([Path(binary).name, flag], timeout=5)
                if v_out:
                    version = v_out.splitlines()[0]
                    break

            status = ToolStatus.PRESENT if running else ToolStatus.DEGRADED

        tools.append(SecurityTool(
            name=spec["name"],
            display_name=spec["display_name"],
            category=spec["category"],
            status=status,
            version=version,
            config_path=spec.get("config"),
            log_path=spec.get("log"),
            binary_path=binary,
            running=running,
            install_cmd=spec.get("install"),
            why_needed=spec.get("why"),
            what_it_unlocks=spec.get("unlocks"),
            priority=spec.get("priority", 5),
        ))

    return tools


# ─────────────────────────────────────────────────────────────────────────────
# Main probe
# ─────────────────────────────────────────────────────────────────────────────

def probe_system() -> SystemInventory:
    hw = probe_hardware()

    return SystemInventory(
        timestamp=datetime.utcnow(),
        hardware=hw,
        packages=_probe_packages(),
        services=_probe_services(),
        ports=_probe_ports(),
        users=_probe_users(),
        cron_jobs=_probe_crons(),
        firewall_rules=_probe_firewall(),
        suid_files=_probe_suid(),
        security_tools=_detect_security_tools(),
        kernel_hardening=_probe_kernel_hardening(),
        world_writable_dirs=_probe_world_writable(),
        config_checksums=_probe_config_checksums(),
    )


def diff_inventory(old: SystemInventory, new: SystemInventory) -> dict:
    """Return a structured diff between two inventory snapshots."""
    old_pkgs = {p.name: p.version for p in old.packages}
    new_pkgs = {p.name: p.version for p in new.packages}
    old_ports = {(p.port, p.protocol) for p in old.ports}
    new_ports = {(p.port, p.protocol) for p in new.ports}
    old_services = {s.name: s.state for s in old.services}
    new_services = {s.name: s.state for s in new.services}
    old_sums = old.config_checksums
    new_sums = new.config_checksums
    old_suid = {f.path for f in old.suid_files}
    new_suid = {f.path for f in new.suid_files}

    return {
        "packages": {
            "added":   {k: v for k, v in new_pkgs.items() if k not in old_pkgs},
            "removed": {k: v for k, v in old_pkgs.items() if k not in new_pkgs},
            "updated": {k: v for k, v in new_pkgs.items()
                        if k in old_pkgs and old_pkgs[k] != v},
        },
        "ports": {
            "opened": list(new_ports - old_ports),
            "closed": list(old_ports - new_ports),
        },
        "services": {
            "started": {k: v for k, v in new_services.items()
                        if k not in old_services or old_services[k] != v and v == "active"},
            "stopped": {k: v for k, v in old_services.items()
                        if k not in new_services or new_services[k] != v and v == "active"},
        },
        "config_changes": {
            path: {"old": old_sums.get(path), "new": chk}
            for path, chk in new_sums.items()
            if old_sums.get(path) != chk
        },
        "suid": {
            "added":   list(new_suid - old_suid),
            "removed": list(old_suid - new_suid),
        },
    }
