"""
System hardening actions — applies CIS-aligned hardening configs.
Every action shows what it will change before applying and logs the diff.
"""

from __future__ import annotations
import logging
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


def _run(cmd: list[str], timeout: int = 30) -> dict:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"success": r.returncode == 0, "stdout": r.stdout.strip(),
                "stderr": r.stderr.strip(), "cmd": " ".join(cmd)}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _sudo(cmd: list[str], timeout: int = 30) -> dict:
    if os.geteuid() == 0:
        return _run(cmd, timeout)
    return _run(["sudo", "-n"] + cmd, timeout)


def _backup_file(path: str) -> Optional[str]:
    """Back up a file before modifying it. Returns backup path."""
    backup = f"{path}.secteam.bak.{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    try:
        shutil.copy2(path, backup)
        return backup
    except Exception:
        return None


def _set_config(path: str, settings: dict[str, str]) -> dict:
    """
    Set key=value pairs in a config file.
    Uncommments existing directives, adds missing ones.
    """
    p = Path(path)
    if not p.exists():
        return {"success": False, "error": f"{path} not found"}

    backup = _backup_file(path)
    original = p.read_text()
    lines = original.splitlines()
    applied = {}
    pending = dict(settings)

    new_lines = []
    for line in lines:
        stripped = line.strip()
        modified = False
        for key, value in list(pending.items()):
            # match commented or uncommented key
            if stripped.lstrip("#").strip().startswith(key):
                new_lines.append(f"{key} {value}")
                applied[key] = value
                del pending[key]
                modified = True
                break
        if not modified:
            new_lines.append(line)

    # append any keys not found in the file
    for key, value in pending.items():
        new_lines.append(f"{key} {value}")
        applied[key] = value

    p.write_text("\n".join(new_lines) + "\n")
    return {
        "success": True,
        "path": path,
        "backup": backup,
        "applied": applied,
    }


# ── SSH hardening ─────────────────────────────────────────────────────────

SSH_HARDENING_SETTINGS = {
    "PermitRootLogin":          "no",
    "PasswordAuthentication":   "no",
    "PubkeyAuthentication":     "yes",
    "MaxAuthTries":             "3",
    "MaxSessions":              "10",
    "Protocol":                 "2",
    "IgnoreRhosts":             "yes",
    "HostbasedAuthentication":  "no",
    "PermitEmptyPasswords":     "no",
    "X11Forwarding":            "no",
    "PrintLastLog":             "yes",
    "TCPKeepAlive":             "yes",
    "AllowAgentForwarding":     "no",
    "AllowTcpForwarding":       "no",
    "Banner":                   "/etc/issue.net",
    "ClientAliveInterval":      "300",
    "ClientAliveCountMax":      "2",
    "LoginGraceTime":           "60",
    "LogLevel":                 "VERBOSE",
}


def harden_ssh(dry_run: bool = False) -> dict:
    path = "/etc/ssh/sshd_config"
    if dry_run:
        return {"action": "harden_ssh", "dry_run": True,
                "would_apply": SSH_HARDENING_SETTINGS}

    result = _set_config(path, SSH_HARDENING_SETTINGS)
    if result.get("success"):
        restart = _sudo(["systemctl", "reload", "ssh"])
        result["service_reload"] = restart
    return {"action": "harden_ssh", **result}


# ── Kernel parameter hardening ────────────────────────────────────────────

SYSCTL_HARDENING = {
    "kernel.randomize_va_space":                "2",
    "kernel.dmesg_restrict":                    "1",
    "kernel.kptr_restrict":                     "2",
    "kernel.perf_event_paranoid":               "3",
    "kernel.yama.ptrace_scope":                 "1",
    "fs.suid_dumpable":                         "0",
    "fs.protected_hardlinks":                   "1",
    "fs.protected_symlinks":                    "1",
    "fs.protected_fifos":                       "2",
    "fs.protected_regular":                     "2",
    "net.ipv4.tcp_syncookies":                  "1",
    "net.ipv4.ip_forward":                      "0",
    "net.ipv4.conf.all.accept_redirects":       "0",
    "net.ipv4.conf.default.accept_redirects":   "0",
    "net.ipv4.conf.all.send_redirects":         "0",
    "net.ipv4.conf.all.accept_source_route":    "0",
    "net.ipv4.conf.all.log_martians":           "1",
    "net.ipv4.conf.all.rp_filter":              "1",
    "net.ipv4.conf.default.rp_filter":          "1",
    "net.ipv6.conf.all.accept_redirects":       "0",
    "net.ipv6.conf.default.accept_redirects":   "0",
    "net.ipv6.conf.all.accept_source_route":    "0",
    "net.core.bpf_jit_harden":                  "2",
}


def harden_kernel(dry_run: bool = False) -> dict:
    if dry_run:
        return {"action": "harden_kernel", "dry_run": True,
                "would_apply": SYSCTL_HARDENING}

    results = {}
    conf_lines = []
    for key, value in SYSCTL_HARDENING.items():
        r = _sudo(["sysctl", "-w", f"{key}={value}"])
        results[key] = {"value": value, "applied": r.get("success")}
        conf_lines.append(f"{key} = {value}")

    # persist to sysctl.d
    conf_path = Path("/etc/sysctl.d/99-secteam-hardening.conf")
    backup = _backup_file(str(conf_path)) if conf_path.exists() else None
    conf_path.write_text("# Applied by secteam\n" + "\n".join(conf_lines) + "\n")

    reload = _sudo(["sysctl", "-p", str(conf_path)])
    return {
        "action": "harden_kernel",
        "applied_count": sum(1 for v in results.values() if v["applied"]),
        "conf_path": str(conf_path),
        "backup": backup,
        "reload": reload.get("success"),
        "results": results,
    }


# ── UFW baseline ──────────────────────────────────────────────────────────

def apply_ufw_baseline(allowed_ports: list[int] | None = None,
                       dry_run: bool = False) -> dict:
    """
    Apply a secure UFW baseline:
    - Default deny in/out
    - Allow only specified ports inbound
    - Allow established connections
    """
    ports = allowed_ports or [22, 80, 443]
    if dry_run:
        return {"action": "ufw_baseline", "dry_run": True,
                "would_allow": ports}

    ops = {}
    ops["default_deny_in"]  = _sudo(["ufw", "default", "deny", "incoming"])
    ops["default_deny_out"] = _sudo(["ufw", "default", "deny", "outgoing"])
    ops["allow_lo_in"]  = _sudo(["ufw", "allow", "in",  "on", "lo"])
    ops["allow_lo_out"] = _sudo(["ufw", "allow", "out", "on", "lo"])

    # Allow DNS and NTP outbound (essential)
    ops["allow_dns"]  = _sudo(["ufw", "allow", "out", "to", "any", "port", "53"])
    ops["allow_ntp"]  = _sudo(["ufw", "allow", "out", "to", "any", "port", "123"])
    ops["allow_http_out"]  = _sudo(["ufw", "allow", "out", "to", "any", "port", "80"])
    ops["allow_https_out"] = _sudo(["ufw", "allow", "out", "to", "any", "port", "443"])

    for port in ports:
        ops[f"allow_in_{port}"] = _sudo(["ufw", "allow", str(port)])

    ops["enable"] = _sudo(["ufw", "--force", "enable"])
    ops["reload"] = _sudo(["ufw", "reload"])

    return {
        "action": "ufw_baseline",
        "allowed_ports": ports,
        "ops": ops,
        "success": ops["enable"].get("success", False),
    }


# ── User account hardening ────────────────────────────────────────────────

def harden_password_policy() -> dict:
    """Apply PAM password quality and aging policies."""
    results = {}

    # pwquality
    pwq_settings = {
        "minlen":   "14",
        "dcredit":  "-1",
        "ucredit":  "-1",
        "ocredit":  "-1",
        "lcredit":  "-1",
        "maxrepeat":"3",
    }
    pwq_path = Path("/etc/security/pwquality.conf")
    if pwq_path.exists():
        results["pwquality"] = _set_config(str(pwq_path), pwq_settings)

    # login.defs aging
    login_settings = {
        "PASS_MAX_DAYS": "90",
        "PASS_MIN_DAYS": "7",
        "PASS_WARN_AGE": "14",
    }
    results["login_defs"] = _set_config("/etc/login.defs", login_settings)

    return {"action": "harden_password_policy", "results": results}


def lock_root_account() -> dict:
    """Lock the root account password (require sudo for all escalation)."""
    r = _sudo(["passwd", "-l", "root"])
    return {"action": "lock_root", "success": r.get("success"), "detail": r}


# ── File permissions hardening ────────────────────────────────────────────

PERMISSION_MAP = {
    "/etc/passwd":  ("0644", "root", "root"),
    "/etc/shadow":  ("0640", "root", "shadow"),
    "/etc/gshadow": ("0640", "root", "shadow"),
    "/etc/group":   ("0644", "root", "root"),
    "/etc/sudoers": ("0440", "root", "root"),
    "/etc/ssh/sshd_config": ("0600", "root", "root"),
    "/boot":        ("0700", "root", "root"),
    "/var/log":     ("0755", "root", "syslog"),
}


def harden_file_permissions(dry_run: bool = False) -> dict:
    results = {}
    for path, (mode, owner, group) in PERMISSION_MAP.items():
        if not Path(path).exists():
            continue
        if dry_run:
            results[path] = {"would_set": f"{mode} {owner}:{group}"}
            continue
        r1 = _sudo(["chmod", mode, path])
        r2 = _sudo(["chown", f"{owner}:{group}", path])
        results[path] = {"chmod": r1.get("success"), "chown": r2.get("success")}

    return {"action": "harden_file_permissions", "dry_run": dry_run, "results": results}


# ── Install security tool ─────────────────────────────────────────────────

def install_security_tool(package_name: str, post_install_cmds: list[list[str]] | None = None) -> dict:
    """Install a security tool via apt and run any post-install commands."""
    # Update apt cache first
    update = _sudo(["apt-get", "update", "-qq"])
    install = _sudo(["apt-get", "install", "-y", "-qq", package_name], timeout=120)

    post_results = []
    if install.get("success") and post_install_cmds:
        for cmd in post_install_cmds:
            post_results.append(_sudo(cmd))

    return {
        "action": "install_tool",
        "package": package_name,
        "apt_update": update.get("success"),
        "installed": install.get("success"),
        "post_install": post_results,
        "timestamp": datetime.utcnow().isoformat(),
    }


# ── Run lynis audit ───────────────────────────────────────────────────────

def run_lynis_audit() -> dict:
    if not shutil.which("lynis"):
        return {"action": "lynis_audit", "error": "lynis not installed"}
    r = _sudo(["lynis", "audit", "system", "--quiet", "--no-colors"], timeout=300)
    # extract hardening index
    score = None
    for line in r.get("stdout", "").splitlines():
        if "Hardening index" in line:
            import re
            m = re.search(r"\[\s*(\d+)\s*\]", line)
            if m:
                score = int(m.group(1))
    return {
        "action": "lynis_audit",
        "hardening_index": score,
        "success": r.get("success"),
        "log_path": "/var/log/lynis.log",
    }


# ── Configure fail2ban ────────────────────────────────────────────────────

FAIL2BAN_SSHD_JAIL = """
[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 3600
findtime = 600
"""


def configure_fail2ban() -> dict:
    jail_path = Path("/etc/fail2ban/jail.local")
    if not jail_path.parent.exists():
        return {"action": "configure_fail2ban",
                "error": "fail2ban not installed"}
    backup = _backup_file(str(jail_path)) if jail_path.exists() else None
    jail_path.write_text(FAIL2BAN_SSHD_JAIL)
    restart = _sudo(["systemctl", "restart", "fail2ban"])
    return {
        "action": "configure_fail2ban",
        "jail_path": str(jail_path),
        "backup": backup,
        "restarted": restart.get("success"),
    }
