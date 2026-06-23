"""
Incident response actions — containment, isolation, and eradication.
All destructive actions log what they do to the knowledge base and are
reversible where possible (ban before drop, kill before rm).
"""

from __future__ import annotations
import logging
import os
import shutil
import signal
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

import psutil

log = logging.getLogger(__name__)


def _run(cmd: list[str], timeout: int = 30) -> dict:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {
            "success": r.returncode == 0,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
            "returncode": r.returncode,
            "command": " ".join(cmd),
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "timeout", "command": " ".join(cmd)}
    except Exception as e:
        return {"success": False, "error": str(e), "command": " ".join(cmd)}


def _sudo(cmd: list[str], timeout: int = 30) -> dict:
    if os.geteuid() == 0:
        return _run(cmd, timeout)
    return _run(["sudo", "-n"] + cmd, timeout)


# ── IP blocking ───────────────────────────────────────────────────────────

def block_ip(ip: str, reason: str = "secteam automated block") -> dict:
    """Block all traffic from/to an IP using UFW or iptables."""
    log.warning("Blocking IP %s — reason: %s", ip, reason)
    results = {}

    if shutil.which("ufw"):
        results["ufw_in"]  = _sudo(["ufw", "deny", "from", ip, "to", "any",
                                     "comment", reason])
        results["ufw_out"] = _sudo(["ufw", "deny", "out", "to", ip,
                                     "comment", reason])
        reload = _sudo(["ufw", "reload"])
        results["reload"]  = reload

    elif shutil.which("iptables"):
        results["iptables_in"]  = _sudo(["iptables", "-I", "INPUT", "-s", ip,
                                          "-j", "DROP", "-m", "comment",
                                          "--comment", reason])
        results["iptables_out"] = _sudo(["iptables", "-I", "OUTPUT", "-d", ip,
                                          "-j", "DROP"])

    success = any(v.get("success") for v in results.values())
    return {"action": "block_ip", "ip": ip, "success": success,
            "timestamp": datetime.utcnow().isoformat(), "results": results}


def unblock_ip(ip: str) -> dict:
    """Remove all blocks on an IP."""
    results = {}
    if shutil.which("ufw"):
        results["ufw"] = _sudo(["ufw", "delete", "deny", "from", ip])
    if shutil.which("fail2ban-client"):
        results["fail2ban"] = _sudo(["fail2ban-client", "unban", ip])
    return {"action": "unblock_ip", "ip": ip, "results": results}


def block_ip_fail2ban(ip: str, jail: str = "sshd") -> dict:
    """Block via fail2ban (preferred — tracks bans with context)."""
    if not shutil.which("fail2ban-client"):
        return block_ip(ip, "fail2ban unavailable — used UFW")
    r = _sudo(["fail2ban-client", "set", jail, "banip", ip])
    return {"action": "fail2ban_ban", "ip": ip, "jail": jail,
            "success": r.get("success"), "detail": r}


# ── Process management ────────────────────────────────────────────────────

def kill_process(pid: int, force: bool = False) -> dict:
    """Kill a process gracefully (SIGTERM), then force (SIGKILL) if needed."""
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        exe  = proc.exe() if not force else ""
        cmdline = " ".join(proc.cmdline()[:5])

        proc.terminate()
        try:
            proc.wait(timeout=5)
            killed = True
        except psutil.TimeoutExpired:
            if force:
                proc.kill()
                proc.wait(timeout=3)
                killed = True
            else:
                killed = False

        return {
            "action": "kill_process",
            "pid": pid,
            "name": name,
            "exe": exe,
            "cmdline": cmdline,
            "killed": killed,
            "force_used": force,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except psutil.NoSuchProcess:
        return {"action": "kill_process", "pid": pid, "error": "process not found"}
    except psutil.AccessDenied:
        # Try via sudo
        sig = signal.SIGKILL if force else signal.SIGTERM
        r = _sudo(["kill", f"-{sig.value}", str(pid)])
        return {"action": "kill_process", "pid": pid,
                "success": r.get("success"), "detail": r}


def kill_process_by_name(name: str, force: bool = False) -> dict:
    """Kill all processes matching a name."""
    killed = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if proc.name() == name:
                result = kill_process(proc.pid, force)
                killed.append(result)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return {"action": "kill_by_name", "name": name, "killed": killed}


# ── File quarantine ───────────────────────────────────────────────────────

QUARANTINE_DIR = Path("/var/lib/secteam/quarantine")


def quarantine_file(path: str, reason: str = "suspicious") -> dict:
    """
    Move a file to quarantine and remove execute permissions.
    Preserves the original path in metadata for potential restoration.
    """
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    src = Path(path)
    if not src.exists():
        return {"action": "quarantine_file", "path": path, "error": "file not found"}

    import hashlib
    h = hashlib.sha256(src.read_bytes()).hexdigest()[:16]
    dst = QUARANTINE_DIR / f"{src.name}.{h}.quarantine"

    # Write metadata alongside
    meta = {
        "original_path": str(src),
        "quarantined_at": datetime.utcnow().isoformat(),
        "reason": reason,
        "sha256": h,
    }
    meta_path = QUARANTINE_DIR / f"{src.name}.{h}.meta.json"

    try:
        import json
        shutil.move(str(src), str(dst))
        meta_path.write_text(json.dumps(meta, indent=2))
        # ensure quarantined file is not executable
        dst.chmod(0o600)
        return {
            "action": "quarantine_file",
            "original": str(src),
            "quarantined_to": str(dst),
            "sha256": h,
            "success": True,
        }
    except Exception as e:
        return {"action": "quarantine_file", "path": path,
                "success": False, "error": str(e)}


def restore_file(quarantine_path: str) -> dict:
    """Restore a quarantined file to its original location."""
    import json
    q = Path(quarantine_path)
    meta_path = Path(str(quarantine_path).replace(".quarantine", ".meta.json"))
    if not meta_path.exists():
        return {"action": "restore_file", "error": "metadata not found"}
    meta = json.loads(meta_path.read_text())
    original = Path(meta["original_path"])
    try:
        shutil.move(str(q), str(original))
        meta_path.unlink(missing_ok=True)
        return {"action": "restore_file", "restored_to": str(original), "success": True}
    except Exception as e:
        return {"action": "restore_file", "error": str(e), "success": False}


# ── Host isolation ────────────────────────────────────────────────────────

def isolate_host(allow_management_ip: Optional[str] = None) -> dict:
    """
    Full host isolation — block all inbound/outbound except optionally one
    management IP.  This is a drastic action; used only for confirmed compromise.
    """
    log.critical("HOST ISOLATION INITIATED")
    results = {}

    if shutil.which("ufw"):
        results["default_deny_in"]  = _sudo(["ufw", "default", "deny", "incoming"])
        results["default_deny_out"] = _sudo(["ufw", "default", "deny", "outgoing"])
        if allow_management_ip:
            results["allow_mgmt_in"]  = _sudo(["ufw", "allow", "from",
                                                allow_management_ip])
            results["allow_mgmt_out"] = _sudo(["ufw", "allow", "out", "to",
                                                allow_management_ip])
        results["allow_lo"]  = _sudo(["ufw", "allow", "in",  "on", "lo"])
        results["allow_lo2"] = _sudo(["ufw", "allow", "out", "on", "lo"])
        results["enable"]    = _sudo(["ufw", "enable"])
        results["reload"]    = _sudo(["ufw", "reload"])

    return {
        "action": "isolate_host",
        "timestamp": datetime.utcnow().isoformat(),
        "management_ip_preserved": allow_management_ip,
        "results": results,
        "warning": "Host is now ISOLATED. Restore with: ufw default allow incoming; ufw reload",
    }


# ── Network rate limiting ─────────────────────────────────────────────────

def rate_limit_ip(ip: str, connections_per_minute: int = 10) -> dict:
    """Apply rate limiting to an IP using UFW's rate limiting."""
    if shutil.which("ufw"):
        r = _sudo(["ufw", "limit", "from", ip])
        return {"action": "rate_limit", "ip": ip,
                "limit": f"{connections_per_minute}/min",
                "success": r.get("success"), "detail": r}
    # iptables fallback
    r = _sudo(["iptables", "-I", "INPUT", "-s", ip, "-m", "state",
               "--state", "NEW", "-m", "recent", "--set"])
    r2 = _sudo(["iptables", "-I", "INPUT", "-s", ip, "-m", "state",
                "--state", "NEW", "-m", "recent", "--update",
                "--seconds", "60", "--hitcount", str(connections_per_minute), "-j", "DROP"])
    return {"action": "rate_limit", "ip": ip, "results": [r, r2]}


# ── SSH session management ────────────────────────────────────────────────

def list_active_ssh_sessions() -> dict:
    """List all active SSH sessions with user and source IP."""
    out_who  = subprocess.run(["who"], capture_output=True, text=True).stdout
    out_ss   = subprocess.run(["ss", "-tnp"], capture_output=True, text=True).stdout
    sessions = []
    for line in out_who.splitlines():
        parts = line.split()
        if len(parts) >= 5:
            sessions.append({
                "user":     parts[0],
                "tty":      parts[1],
                "login_at": f"{parts[2]} {parts[3]}",
                "from":     parts[4].strip("()") if len(parts) > 4 else "local",
            })
    return {"sessions": sessions, "raw_ss": out_ss[:1000]}


def terminate_ssh_session(tty: str) -> dict:
    """Forcibly terminate an SSH session by its TTY."""
    r = _sudo(["pkill", "-t", tty])
    return {"action": "terminate_ssh_session", "tty": tty,
            "success": r.get("success"), "detail": r}


# ── Service management ────────────────────────────────────────────────────

def stop_service(service_name: str) -> dict:
    r = _sudo(["systemctl", "stop", service_name])
    return {"action": "stop_service", "service": service_name,
            "success": r.get("success"), "detail": r}


def restart_service(service_name: str) -> dict:
    r = _sudo(["systemctl", "restart", service_name])
    return {"action": "restart_service", "service": service_name,
            "success": r.get("success"), "detail": r}
