"""
Builds the system context string that all agents carry in their system prompt.
This is the living ground truth — rebuilt after every audit, updated whenever
a tool is installed or a baseline changes.

The context gives every agent the same factual foundation so they don't guess
about what's on the system.
"""

from __future__ import annotations
from secteam.models import SecurityTool, SystemInventory, ToolStatus


def build_context(inv: SystemInventory) -> str:
    hw   = inv.hardware
    llm  = inv.llm

    # Security tools summary
    present  = [t for t in inv.security_tools if t.status == ToolStatus.PRESENT]
    missing  = [t for t in inv.security_tools if t.status == ToolStatus.MISSING]
    degraded = [t for t in inv.security_tools if t.status == ToolStatus.DEGRADED]
    critical_missing = sorted(
        [t for t in missing if t.priority <= 2],
        key=lambda t: t.priority,
    )

    def tool_list(tools: list[SecurityTool]) -> str:
        return ", ".join(t.name for t in tools) if tools else "none"

    # Firewall summary
    fw_rules  = len(inv.firewall_rules)
    fw_status = "ACTIVE" if any(
        "active" in str(r).lower() for r in inv.firewall_rules
    ) else "PRESENT" if shutil.which_exists("ufw") else "UNKNOWN"

    # Ports summary
    ports_str = ", ".join(
        f"{p.port}/{p.protocol}({p.process or '?'})" for p in inv.ports[:10]
    )

    # Kernel hardening
    kh = inv.kernel_hardening
    kh_ok = all([
        kh.aslr_enabled,
        kh.tcp_syncookies,
        not kh.ip_forward,
        not kh.accept_redirects,
    ])

    # Users with sudo
    sudo_users = [u.username for u in inv.users if u.sudo_access]

    # SUID anomalies
    unknown_suid = [f.path for f in inv.suid_files if not f.known_safe]

    # LLM context
    llm_str = ""
    if llm:
        models = ", ".join(llm.recommended_models.values()) if llm.recommended_models else "none pulled"
        llm_str = (
            f"\nAI STACK:\n"
            f"  Provider: {llm.recommended_provider}\n"
            f"  Models: {models}\n"
            f"  Local fine-tune: {'yes (' + llm.finetune_backend + ')' if llm.can_finetune_local else 'no'}"
        )

    return f"""
SYSTEM CONTEXT (last updated: {inv.timestamp.strftime('%Y-%m-%d %H:%M UTC')})

HOST: {hw.hostname} | OS: {hw.os_version} | Kernel: {hw.kernel_version}
HARDWARE: {hw.cpu.model} ({hw.cpu.cores_physical}p/{hw.cpu.cores_logical}t) | RAM: {hw.ram_total_gb:.1f}GB | {'GPU: ' + hw.gpu.model + f' ({hw.gpu.vram_gb:.1f}GB VRAM)' if hw.gpu.present else 'No GPU'}
DISK: {hw.disk_available_gb:.1f}GB free of {hw.disk_total_gb:.1f}GB
{llm_str}

PACKAGES: {len(inv.packages)} installed
SERVICES: {len([s for s in inv.services if s.state == 'active'])} running of {len(inv.services)} total
LISTENING PORTS: {ports_str}
USERS: {', '.join(u.username for u in inv.users)} | SUDO ACCESS: {', '.join(sudo_users)}
CRON JOBS: {len(inv.cron_jobs)}

SECURITY POSTURE SCORE: {inv.posture_score or 'not yet scored'}/100

SECURITY TOOLS:
  Active: {tool_list(present)}
  Degraded (installed, not running): {tool_list(degraded)}
  CRITICAL MISSING: {', '.join(f'{t.name} (priority {t.priority})' for t in critical_missing) or 'none'}
  All missing: {tool_list(missing)}

FIREWALL: {fw_rules} rules configured
KERNEL HARDENING: {'ADEQUATE' if kh_ok else 'NEEDS ATTENTION'} | ASLR: {kh.aslr_enabled} | SYNCookies: {kh.tcp_syncookies} | IP Forward: {kh.ip_forward}
SUID ANOMALIES: {len(unknown_suid)} unknown SUID files{' (' + ', '.join(unknown_suid[:3]) + ')' if unknown_suid else ''}
CONFIG MONITORING: {len(inv.config_checksums)} critical files baselined
WORLD-WRITABLE DIRS: {len(inv.world_writable_dirs)} found
""".strip()


# Thin shim so we don't need to import shutil in the context builder
class shutil_exists:
    @staticmethod
    def which_exists(name: str) -> bool:
        import shutil
        return bool(shutil.which(name))


# make the function importable cleanly
import shutil as _shutil
shutil = type("shutil", (), {"which_exists": staticmethod(lambda n: bool(_shutil.which(n)))})()
