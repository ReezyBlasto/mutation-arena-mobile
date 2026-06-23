"""
Reporter — generates human-readable security reports from the knowledge base.
Outputs rich terminal reports, plain text, or JSON depending on context.
"""

from __future__ import annotations
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from secteam.models import (
    PostureReport, SecurityTool, SystemInventory, ToolStatus,
)
from secteam.core.knowledge_base import KnowledgeBase

console = Console()


SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim",
}


def _score_color(score: float) -> str:
    if score >= 80:
        return "green"
    if score >= 60:
        return "yellow"
    if score >= 40:
        return "orange1"
    return "red"


def compute_posture_score(inv: SystemInventory) -> tuple[float, dict[str, float]]:
    """
    Compute a 0-100 security posture score across categories.
    Weighted to mirror CIS L1 priorities.
    """
    scores: dict[str, float] = {}

    # Firewall (15 pts)
    from secteam.models import ToolStatus
    ufw = next((t for t in inv.security_tools if t.name == "ufw"), None)
    scores["firewall"] = 15.0 if (ufw and ufw.running) else 5.0 if (ufw and ufw.status != ToolStatus.MISSING) else 0.0

    # Auth hardening (20 pts)
    kh = inv.kernel_hardening
    ssh_score = 0.0
    # check sshd_config for root login disabled
    try:
        cfg = open("/etc/ssh/sshd_config").read()
        if "PermitRootLogin no" in cfg:
            ssh_score += 10
        if "PasswordAuthentication no" in cfg:
            ssh_score += 10
    except Exception:
        pass
    scores["auth_hardening"] = min(ssh_score, 20.0)

    # Kernel hardening (15 pts)
    kh_checks = [
        kh.aslr_enabled,
        kh.tcp_syncookies,
        not kh.ip_forward,
        not kh.accept_redirects,
        not kh.send_redirects,
        kh.ptrace_scope >= 1,
        kh.suid_dumpable == 0,
    ]
    scores["kernel_hardening"] = round(sum(kh_checks) / len(kh_checks) * 15, 1)

    # Security tools (20 pts)
    critical_tools = ["ufw", "fail2ban", "auditd", "aide", "apparmor"]
    present_critical = sum(
        1 for t in inv.security_tools
        if t.name in critical_tools and t.status == ToolStatus.PRESENT
    )
    scores["security_tools"] = round(present_critical / len(critical_tools) * 20, 1)

    # SUID cleanliness (10 pts)
    unknown_suid = len([f for f in inv.suid_files if not f.known_safe])
    scores["suid_cleanliness"] = max(0.0, 10.0 - unknown_suid * 2)

    # User hygiene (10 pts)
    user_score = 10.0
    if any(u.username == "root" and u.last_login for u in inv.users):
        user_score -= 3
    scores["user_hygiene"] = user_score

    # Logging coverage (10 pts)
    logging_tools = ["auditd", "logwatch"]
    log_score = sum(
        3 for t in inv.security_tools
        if t.name in logging_tools and t.status == ToolStatus.PRESENT
    )
    # journald is always present on systemd systems
    log_score += 4
    scores["logging_coverage"] = min(log_score, 10.0)

    total = sum(scores.values())
    return round(total, 1), scores


def print_status_dashboard(inv: SystemInventory, kb: KnowledgeBase) -> None:
    """Rich terminal dashboard — main status view."""
    score, categories = compute_posture_score(inv)
    score_color = _score_color(score)

    # Header
    console.print(Panel(
        f"[bold]SecTeam Security Operations[/bold]\n"
        f"[dim]{inv.hardware.hostname} | {inv.hardware.os_version}[/dim]",
        style="blue",
    ))

    # Posture score
    console.print(Panel(
        f"[{score_color}]POSTURE SCORE: {score}/100[/{score_color}]\n" +
        "\n".join(f"  {k:<25} {v:.0f}" for k, v in categories.items()),
        title="Security Posture",
        box=box.ROUNDED,
    ))

    # Open events
    open_evts = kb.open_events()
    if open_evts:
        tbl = Table(title="Open Events", box=box.MINIMAL_DOUBLE_HEAD)
        tbl.add_column("Severity", style="bold")
        tbl.add_column("Type")
        tbl.add_column("Source")
        tbl.add_column("When")
        for e in sorted(open_evts, key=lambda x: x.severity.value)[:15]:
            color = SEVERITY_COLORS.get(e.severity.value, "")
            tbl.add_row(
                Text(e.severity.value, style=color),
                e.event_type,
                e.source,
                e.timestamp.strftime("%H:%M:%S"),
            )
        console.print(tbl)
    else:
        console.print("[green]No open events[/green]")

    # Security tools
    tbl2 = Table(title="Security Tools", box=box.MINIMAL_DOUBLE_HEAD)
    tbl2.add_column("Tool")
    tbl2.add_column("Status")
    tbl2.add_column("Category")
    tbl2.add_column("Priority")

    for t in sorted(inv.security_tools, key=lambda x: x.priority):
        status_color = {
            ToolStatus.PRESENT:     "green",
            ToolStatus.DEGRADED:    "yellow",
            ToolStatus.MISSING:     "red",
            ToolStatus.RECOMMENDED: "cyan",
            ToolStatus.CRITICAL:    "bold red",
        }.get(t.status, "white")

        tbl2.add_row(
            t.display_name,
            Text(t.status.value, style=status_color),
            t.category,
            str(t.priority),
        )
    console.print(tbl2)

    # Training data stats
    td_counts = kb.training_data_count()
    if td_counts:
        console.print(Panel(
            "\n".join(f"  {domain:<25} {count} examples" for domain, count in td_counts.items()),
            title="Training Data Collected",
            box=box.ROUNDED,
        ))


def generate_tool_recommendations(inv: SystemInventory) -> str:
    """
    Human-readable list of tool installation recommendations,
    ordered by priority with rationale for each.
    """
    from secteam.models import ToolStatus
    missing = sorted(
        [t for t in inv.security_tools if t.status == ToolStatus.MISSING],
        key=lambda t: t.priority,
    )
    if not missing:
        return "All recommended security tools are installed."

    lines = ["RECOMMENDED TOOL INSTALLATIONS", "=" * 40, ""]
    for t in missing:
        pri_label = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM"}.get(t.priority, "LOW")
        lines.append(f"[{pri_label}] {t.display_name}")
        if t.why_needed:
            lines.append(f"  Why: {t.why_needed}")
        if t.what_it_unlocks:
            lines.append(f"  Unlocks: {t.what_it_unlocks}")
        if t.install_cmd:
            lines.append(f"  Install: sudo {t.install_cmd}")
        lines.append("")

    return "\n".join(lines)


def generate_posture_report(inv: SystemInventory, kb: KnowledgeBase) -> PostureReport:
    score, categories = compute_posture_score(inv)

    critical_gaps = []
    for t in inv.security_tools:
        if t.status == ToolStatus.MISSING and t.priority <= 2:
            critical_gaps.append(
                f"{t.display_name} not installed — {t.why_needed or 'security gap'}"
            )

    kh = inv.kernel_hardening
    if not kh.aslr_enabled:
        critical_gaps.append("ASLR disabled — kernel memory layout predictable")
    if kh.ip_forward:
        critical_gaps.append("IP forwarding enabled — system acting as router")
    if kh.accept_redirects:
        critical_gaps.append("ICMP redirects accepted — routing attack vector")

    unknown_suid = [f.path for f in inv.suid_files if not f.known_safe]
    if unknown_suid:
        critical_gaps.append(f"{len(unknown_suid)} unknown SUID files present")

    open_count     = len(kb.open_events())
    resolved_count = len(kb.open_events()) - open_count   # approximate

    return PostureReport(
        score=score,
        categories=categories,
        critical_gaps=critical_gaps,
        recommendations=[t for t in inv.security_tools
                         if t.status == ToolStatus.MISSING],
        installed_tools=[t for t in inv.security_tools
                         if t.status == ToolStatus.PRESENT],
        open_incidents=open_count,
        resolved_incidents=resolved_count,
    )
