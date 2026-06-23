#!/usr/bin/env python3
"""
SecTeam CLI — interactive interface to the security operations daemon.

Usage:
  python main.py start          # start the daemon
  python main.py status         # live dashboard
  python main.py audit          # force full audit now
  python main.py ask "..."      # query any agent
  python main.py approve <id>   # approve a pending action
  python main.py deny <id>      # deny a pending action
  python main.py events         # list open events
  python main.py report         # full posture report
  python main.py tools          # tool recommendations
  python main.py models         # LLM model status
  python main.py install <tool> # approve and install a tool
  python main.py pull <model>   # pull an Ollama model
"""

from __future__ import annotations
import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

# Allow running from the repo root without installing
sys.path.insert(0, str(Path(__file__).parent))

from secteam.core.probe.system import probe_system
from secteam.core.probe.llm_probe import probe_llm
from secteam.core.knowledge_base import KnowledgeBase
from secteam.core.reporter import (
    print_status_dashboard, generate_tool_recommendations,
    generate_posture_report, compute_posture_score,
)
from secteam.core.llm.model_manager import (
    list_local_models, pull_model, recommend_and_pull, benchmark_model,
    check_finetune_jobs,
)

app     = typer.Typer(help="SecTeam — Autonomous Cybersecurity Operations")
console = Console()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

DATA_DIR = Path(os.environ.get("SECTEAM_DATA", "/var/lib/secteam"))


def _get_kb() -> KnowledgeBase:
    return KnowledgeBase(DATA_DIR / "knowledge.db")


def _get_inv():
    kb = _get_kb()
    inv = kb.get_latest_inventory()
    if not inv:
        console.print("[yellow]No inventory found — running probe now...[/yellow]")
        inv = probe_system()
        score, _ = compute_posture_score(inv)
        inv.posture_score = score
        kb.save_inventory(inv, baseline=not bool(kb.get_baseline()))
    return inv, kb


# ── Commands ──────────────────────────────────────────────────────────────

@app.command()
def status():
    """Live security dashboard — posture score, events, and team status."""
    inv, kb = _get_inv()
    print_status_dashboard(inv, kb)


@app.command()
def audit(baseline: bool = typer.Option(False, "--baseline", help="Save as new baseline")):
    """Run a full system audit and update the inventory."""
    with console.status("Running full system audit..."):
        inv = probe_system()
        llm_profile = probe_llm(inv.hardware)
        inv.llm = llm_profile
        score, _ = compute_posture_score(inv)
        inv.posture_score = score

    kb = _get_kb()
    kb.save_inventory(inv, baseline=baseline)

    prev = kb.get_baseline() if not baseline else None
    if prev:
        from secteam.core.probe.system import diff_inventory
        diff = diff_inventory(prev, inv)
        if any(v for v in diff.values() if v):
            console.print(Panel(
                json.dumps(diff, indent=2, default=str),
                title="[yellow]Changes since baseline[/yellow]",
            ))
        else:
            console.print("[green]No changes detected since baseline.[/green]")

    console.print(f"\n[green]Audit complete.[/green] Posture score: "
                  f"[bold]{score}/100[/bold]")
    print_status_dashboard(inv, kb)


@app.command()
def ask(
    question: str = typer.Argument(..., help="Question to ask the security team"),
    agent: str = typer.Option("soc_analyst",
                               help="Which agent to ask: coordinator, soc_analyst, threat_intel, etc.")
):
    """Ask any agent a question and get a reasoned answer."""
    inv, kb = _get_inv()
    from secteam.core.system_context import build_context
    from secteam.core.probe.llm_probe import probe_llm
    from secteam.agents.base import SecAgent
    from secteam.actions.research import research as do_research

    llm_profile = inv.llm or probe_llm(inv.hardware)
    model = llm_profile.recommended_models.get(agent, "llama3.1:8b")
    ctx   = build_context(inv)

    def research_fn(q: str) -> str:
        result = do_research(q, kb)
        return result.content

    BIOS = {
        "coordinator":  "CISO — final decision authority, strategic oversight",
        "soc_analyst":  "SOC Analyst — triage, correlation, alert management",
        "threat_intel": "Threat Intel — CVE research, IOC enrichment, MITRE ATT&CK",
        "responder":    "Incident Responder — containment, forensics, eradication",
        "hardener":     "Hardening Engineer — CIS benchmarks, config hardening",
        "monitor":      "Edge/IDS Monitor — network analysis, IDS alerts",
        "auditor":      "Auditor — inventory, compliance, drift detection",
        "forensics":    "Forensics Analyst — deep investigation, evidence preservation",
        "vuln_analyst": "Vulnerability Analyst — scanning, assessment, prioritization",
    }

    ag = SecAgent(
        name=agent.replace("_", " ").title(),
        role=agent,
        bio=BIOS.get(agent, "Security analyst"),
        model=model,
        kb=kb,
        research_fn=research_fn,
        system_context=ctx,
    )

    with console.status(f"[{agent}] thinking..."):
        answer = ag.ask(question)

    console.print(Panel(
        Markdown(answer),
        title=f"[bold cyan]{agent.replace('_',' ').title()}[/bold cyan]",
    ))


@app.command()
def events(
    severity: Optional[str] = typer.Option(None, help="Filter by: CRITICAL, HIGH, MEDIUM, LOW, INFO")
):
    """List open security events."""
    kb = _get_kb()
    open_evts = kb.open_events(severity=severity)
    if not open_evts:
        console.print("[green]No open events.[/green]")
        return

    from rich.table import Table
    from rich import box
    tbl = Table(box=box.MINIMAL_DOUBLE_HEAD)
    tbl.add_column("ID",       width=8)
    tbl.add_column("Severity")
    tbl.add_column("Type")
    tbl.add_column("Source")
    tbl.add_column("Raw")
    tbl.add_column("When")

    COLORS = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
               "LOW": "cyan", "INFO": "dim"}

    for e in sorted(open_evts, key=lambda x: x.severity.value):
        from rich.text import Text
        tbl.add_row(
            e.id[:8],
            Text(e.severity.value, style=COLORS.get(e.severity.value, "")),
            e.event_type,
            e.source,
            e.raw[:80],
            e.timestamp.strftime("%Y-%m-%d %H:%M"),
        )
    console.print(tbl)


@app.command()
def report():
    """Generate a full security posture report."""
    inv, kb = _get_inv()
    r = generate_posture_report(inv, kb)

    console.print(Panel(
        f"Score: [bold]{r.score}/100[/bold]\n"
        f"Open incidents: {r.open_incidents}\n\n"
        "[bold]Critical Gaps:[/bold]\n" +
        "\n".join(f"  • {g}" for g in r.critical_gaps) +
        "\n\n[bold]Active Tools:[/bold]\n" +
        ", ".join(t.name for t in r.installed_tools),
        title="Security Posture Report",
    ))


@app.command()
def tools():
    """Show security tool recommendations and installation commands."""
    inv, _ = _get_inv()
    recs = generate_tool_recommendations(inv)
    console.print(recs)


@app.command()
def install(
    tool_name: str = typer.Argument(..., help="Package name to install"),
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
):
    """Approve and install a recommended security tool."""
    if not confirm:
        ok = typer.confirm(f"Install {tool_name}? This requires sudo.")
        if not ok:
            raise typer.Abort()

    from secteam.actions.hardening import install_security_tool

    POST_INSTALL: dict[str, list[list[str]]] = {
        "fail2ban":  [["systemctl", "enable", "fail2ban"],
                      ["systemctl", "start",  "fail2ban"]],
        "auditd":    [["systemctl", "enable", "auditd"],
                      ["systemctl", "start",  "auditd"]],
        "aide":      [["aideinit"], ["mv", "/var/lib/aide/aide.db.new",
                                     "/var/lib/aide/aide.db"]],
        "lynis":     [],
        "rkhunter":  [["rkhunter", "--update"],
                      ["rkhunter", "--propupd"]],
        "apparmor":  [["systemctl", "enable", "apparmor"],
                      ["systemctl", "start",  "apparmor"]],
        "unattended-upgrades": [
            ["dpkg-reconfigure", "-plow", "unattended-upgrades"]],
    }

    with console.status(f"Installing {tool_name}..."):
        result = install_security_tool(tool_name, POST_INSTALL.get(tool_name))

    if result.get("installed"):
        console.print(f"[green]✓ {tool_name} installed successfully[/green]")
        # Re-run audit to pick up new tool
        console.print("Re-running audit to register new capability...")
        audit_inv = probe_system()
        score, _ = compute_posture_score(audit_inv)
        audit_inv.posture_score = score
        _get_kb().save_inventory(audit_inv)
        console.print(f"[green]New posture score: {score}/100[/green]")
    else:
        console.print(f"[red]✗ Installation failed[/red]")
        console.print(json.dumps(result, indent=2))


@app.command()
def models(pull_recommended: bool = typer.Option(False, "--pull",
           help="Pull recommended models for this hardware")):
    """Show LLM model status and optionally pull recommended models."""
    inv, _ = _get_inv()
    llm = inv.llm or probe_llm(inv.hardware)

    local = list_local_models()
    console.print(Panel(
        f"Provider: {llm.recommended_provider}\n"
        f"Models pulled: {', '.join(local) if local else 'none'}\n"
        f"Local fine-tune: {'yes (' + llm.finetune_backend + ')' if llm.can_finetune_local else 'no'}\n\n"
        "[bold]Recommended per role:[/bold]\n" +
        "\n".join(f"  {role:<20} {model}"
                  for role, model in llm.recommended_models.items()),
        title="LLM Stack",
    ))

    jobs = check_finetune_jobs()
    if jobs:
        console.print("\n[bold]Fine-tune jobs:[/bold]")
        for j in jobs:
            console.print(f"  {j['job_name']} [{j['status']}] base={j['base_model']}")

    if pull_recommended:
        results = recommend_and_pull(inv.hardware, force=True)
        for r in results:
            if r.get("success"):
                console.print(f"[green]Pulled: {r['model']}[/green]")
            elif r.get("pending_approval"):
                console.print(f"[yellow]Pending approval: {r['model']}[/yellow]")
            elif r.get("skipped"):
                console.print(f"[dim]Skipped: {r['model']} — {r['reason']}[/dim]")
            else:
                console.print(f"[red]Failed: {r.get('model')} — {r.get('error')}[/red]")


@app.command()
def pull(model_tag: str = typer.Argument(..., help="Ollama model tag to pull e.g. llama3.1:8b")):
    """Pull a specific Ollama model."""
    with console.status(f"Pulling {model_tag}..."):
        result = pull_model(model_tag)
    if result.get("success"):
        console.print(f"[green]✓ {model_tag} pulled ({result.get('elapsed_seconds', 0):.0f}s)[/green]")
    else:
        console.print(f"[red]✗ Pull failed: {result.get('error')}[/red]")


@app.command()
def start(
    foreground: bool = typer.Option(False, "--foreground", "-f",
                                     help="Run in foreground instead of as daemon"),
):
    """Start the SecTeam monitoring daemon."""
    console.print("[bold blue]Starting SecTeam daemon...[/bold blue]")
    if foreground:
        from secteam.daemon import run_daemon
        asyncio.run(run_daemon())
    else:
        import subprocess
        subprocess.Popen(
            ["python3", str(Path(__file__).parent / "secteam" / "daemon.py")],
            stdout=open("/var/log/secteam.log", "a"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        console.print("[green]Daemon started. Logs: /var/log/secteam.log[/green]")


@app.command()
def research(
    query: str = typer.Argument(..., help="Research query (CVE ID, IP, package, or question)"),
):
    """Research anything — CVEs, IPs, packages, techniques."""
    kb = _get_kb()
    from secteam.actions.research import research as do_research
    with console.status("Researching..."):
        result = do_research(query, kb)

    console.print(Panel(
        result.content + f"\n\n[dim]Source: {result.source} | "
        f"Confidence: {result.confidence:.0%} | "
        f"{'Cached' if result.cached else 'Fresh'}[/dim]",
        title=f"Research: {query}",
    ))


if __name__ == "__main__":
    app()
