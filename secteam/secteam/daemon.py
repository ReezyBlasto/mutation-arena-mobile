"""
SecTeam daemon — the always-on monitoring and response engine.
Runs all watchers concurrently, processes events, and keeps the audit
fresh on a schedule.

Entry points:
  python -m secteam.daemon          # run directly
  systemctl start secteam           # via systemd
"""

from __future__ import annotations
import asyncio
import logging
import os
import signal
import sys
from datetime import datetime
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler

# ensure project is importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from secteam.core.probe.system import probe_system, diff_inventory
from secteam.core.probe.llm_probe import probe_llm
from secteam.core.knowledge_base import KnowledgeBase
from secteam.core.event_bus import EventBus
from secteam.core.response_engine import ResponseEngine
from secteam.core.reporter import compute_posture_score, print_status_dashboard
from secteam.core.system_context import build_context
from secteam.core.watchers.log_watcher import LogWatcherManager
from secteam.core.watchers.net_watcher import NetworkWatcher
from secteam.core.watchers.process_watcher import ProcessWatcher
from secteam.core.watchers.fs_watcher import FilesystemWatcher
from secteam.agents.base import SecAgent
from secteam.actions.research import research as do_research
from secteam.models import ApprovalRequest, SecurityEvent

log = logging.getLogger("secteam.daemon")

DATA_DIR    = Path(os.environ.get("SECTEAM_DATA",    "/var/lib/secteam"))
AUDIT_INTERVAL_MINUTES = int(os.environ.get("AUDIT_INTERVAL", "10"))

AGENT_BIOS = {
    "coordinator":  ("Alex",   "CISO — final decision authority, risk management, team orchestration"),
    "soc_analyst":  ("Jordan", "SOC Analyst — alert triage, event correlation, escalation"),
    "threat_intel": ("Sam",    "Threat Intel — CVE research, IOC enrichment, MITRE ATT&CK mapping"),
    "responder":    ("Morgan", "Incident Responder — containment, isolation, eradication"),
    "hardener":     ("Riley",  "Hardening Engineer — CIS benchmarks, config hardening, patching"),
    "monitor":      ("Casey",  "Edge/IDS Monitor — network analysis, IDS alerting, traffic baselines"),
    "auditor":      ("Drew",   "Auditor — system inventory, compliance, drift detection"),
    "forensics":    ("Blake",  "Forensics Analyst — evidence preservation, timeline reconstruction"),
    "vuln_analyst": ("Quinn",  "Vulnerability Analyst — vuln scanning, CVE triage, patch priority"),
}


class SecTeamDaemon:
    def __init__(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.kb           = KnowledgeBase(DATA_DIR / "knowledge.db")
        self.bus          = EventBus()
        self.scheduler    = AsyncIOScheduler()
        self.agents: dict[str, SecAgent] = {}
        self._running     = False
        self._pending_approvals: list[ApprovalRequest] = []

    # ── Bootstrap ─────────────────────────────────────────────────────────

    async def bootstrap(self) -> None:
        log.info("=" * 60)
        log.info("SecTeam bootstrapping...")

        with _status("Running initial system probe..."):
            inv = probe_system()

        with _status("Probing LLM stack..."):
            llm = probe_llm(inv.hardware)
            inv.llm = llm

        score, _ = compute_posture_score(inv)
        inv.posture_score = score

        is_first = not bool(self.kb.get_baseline())
        self.kb.save_inventory(inv, baseline=is_first)
        log.info("Initial posture score: %.1f/100", score)

        # Pull recommended models (non-blocking — happens in background)
        if llm.recommended_provider == "ollama":
            asyncio.create_task(self._pull_models_background(inv))

        # Build system context for all agents
        ctx = build_context(inv)

        # Initialize all agents
        for role, (name, bio) in AGENT_BIOS.items():
            model = llm.recommended_models.get(role, "llama3.1:8b")

            def make_research_fn(r=role) -> callable:
                def fn(q: str) -> str:
                    result = do_research(q, self.kb)
                    return result.content
                return fn

            def make_escalate_fn(r=role) -> callable:
                def fn(action: str, msg: str) -> None:
                    log.warning("[%s→coordinator] Escalating %s: %s", r, action, msg[:200])
                return fn

            self.agents[role] = SecAgent(
                name=name,
                role=role,
                bio=bio,
                model=model,
                kb=self.kb,
                research_fn=make_research_fn(),
                escalate_fn=make_escalate_fn(),
                system_context=ctx,
            )
            log.info("Agent initialized: %s (%s) → %s", name, role, model)

        # Wire response engine
        self.response_engine = ResponseEngine(
            kb=self.kb,
            dispatch_agent=self._dispatch_agent,
            request_approval=self._request_approval,
        )

        # Subscribe all events through the response engine
        self.bus.subscribe_all(self._handle_event)

        # Set expected ports from inventory (so new ports get flagged)
        from secteam.core.watchers.net_watcher import EXPECTED_LISTENING_PORTS
        EXPECTED_LISTENING_PORTS.update(p.port for p in inv.ports)

        log.info("Bootstrap complete. Team is operational.")

    async def _pull_models_background(self, inv) -> None:
        from secteam.core.llm.model_manager import recommend_and_pull
        results = recommend_and_pull(inv.hardware, force=False)
        for r in results:
            if r.get("pending_approval"):
                log.info("Model recommended (needs approval): %s — run: secteam pull %s",
                         r["model"], r["model"])

    # ── Event handling ────────────────────────────────────────────────────

    async def _handle_event(self, event: SecurityEvent) -> None:
        await self.response_engine.handle(event)

    async def _dispatch_agent(self, role: str, event: SecurityEvent) -> None:
        agent = self.agents.get(role)
        if not agent:
            log.error("No agent for role: %s", role)
            return

        log.info("[%s] Analyzing event: %s (severity=%s)",
                 role, event.event_type, event.severity.value)

        result = agent.analyze_event(event.model_dump())

        log.info(
            "[%s] Analysis complete — confidence=%.2f | action=%s",
            role, result.confidence,
            result.result.get("recommended_action", "none")
            if isinstance(result.result, dict) else "see result",
        )

        # If it's a response action, execute it
        if event.response_mode.value == "AUTO" and event.recommended_action:
            await self._auto_respond(role, event)

    async def _request_approval(self, req: ApprovalRequest) -> None:
        self._pending_approvals.append(req)
        log.warning(
            "[APPROVAL REQUIRED] %s wants to: %s\n"
            "Rationale: %s\n"
            "Risk if denied: %s\n"
            "Timeout: %ds | ID: %s\n"
            "Approve with: secteam approve %s",
            req.requesting_agent, req.proposed_action,
            req.rationale, req.risk_if_denied,
            req.timeout_seconds, req.id[:8], req.id[:8],
        )

    async def _auto_respond(self, role: str, event: SecurityEvent) -> None:
        """Execute auto-response actions based on event type."""
        from secteam.actions import response as resp
        action = event.recommended_action or ""
        enriched = event.enriched

        if action in ("block_ip", "block_ip_permanently"):
            ip = enriched.get("src_ip") or enriched.get("banned_ip") or \
                 (event.iocs[0] if event.iocs else None)
            if ip:
                result = resp.block_ip(ip, reason=f"secteam auto-block: {event.event_type}")
                log.info("Auto-blocked IP %s: %s", ip, result.get("success"))

        elif action in ("kill_and_isolate", "isolate_and_kill"):
            pid = enriched.get("pid")
            ip  = enriched.get("dst_ip") or (event.iocs[0] if event.iocs else None)
            if pid:
                resp.kill_process(pid, force=True)
            if ip:
                resp.block_ip(ip, "secteam auto-block: C2 connection")

        elif action == "rate_limit_ip":
            ip = enriched.get("src_ip")
            if ip:
                resp.rate_limit_ip(ip)

    # ── Periodic audit ────────────────────────────────────────────────────

    async def _periodic_audit(self) -> None:
        log.info("Running scheduled audit...")
        try:
            inv = probe_system()
            inv.llm = probe_llm(inv.hardware)
            score, _ = compute_posture_score(inv)
            inv.posture_score = score

            baseline = self.kb.get_baseline()
            if baseline:
                changes = diff_inventory(baseline, inv)
                if changes.get("config_changes"):
                    from secteam.models import ResponseMode, SecurityEvent, Severity
                    import json
                    for path, diff in changes["config_changes"].items():
                        self.bus.publish(SecurityEvent(
                            source="audit",
                            severity=Severity.HIGH,
                            event_type="config_or_binary_modified",
                            raw=f"Config changed since baseline: {path}",
                            enriched={"path": path, **diff},
                            confidence=0.99,
                            response_mode=ResponseMode.REQUEST,
                        ))

            self.kb.save_inventory(inv)
            ctx = build_context(inv)
            for agent in self.agents.values():
                agent.update_context(ctx)

            log.info("Scheduled audit complete. Score: %.1f/100", score)
        except Exception as e:
            log.exception("Periodic audit failed: %s", e)

    # ── Run ───────────────────────────────────────────────────────────────

    async def run(self) -> None:
        await self.bootstrap()

        # Schedule periodic audit
        self.scheduler.add_job(
            self._periodic_audit,
            "interval",
            minutes=AUDIT_INTERVAL_MINUTES,
            next_run_time=datetime.now(),
        )
        self.scheduler.start()

        # Start all watchers
        inv = self.kb.get_latest_inventory()
        checksums = inv.config_checksums if inv else {}

        watchers = [
            LogWatcherManager(self.bus).start_all(),
            NetworkWatcher(self.bus, interval_seconds=15).start(),
            ProcessWatcher(self.bus, interval_seconds=10).start(),
            FilesystemWatcher(self.bus, checksums).start(),
            self.bus.dispatch(),
        ]

        self._running = True
        log.info("All watchers active. SecTeam is OPERATIONAL.")

        try:
            await asyncio.gather(*[asyncio.create_task(w) for w in watchers])
        except asyncio.CancelledError:
            log.info("Daemon shutdown requested")
        finally:
            self.scheduler.shutdown()
            self._running = False

    def stop(self) -> None:
        self._running = False
        self.bus.stop()


def _status(msg: str):
    """Context manager for simple status logging (no rich in daemon)."""
    class _CM:
        def __enter__(self): log.info(msg); return self
        def __exit__(self, *a): pass
    return _CM()


async def run_daemon() -> None:
    daemon = SecTeamDaemon()

    loop = asyncio.get_running_loop()

    def _shutdown():
        log.info("Shutdown signal received")
        daemon.stop()

    loop.add_signal_handler(signal.SIGTERM, _shutdown)
    loop.add_signal_handler(signal.SIGINT,  _shutdown)

    await daemon.run()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
    )
    asyncio.run(run_daemon())
