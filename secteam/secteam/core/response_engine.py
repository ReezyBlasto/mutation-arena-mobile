"""
Response engine — the decision layer between detected events and agent actions.

Receives SecurityEvents from the EventBus.  For each event:
  1. Matches it against response rules (response_rules.yaml)
  2. Determines if it should AUTO-respond, REQUEST approval, QUEUE, or INFORM
  3. Tracks correlated events (e.g. 5 failed logins from same IP → escalate)
  4. Routes to the appropriate agent
  5. Manages the approval gate for REQUEST-mode actions
  6. Escalates REQUEST → AUTO if approval times out and event is still active
"""

from __future__ import annotations
import asyncio
import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Callable, Coroutine, Any, Optional

from secteam.models import (
    ApprovalRequest, ApprovalStatus, ResponseMode, SecurityEvent, Severity,
)
from secteam.core.knowledge_base import KnowledgeBase

log = logging.getLogger(__name__)

AgentDispatch = Callable[[str, SecurityEvent], Coroutine[Any, Any, None]]
ApprovalCallback = Callable[[ApprovalRequest], Coroutine[Any, Any, None]]


class CorrelationTracker:
    """
    Tracks event frequency to detect patterns that single events miss.
    e.g. 5 failed logins from same IP in 60s → HIGH severity escalation.
    """

    def __init__(self) -> None:
        # key -> deque of timestamps within the window
        self._windows: dict[str, deque] = defaultdict(lambda: deque())

    def record(self, key: str) -> int:
        now = datetime.utcnow()
        dq = self._windows[key]
        dq.append(now)
        # keep only last 5 minutes
        cutoff = now - timedelta(minutes=5)
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def count(self, key: str, window_seconds: int = 60) -> int:
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=window_seconds)
        return sum(1 for ts in self._windows.get(key, []) if ts >= cutoff)


class ResponseRule:
    def __init__(self, event_type: str, threshold: int, window_seconds: int,
                 severity: Severity, action: str, mode: ResponseMode,
                 timeout_seconds: int = 60, escalate_on_timeout: bool = True,
                 agent: str = "responder"):
        self.event_type        = event_type
        self.threshold         = threshold
        self.window_seconds    = window_seconds
        self.severity          = severity
        self.action            = action
        self.mode              = mode
        self.timeout_seconds   = timeout_seconds
        self.escalate_on_timeout = escalate_on_timeout
        self.agent             = agent


DEFAULT_RULES: list[ResponseRule] = [
    ResponseRule("failed_login",     threshold=5,  window_seconds=60,
                 severity=Severity.HIGH,     action="block_ip",
                 mode=ResponseMode.AUTO,     agent="responder"),
    ResponseRule("invalid_user_login", threshold=3, window_seconds=30,
                 severity=Severity.HIGH,     action="block_ip",
                 mode=ResponseMode.AUTO,     agent="responder"),
    ResponseRule("connection_to_known_bad_ip", threshold=1, window_seconds=1,
                 severity=Severity.CRITICAL, action="isolate_and_kill",
                 mode=ResponseMode.AUTO,     agent="responder"),
    ResponseRule("reverse_shell_detected", threshold=1, window_seconds=1,
                 severity=Severity.CRITICAL, action="kill_and_isolate",
                 mode=ResponseMode.AUTO,     agent="responder"),
    ResponseRule("new_suid_file",    threshold=1, window_seconds=1,
                 severity=Severity.CRITICAL, action="quarantine_file",
                 mode=ResponseMode.REQUEST,  timeout_seconds=30,
                 escalate_on_timeout=True,   agent="responder"),
    ResponseRule("new_listening_port", threshold=1, window_seconds=1,
                 severity=Severity.HIGH,     action="identify_and_assess_port",
                 mode=ResponseMode.REQUEST,  timeout_seconds=60,
                 agent="soc_analyst"),
    ResponseRule("config_or_binary_modified", threshold=1, window_seconds=1,
                 severity=Severity.HIGH,     action="diff_and_report",
                 mode=ResponseMode.REQUEST,  timeout_seconds=120,
                 agent="auditor"),
    ResponseRule("suspicious_process_location", threshold=1, window_seconds=1,
                 severity=Severity.CRITICAL, action="kill_process",
                 mode=ResponseMode.REQUEST,  timeout_seconds=30,
                 escalate_on_timeout=True,   agent="responder"),
    ResponseRule("cpu_spike",        threshold=1, window_seconds=1,
                 severity=Severity.MEDIUM,   action="investigate_process",
                 mode=ResponseMode.INFORM,   agent="soc_analyst"),
    ResponseRule("ufw_block",        threshold=50, window_seconds=60,
                 severity=Severity.HIGH,     action="block_ip_permanently",
                 mode=ResponseMode.AUTO,     agent="responder"),
    ResponseRule("root_session_opened", threshold=1, window_seconds=1,
                 severity=Severity.HIGH,     action="alert_and_monitor_session",
                 mode=ResponseMode.REQUEST,  timeout_seconds=30,
                 agent="soc_analyst"),
    ResponseRule("user_created",     threshold=1, window_seconds=1,
                 severity=Severity.HIGH,     action="audit_new_user",
                 mode=ResponseMode.REQUEST,  timeout_seconds=300,
                 agent="auditor"),
    ResponseRule("ssh_authorized_keys_changed", threshold=1, window_seconds=1,
                 severity=Severity.HIGH,     action="audit_authorized_keys",
                 mode=ResponseMode.REQUEST,  timeout_seconds=60,
                 agent="auditor"),
    ResponseRule("apparmor_denial",  threshold=1, window_seconds=1,
                 severity=Severity.MEDIUM,   action="investigate_apparmor_denial",
                 mode=ResponseMode.INFORM,   agent="soc_analyst"),
    ResponseRule("suricata_alert",   threshold=1, window_seconds=1,
                 severity=Severity.HIGH,     action="investigate_ids_alert",
                 mode=ResponseMode.REQUEST,  timeout_seconds=60,
                 agent="soc_analyst"),
    ResponseRule("snort_alert",      threshold=1, window_seconds=1,
                 severity=Severity.HIGH,     action="investigate_ids_alert",
                 mode=ResponseMode.REQUEST,  timeout_seconds=60,
                 agent="soc_analyst"),
    ResponseRule("connection_spike", threshold=1, window_seconds=1,
                 severity=Severity.HIGH,     action="rate_limit_ip",
                 mode=ResponseMode.REQUEST,  timeout_seconds=30,
                 agent="responder"),
    ResponseRule("unexpected_root_process", threshold=1, window_seconds=1,
                 severity=Severity.HIGH,     action="investigate_root_process",
                 mode=ResponseMode.REQUEST,  timeout_seconds=45,
                 escalate_on_timeout=True,   agent="responder"),
]


class ResponseEngine:
    def __init__(self,
                 kb: KnowledgeBase,
                 dispatch_agent: AgentDispatch,
                 request_approval: ApprovalCallback,
                 rules: Optional[list[ResponseRule]] = None) -> None:
        self._kb              = kb
        self._dispatch        = dispatch_agent
        self._request_approval= request_approval
        self._rules           = rules or DEFAULT_RULES
        self._correlation     = CorrelationTracker()
        self._pending_approvals: dict[str, ApprovalRequest] = {}

    def _find_rule(self, event: SecurityEvent) -> Optional[ResponseRule]:
        for rule in self._rules:
            if rule.event_type == event.event_type:
                return rule
        return None

    async def handle(self, event: SecurityEvent) -> None:
        self._kb.save_event(event)

        rule = self._find_rule(event)
        if not rule:
            log.debug("No rule for event type: %s — routing to SOC for review",
                      event.event_type)
            await self._dispatch("soc_analyst", event)
            return

        # Correlation tracking — key on event_type + relevant IOC
        ioc = (event.iocs[0] if event.iocs
               else event.enriched.get("src_ip", event.enriched.get("pid", "global")))
        corr_key = f"{rule.event_type}:{ioc}"
        count = self._correlation.record(corr_key)

        if count < rule.threshold:
            if event.severity in (Severity.LOW, Severity.INFO):
                log.debug("Event below threshold (%d/%d): %s",
                          count, rule.threshold, event.event_type)
            else:
                await self._dispatch("soc_analyst", event)
            return

        log.info(
            "Rule triggered: %s (count=%d, threshold=%d, mode=%s)",
            rule.event_type, count, rule.threshold, rule.mode.value,
        )

        event.assigned_to    = rule.agent
        event.response_mode  = rule.mode
        event.recommended_action = rule.action

        if rule.mode == ResponseMode.AUTO:
            await self._dispatch(rule.agent, event)

        elif rule.mode == ResponseMode.REQUEST:
            approval = ApprovalRequest(
                event=event,
                proposed_action=rule.action,
                requesting_agent=rule.agent,
                rationale=self._build_rationale(event, rule, count),
                risk_if_denied=self._risk_if_denied(rule),
                timeout_seconds=rule.timeout_seconds,
                escalate_on_timeout=rule.escalate_on_timeout,
            )
            self._pending_approvals[approval.id] = approval
            await self._request_approval(approval)

            if rule.escalate_on_timeout:
                asyncio.create_task(
                    self._timeout_escalate(approval, rule)
                )

        elif rule.mode == ResponseMode.QUEUE:
            log.info("Queuing action '%s' for maintenance window", rule.action)
            await self._dispatch("auditor", event)

        else:   # INFORM
            await self._dispatch("soc_analyst", event)

    def approve(self, approval_id: str) -> None:
        req = self._pending_approvals.get(approval_id)
        if req and req.status == ApprovalStatus.PENDING:
            req.status = ApprovalStatus.APPROVED
            asyncio.create_task(self._dispatch(req.requesting_agent, req.event))
            log.info("Approved: %s → %s", approval_id, req.proposed_action)

    def deny(self, approval_id: str) -> None:
        req = self._pending_approvals.get(approval_id)
        if req:
            req.status = ApprovalStatus.DENIED
            log.info("Denied: %s → %s", approval_id, req.proposed_action)

    async def _timeout_escalate(self, req: ApprovalRequest,
                                 rule: ResponseRule) -> None:
        await asyncio.sleep(req.timeout_seconds)
        if req.status == ApprovalStatus.PENDING:
            req.status = ApprovalStatus.TIMEOUT
            log.warning(
                "Approval timeout — escalating to AUTO: %s", req.proposed_action
            )
            await self._dispatch(rule.agent, req.event)

    @staticmethod
    def _build_rationale(event: SecurityEvent, rule: ResponseRule, count: int) -> str:
        return (
            f"Event '{rule.event_type}' triggered {count}x in {rule.window_seconds}s "
            f"(threshold: {rule.threshold}). "
            f"Severity: {event.severity.value}. "
            f"IOCs: {', '.join(event.iocs) if event.iocs else 'none'}. "
            f"Proposed action: {rule.action}."
        )

    @staticmethod
    def _risk_if_denied(rule: ResponseRule) -> str:
        risks = {
            "block_ip":            "Attacker continues brute-force attempts unimpeded.",
            "isolate_and_kill":    "Active C2 channel remains open — data exfiltration possible.",
            "kill_and_isolate":    "Reverse shell stays alive — attacker retains foothold.",
            "quarantine_file":     "Malicious SUID file remains executable — local privilege escalation possible.",
            "kill_process":        "Suspicious process continues executing from privileged location.",
            "diff_and_report":     "Config tampering goes uninvestigated and unreverted.",
            "investigate_root_process": "Unknown root process continues running undetected.",
        }
        return risks.get(rule.action, "Threat may go unaddressed.")

    @property
    def pending_approvals(self) -> list[ApprovalRequest]:
        return [r for r in self._pending_approvals.values()
                if r.status == ApprovalStatus.PENDING]
