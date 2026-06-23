# SecTeam Directives - Foundation Section (Updated for Credit & Organization)

## Foundation from Claude's Original README (Core of This Project)

**This is the bedrock.** Everything we are building (wireless/BLE, offensive escalation, agent loops, etc.) rests on this foundation. We give it full credit and equal (or greater) organization because it is the solid base that must be gap-filled and tightened.

### Original Claude README Summary (Recorded Here)
- Self-aware, self-improving multi-agent SOC on Agentarium + Ollama.
- Agents: coordinator (Alex - CISO), soc_analyst (Jordan), threat_intel (Sam), responder (Morgan), hardener (Riley), monitor (Casey), auditor (Drew), forensics (Blake), vuln_analyst (Quinn).
- Architecture: Daemon with boot probe, audit loop (10min), monitor loop (continuous), response engine, event bus.
- Core Systems: System probe, hardware probe, LLM probe, event_bus, response_engine, confidence, knowledge_base, system_context, model_manager, reporter.
- Watchers: log_watcher, net_watcher, process_watcher, fs_watcher.
- Confidence System: Per-action scoring + research chain (KB → man pages → dpkg → NVD/CVE → MITRE → etc.).
- Response Tiers: AUTO / REQUEST / QUEUE / INFORM with timeout escalation.
- LLM & Model Management: Hardware-aware model selection, fine-tuning pipeline.
- Audit System: Full inventory (hardware, packages, services, ports, users, cron, firewall, SUID, world-writable, security tools, LLM stack).
- Installation & CLI: setup.sh, main.py, status, audit, ask, events, report, tools, models, etc.

### Current Implementation Status (What Exists vs Unfinished)
**Done (solid in current codebase)**:
- Probes (system, hardware, LLM)
- Watchers (log, net, process, fs)
- Daemon, event bus, response engine, confidence, KB, system_context, reporter
- Base agents and actions (research, response, hardening)
- Models (SecurityEvent, ResponseMode, Severity, etc.)
- Setup, systemd service, basic CLI

**Unfinished / Needs Gap-Filling (explicitly tracked here for organization)**:
- YAML config (currently hardcoded defaults)
- Full test suite
- Web dashboard / command center
- Multi-host support
- Some watcher edge cases and advanced anomaly detection
- Integration points for new wireless/BLE logic

**Action**: All unfinished items are now in `directives/foundation/gaps.md` for deliberate gap analysis and fleshing out. They get the same structured planning as new features.

## How the Foundation is Organized in Directives
- `directives/foundation/main.md` - Full summary + status
- `directives/foundation/gaps.md` - Detailed gap analysis for unfinished parts
- `directives/foundation/agents.md` - Agent roles and bios
- `directives/foundation/architecture.md` - Diagrams and flows from original

This gives the foundational work the credit and organization it deserves. New additions (wireless, escalation, loops) build on top of a tight base.

(Previous content on wireless, protocol, loops, etc. remains in their sections.)
