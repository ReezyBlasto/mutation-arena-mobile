# SecTeam - Project Overview & Function (Clear Naming for Searchability)

## What This Project Is
**Project Name**: SecTeam (Autonomous Cybersecurity Operations)
**Core Function**: A self-aware, self-improving multi-agent Security Operations Center (SOC) built on Agentarium + Ollama.

It acts as an autonomous team of AI agents that:
- Probes the system on startup for ground truth
- Monitors in real time (logs, network, processes, filesystem)
- Responds to threats with tiered actions (AUTO / REQUEST / QUEUE / INFORM)
- Uses confidence scoring + research chain before acting
- Gets smarter over time via knowledge base and fine-tuning
- Now expanding with deep wireless/BLE/IoT integration and offensive deterrence capabilities

**Why I Was Excited About the Original Claude README**:
The original README described a very solid, mostly implemented foundation:
- Full agent team with clear roles (CISO coordinator, SOC analyst, threat intel, responder, hardener, monitor, auditor, forensics, vuln analyst)
- Clean architecture (daemon, audit loop, monitor loop, response engine, event bus)
- Strong core systems (probes, watchers, confidence, KB, system_context, reporter)
- Practical features (setup.sh, CLI, systemd service)
- Smart design choices (confidence-gated actions, hardware-aware models, tiered responses with escalation)

That foundation is why we are building on it instead of starting from scratch. It is already battle-tested in structure.

## Naming Conventions for Directives (Searchability & Clarity)
To avoid confusion and make everything easy to find, we are using clear, descriptive naming:
- `foundation_original_readme_summary.md` - Full summary of Claude's original README
- `foundation_architecture.md` - Architecture diagram and flows
- `foundation_agent_team.md` - Detailed agent roles and bios
- `foundation_implementation_status.md` - What is done vs unfinished
- `foundation_gaps.md` - Structured gap analysis for unfinished parts
- `wireless_ble_integration.md` - Wireless and BLE addition details
- `escalation_offensive_protocol.md` - Offensive escalation logic
- `agent_loops_cron.md` - Agent loops and cron structure
- `planning_gap_analysis.md` - Per-todo step discussions
- `recording_log.md` - All insights and decisions

This makes searching and navigation much easier as the project grows.

## How to Find Things
- Foundation stuff is under `directives/foundation/`
- New additions have clear names like `wireless_ble_...` or `escalation_...`
- Planning and gaps have their own dedicated files

We are embedding key summaries directly in these files so you don't have to hunt through code or old READMEs.
