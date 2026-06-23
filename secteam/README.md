# SecTeam — Autonomous Cybersecurity Operations

> A self-aware, self-improving multi-agent security team built on [Agentarium](https://github.com/Thytu/Agentarium) and Ollama.
> Designed to run on Ubuntu systems — hardens, monitors, responds, and gets smarter over time.

---

## What This Is

SecTeam is a team of AI agents that collectively function as a Security Operations Center (SOC). It:

1. **Probes itself** on startup — discovers every package, service, port, user, config file, security tool, and piece of hardware on the system
2. **Builds ground truth** — agents are initialized with what actually exists, not what might exist
3. **Monitors in real time** — watches logs, network state, processes, and filesystem simultaneously
4. **Responds to threats** — automatically or with human approval depending on severity and configured rules
5. **Knows what it doesn't know** — every agent action has a confidence score; low confidence triggers research before acting
6. **Gets smarter** — collects training data from every incident, can commission fine-tuned models when capability gaps are identified
7. **Recommends and installs** — identifies missing security tools, explains why they're needed, and installs them with approval

---

## The Agent Team

| Agent | Name | Role | Model Tier | Confidence Threshold |
|-------|------|------|------------|---------------------|
| `coordinator`  | Alex  | CISO — final authority, risk decisions, team orchestration | Largest available | 0.85 |
| `soc_analyst`  | Jordan| SOC Analyst — alert triage, event correlation, escalation | Medium, fast | 0.60 |
| `threat_intel` | Sam   | Threat Intel — CVE research, IOC enrichment, MITRE ATT&CK | Strong at reasoning | 0.70 |
| `responder`    | Morgan| Incident Responder — containment, isolation, eradication | Large, security-capable | 0.82 |
| `hardener`     | Riley | Hardening Engineer — CIS benchmarks, config hardening | Code-capable | 0.88 |
| `monitor`      | Casey | Edge/IDS Monitor — network analysis, IDS alerting | Smallest, fastest | 0.65 |
| `auditor`      | Drew  | Auditor — inventory, compliance, drift detection | Instruction-following | 0.75 |
| `forensics`    | Blake | Forensics Analyst — evidence preservation, timeline reconstruction | Deep reasoning | 0.80 |
| `vuln_analyst` | Quinn | Vulnerability Analyst — vuln scanning, CVE triage, patch priority | Security-capable | 0.75 |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SECTEAM DAEMON                           │
│                                                                 │
│  [BOOT] System Probe → LLM Probe → Tool Registry → Init Agents │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ AUDIT LOOP   │  │ MONITOR LOOP │  │   RESPONSE ENGINE    │  │
│  │ every 10min  │  │ continuous   │  │   event-driven       │  │
│  │              │  │              │  │                      │  │
│  │ full probe   │  │ journald     │  │ match rules          │  │
│  │ diff baseline│  │ log files    │  │ correlate events     │  │
│  │ score posture│  │ network poll │  │ AUTO / REQUEST / QUEUE│ │
│  │ update agents│  │ process poll │  │ approval gate        │  │
│  │ check models │  │ inotify fs   │  │ timeout escalation   │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         └─────────────────┴──────────────────────┘             │
│                            │                                    │
│                       [EVENT BUS]                               │
│                            │                                    │
│         ┌──────────────────┼──────────────────┐                │
│         ▼                  ▼                  ▼                │
│    [SOC Analyst]      [Monitor]         [Threat Intel]         │
│         │                  │                  │                │
│         └──────────────────┴──────────────────┘                │
│                            │                                    │
│                    [CISO Coordinator]                           │
│                            │                                    │
│         ┌──────────────────┼──────────────────┐                │
│         ▼                  ▼                  ▼                │
│    [Responder]       [Hardener]          [Auditor]             │
│                                                                 │
│  [Forensics]                              [Vuln Analyst]       │
└─────────────────────────────────────────────────────────────────┘
```

### Core Systems

| System | File | Purpose |
|--------|------|---------|
| System Probe | `core/probe/system.py` | Full OS inventory |
| Hardware Probe | `core/probe/hardware.py` | CPU/GPU/RAM/disk |
| LLM Probe | `core/probe/llm_probe.py` | AI stack discovery |
| Event Bus | `core/event_bus.py` | Async event routing |
| Response Engine | `core/response_engine.py` | Rule matching + tiered response |
| Confidence System | `core/confidence.py` | Per-action certainty scoring |
| Knowledge Base | `core/knowledge_base.py` | SQLite persistence layer |
| System Context | `core/system_context.py` | Ground-truth context for agents |
| Model Manager | `core/llm/model_manager.py` | Pull, benchmark, fine-tune |
| Reporter | `core/reporter.py` | Posture scoring + rich output |

### Watchers (Real-Time Monitoring)

| Watcher | File | What It Watches |
|---------|------|-----------------|
| Log Watcher | `core/watchers/log_watcher.py` | journald, auth.log, UFW, fail2ban, auditd, AppArmor, IDS |
| Network Watcher | `core/watchers/net_watcher.py` | New ports, outbound connections, known-bad IPs, connection spikes |
| Process Watcher | `core/watchers/process_watcher.py` | New processes, suspicious paths, reverse shells, CPU spikes, root escalation |
| Filesystem Watcher | `core/watchers/fs_watcher.py` | Critical file changes, new SUID files, /tmp executables, SSH key changes |

---

## Confidence System

Every agent action returns a structured result:

```json
{
  "confidence": 0.82,
  "reasoning": "Matched known port-scan pattern in IDS log with high certainty.",
  "result": { ... },
  "needs_research": false,
  "research_query": null
}
```

**Research chain** (triggered when `confidence < threshold`):
```
Local KB cache → Man pages → dpkg/apt → NVD/CVE API → MITRE ATT&CK
→ AbuseIPDB → DuckDuckGo → synthesize → cache result
```

If confidence remains low after research, the action escalates to the CISO agent and the human operator.

---

## Response Tiers

| Tier | When | Action | Human Required |
|------|------|--------|----------------|
| `AUTO` | Confirmed threat, pre-authorized action | Execute immediately | No |
| `REQUEST` | High severity, potentially destructive | Show rationale, wait for approval | Yes (with timeout) |
| `QUEUE` | Medium severity, non-urgent | Schedule for maintenance window | No |
| `INFORM` | Low severity, monitoring data | Log and notify | No |

`REQUEST` actions time out after the configured seconds and **escalate to AUTO** if the event is still active.

---

## LLM & Model Management

### Hardware-Aware Model Selection

The system detects GPU/VRAM, RAM, and disk, then maps each agent to the best model that will actually run:

| Hardware | Max Tier | Example Models |
|----------|----------|----------------|
| No GPU, 8GB RAM | TINY/SMALL | tinyllama, phi3:mini |
| No GPU, 16GB RAM | SMALL/MEDIUM | llama3.2:3b, mistral:7b (slow) |
| 4GB VRAM | SMALL | gemma2:2b, phi3:mini |
| 8GB VRAM | MEDIUM | llama3.1:8b, mistral:7b, qwen2.5:7b |
| 16GB VRAM | LARGE | llama3.1:13b, qwen2.5:14b, deepseek-r1:14b |
| 24GB+ VRAM | ULTRA | llama3.1:70b, qwen2.5:72b |

### Model Routing

Each agent role maps to models with complementary strengths:

```
coordinator   → deepseek-r1 (deep reasoning, planning)
soc_analyst   → llama3.1:8b (analysis, fast)
threat_intel  → deepseek-r1 (reasoning, CVE knowledge)
responder     → llama3.1:8b (security, instruction following)
hardener      → qwen2.5 (code analysis, configs)
monitor       → tinyllama / phi3:mini (fast classification)
auditor       → mistral (instruction following, structured output)
forensics     → deepseek-r1 (chain of thought, deep analysis)
vuln_analyst  → qwen2.5 (code + security analysis)
```

### Fine-Tuning Pipeline

SecTeam collects training data from every incident it handles. When a capability gap is identified:

1. **Local** (if ≥8GB VRAM): Unsloth LoRA fine-tune on the host
2. **Cloud**: Together.ai, Replicate, or HuggingFace (requires API key in environment)

Training data is stored in SQLite and exported as JSONL. Jobs are tracked and models hot-swapped when ready.

---

## Security Tool Coverage

SecTeam detects, monitors, and recommends 17 security tools across 8 categories:

| Category | Tools |
|----------|-------|
| Firewall | UFW |
| HIDS | fail2ban, rkhunter, chkrootkit, AIDE, OSSEC |
| IDS/IPS | Snort, Suricata |
| Audit | auditd, lynis, logwatch |
| Antivirus | ClamAV |
| MAC | AppArmor |
| Patch | unattended-upgrades, needrestart |
| Integrity | debsums |

Missing tools are not silently skipped — they generate recommendations with:
- What the tool does
- Why this specific system needs it right now
- What risk exists without it
- The exact install command
- What agent capabilities it unlocks

---

## Audit System

The audit captures a complete system snapshot:

```
System Identity    → hostname, OS, kernel, architecture, uptime
Hardware           → CPU, RAM, GPU/VRAM, disk
Installed Packages → full dpkg manifest with versions
Running Services   → systemctl state for all units
Listening Ports    → ss -tulnp mapped to owning process
Active Users       → login history, sudo access
Cron Jobs          → all crontabs, /etc/cron.d, systemd timers
Firewall Rules     → UFW rules, iptables chains
Config Checksums   → SHA-256 of 15+ critical files
Kernel Hardening   → 15 sysctl security parameters
SUID/SGID Files    → unknown SUID detection
World-Writable Dirs→ common persistence locations
Security Tools     → presence, version, running state
LLM Stack          → providers, models, fine-tune capability
```

The first run saves a **baseline**. Every subsequent audit diffs against it. Changes trigger security events routed to the appropriate agent.

---

## Installation

### Requirements
- Ubuntu 20.04 / 22.04 / 24.04
- Python 3.10+
- [Ollama](https://ollama.com/download) (recommended) or any API key (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.)
- sudo access

### Quick Install

```bash
git clone <this-repo>
cd mutation-arena-mobile/secteam
sudo bash setup.sh
```

The setup script:
1. Creates a `secteam` system user with minimal privileges
2. Sets up `/opt/secteam` with a Python venv
3. Installs Python dependencies
4. Configures sudoers for specific commands only
5. Installs the systemd service
6. Runs the initial audit and saves the baseline
7. Makes `secteam` available as a CLI command

### Manual / Development Install

```bash
cd secteam
pip install -r requirements.txt
python main.py audit --baseline    # first run — saves baseline
python main.py start --foreground  # run daemon in foreground
```

---

## CLI Reference

```bash
secteam status                    # live dashboard with posture score
secteam audit                     # run full audit, diff against baseline
secteam audit --baseline          # save current state as new baseline
secteam ask "what is on port 4444"# ask any agent a question
secteam ask "analyze this IP 1.2.3.4" --agent threat_intel
secteam events                    # list all open security events
secteam events --severity HIGH    # filter by severity
secteam report                    # full posture report
secteam tools                     # tool recommendations + install commands
secteam install lynis --yes       # install a recommended tool
secteam models                    # LLM model status and recommendations
secteam models --pull             # pull recommended models for this hardware
secteam pull llama3.1:8b          # pull a specific model
secteam research "CVE-2024-1234"  # research a CVE, IP, package, or concept
secteam start                     # start the daemon
secteam start --foreground        # run in foreground (dev mode)
```

---

## Configuration

### Environment Variables

```bash
SECTEAM_DATA=/var/lib/secteam     # data directory (knowledge base, quarantine)
OLLAMA_HOST=http://localhost:11434 # Ollama API endpoint
AUDIT_INTERVAL=10                  # minutes between scheduled audits

# Optional LLM provider keys (auto-detected)
OPENAI_API_KEY=...
ANTHROPIC_API_KEY=...
TOGETHER_API_KEY=...               # also used for cloud fine-tuning
REPLICATE_API_TOKEN=...
HF_TOKEN=...                       # HuggingFace (fine-tuning + models)
GROQ_API_KEY=...                   # fast inference

# Optional security tool keys
ABUSEIPDB_KEY=...                  # IP reputation (free tier works without key)
VIRUSTOTAL_KEY=...                 # file hash reputation
SHODAN_KEY=...                     # passive reconnaissance
```

Set in `/etc/secteam/secteam.env` when running as a service.

### Response Rules

Response rules are defined in code (`core/response_engine.py`) but can be extended. Each rule specifies:

```python
ResponseRule(
    event_type="failed_login",
    threshold=5,                  # how many events before rule fires
    window_seconds=60,            # time window for threshold
    severity=Severity.HIGH,
    action="block_ip",
    mode=ResponseMode.AUTO,       # AUTO / REQUEST / QUEUE / INFORM
    timeout_seconds=60,           # for REQUEST mode — time before escalating
    escalate_on_timeout=True,
    agent="responder",            # which agent handles this
)
```

---

## Data Flow

```
[Watcher detects event]
        │
        ▼
[SecurityEvent created + published to EventBus]
        │
        ▼
[ResponseEngine.handle()]
  ├── Save to KnowledgeBase
  ├── Find matching rule
  ├── Track correlation (N events in T seconds)
  └── Route based on threshold + mode:
        ├── AUTO     → dispatch to agent → execute action
        ├── REQUEST  → ApprovalRequest → log warning → start timeout
        │             approve: secteam approve <id>
        │             deny:    secteam deny    <id>
        │             timeout: escalate to AUTO
        ├── QUEUE    → dispatch to auditor for scheduling
        └── INFORM   → dispatch to SOC analyst for logging

[Agent.analyze_event()]
  ├── LLM call → structured assessment
  ├── confidence < threshold?
  │   └── research_chain() → re-evaluate
  ├── still low? → escalate to CISO
  └── save to KnowledgeBase (training data)
```

---

## Training Data & Fine-Tuning

Every agent interaction is recorded as a training example:

```json
{
  "messages": [
    {"role": "system",    "content": "<agent system prompt>"},
    {"role": "user",      "content": "<event or question>"},
    {"role": "assistant", "content": "<agent response>"}
  ],
  "domain": "event_analysis",
  "quality": 0.87
}
```

Domains collected: `event_analysis`, `agent_communication`, `log_analysis`, `hardening`, `cve_research`, `forensics`.

Export training data:
```bash
python3 -c "
from secteam.core.knowledge_base import KnowledgeBase
kb = KnowledgeBase()
data = kb.export_training_data(min_quality=0.8)
import json; print(json.dumps(data, indent=2))
" > training_data.jsonl
```

Submit local fine-tune (requires GPU + unsloth):
```bash
secteam models --pull  # ensure base model is present
# Then programmatically via model_manager.submit_finetune_local()
```

---

## File Structure

```
secteam/
├── README.md                    ← you are here
├── requirements.txt
├── setup.sh                     ← one-command install
├── main.py                      ← CLI entry point
├── secteam/
│   ├── models.py                ← all Pydantic data models
│   ├── daemon.py                ← async daemon + watcher orchestration
│   ├── agents/
│   │   └── base.py              ← SecAgent: Agentarium + confidence + Ollama
│   ├── actions/
│   │   ├── research.py          ← CVE/MITRE/web/manpage/dpkg research chain
│   │   ├── response.py          ← block_ip, kill_process, quarantine, isolate
│   │   └── hardening.py         ← SSH/kernel/UFW/PAM/SUID hardening
│   ├── core/
│   │   ├── probe/
│   │   │   ├── system.py        ← full OS inventory
│   │   │   ├── hardware.py      ← CPU/GPU/RAM/disk detection
│   │   │   └── llm_probe.py     ← Ollama + API key + model selection
│   │   ├── llm/
│   │   │   └── model_manager.py ← pull/benchmark/finetune models
│   │   ├── watchers/
│   │   │   ├── log_watcher.py   ← journald + file tail + pattern matching
│   │   │   ├── net_watcher.py   ← port + connection monitoring
│   │   │   ├── process_watcher.py← process anomaly detection
│   │   │   └── fs_watcher.py    ← inotify critical path watching
│   │   ├── confidence.py        ← confidence scoring + research gate
│   │   ├── event_bus.py         ← async publish/subscribe event routing
│   │   ├── response_engine.py   ← rule matching + tiered response
│   │   ├── knowledge_base.py    ← SQLite: events, research, training data
│   │   ├── system_context.py    ← agent ground-truth context builder
│   │   └── reporter.py          ← posture scoring + rich dashboard
│   └── config/                  ← YAML configs (coming in next phase)
├── systemd/
│   └── secteam.service          ← systemd unit
└── tests/
    └── (test suite in progress)
```

---

## Security Posture Scoring

The audit computes a 0–100 score across weighted categories:

| Category | Weight | What Drives the Score |
|----------|--------|-----------------------|
| Firewall | 15 pts | UFW running, rules configured |
| Auth Hardening | 20 pts | SSH root login disabled, password auth off |
| Kernel Hardening | 15 pts | ASLR, SYN cookies, ptrace scope, etc. |
| Security Tools | 20 pts | lynis, fail2ban, auditd, AIDE, AppArmor present |
| SUID Cleanliness | 10 pts | No unknown SUID files |
| User Hygiene | 10 pts | No direct root logins, minimal sudo users |
| Logging Coverage | 10 pts | auditd, logwatch, journald active |

Score improves automatically as the hardening engineer applies fixes and the install queue is approved.

---

## Known Limitations & Planned Improvements

- [ ] `secteam.config/` YAML config files (currently hardcoded defaults)
- [ ] Web dashboard (FastAPI + htmx) for mobile-friendly monitoring
- [ ] Wazuh / Elastic SIEM integration for centralized logging
- [ ] Shodan passive recon integration (with API key)
- [ ] VirusTotal file hash checking in quarantine workflow
- [ ] Automated AIDE database initialization post-install
- [ ] AppArmor profile auto-generation for new services
- [ ] Multi-host support (agent network across machines)
- [ ] Encrypted knowledge base
- [ ] Fine-tune job cloud polling (check status without blocking)
- [ ] Full test suite

---

## For AI Collaborators (Grok / Claude / Other)

This section exists so AI assistants can understand the project state and contribute meaningfully without needing to re-derive the architecture from scratch.

### Design Philosophy

1. **Ground truth first** — agents never act on assumptions. The system probe runs before any agent is initialized. If a tool isn't confirmed present, it's not used.

2. **Confidence before action** — every action is wrapped in a confidence evaluation. The research chain exists to eliminate uncertainty, not to add latency. Research only fires when needed.

3. **Tiered autonomy** — AUTO actions are pre-authorized by the response rules. REQUEST actions wait for the human. The human is always in the loop for novel situations.

4. **Training as a side effect** — every real incident generates training data automatically. No manual labeling step.

5. **Self-improvement loop** — model → operations → training data → fine-tune → better model → better operations.

6. **No stubbed functions** — everything in this codebase does real work or raises a clear error. No placeholder TODOs left in active code paths.

### Current Implementation Status

| Component | Status | Notes |
|-----------|--------|-------|
| System probe | ✅ Complete | Full inventory including hardware, LLM stack |
| Hardware probe | ✅ Complete | CPU, GPU (NVIDIA + AMD), RAM, disk |
| LLM probe | ✅ Complete | Ollama, API keys, model selection |
| Event bus | ✅ Complete | Async publish/subscribe |
| Confidence system | ✅ Complete | Per-role thresholds, research gate |
| Knowledge base | ✅ Complete | SQLite, research cache, training data |
| Log watcher | ✅ Complete | journald + file tail, 40+ patterns |
| Network watcher | ✅ Complete | Port detection, C2 detection, spikes |
| Process watcher | ✅ Complete | Reverse shells, suspicious paths, root procs |
| Filesystem watcher | ✅ Complete | inotify, SUID detection, critical paths |
| Response engine | ✅ Complete | 18 default rules, correlation tracking |
| Response actions | ✅ Complete | block_ip, kill_process, quarantine, isolate |
| Hardening actions | ✅ Complete | SSH, kernel, UFW, PAM, file permissions |
| Research chain | ✅ Complete | CVE, MITRE, web, manpage, dpkg, IP reputation |
| Model manager | ✅ Complete | Pull, benchmark, local + cloud fine-tune |
| Agent base class | ✅ Complete | SecAgent wrapping Ollama + confidence |
| Daemon | ✅ Complete | Async event loop, schedulers, graceful shutdown |
| CLI | ✅ Complete | All major commands implemented |
| Setup script | ✅ Complete | Idempotent, creates service user, systemd |
| System context | ✅ Complete | Ground-truth context string for agents |
| Posture scoring | ✅ Complete | 7 categories, weighted 0-100 |
| Reporter | ✅ Complete | Rich terminal dashboard, recommendation reports |
| Systemd service | ✅ Complete | With capability grants, resource limits |
| Config YAML | ⏳ Planned | Currently uses hardcoded defaults |
| Web dashboard | ⏳ Planned | FastAPI + htmx |
| Full test suite | ⏳ Planned | Core logic tests in progress |
| Multi-host | ⏳ Planned | Agent network across machines |

### Key Extension Points

**Adding a new response rule:**
Edit `core/response_engine.py` → `DEFAULT_RULES` list. Add a `ResponseRule` with the event_type, threshold, mode, and agent.

**Adding a new security tool to the catalog:**
Edit `core/probe/system.py` → `SECURITY_TOOL_CATALOG`. Add a dict with name, binary path, why_needed, what_it_unlocks, install command.

**Adding a new log pattern:**
Edit `core/watchers/log_watcher.py`. Add a `LogPattern` to the appropriate list (AUTH_PATTERNS, UFW_PATTERNS, etc.). The `extract` dict maps regex named groups to enriched field names.

**Adding a new agent:**
1. Add entry to `AGENT_BIOS` in `daemon.py`
2. Add role threshold to `confidence.py` → `ROLE_THRESHOLDS`
3. Add model needs to `llm_probe.py` → `AGENT_MODEL_NEEDS`
4. Wire up in `daemon.py` → `SecTeamDaemon._dispatch_agent()`

**Adding a new action:**
Create a function in the appropriate `actions/` module. Functions return `dict` with at minimum `success: bool`. Wrap the result with `agent.execute(action_name, result, context)` to get confidence scoring.

### Questions Grok / Claude Should Be Able to Answer

After reading this README:
- Why does the system probe before initializing agents? (ground truth first)
- What happens when confidence < threshold? (research chain, then escalate)
- How does a failed login become a blocked IP? (event → rule match → correlation → AUTO dispatch → response action)
- Where does training data come from? (every `agent.analyze_event()` call)
- How does the system know what model to use? (`llm_probe.py` → hardware → model catalog → role needs → best fit)
- What happens when a critical tool is missing? (audit flags it → reporter shows it → `secteam install <tool>` installs it → re-audit registers new capability)

---

## License

Apache 2.0 — same as [Agentarium](https://github.com/Thytu/Agentarium).

---

*Built with [Agentarium](https://github.com/Thytu/Agentarium) + [Ollama](https://ollama.com)*
