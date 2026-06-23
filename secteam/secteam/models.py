"""
Central Pydantic models used across the entire secteam system.
Everything that crosses a module boundary lives here to avoid circular imports.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field
import uuid


# ── Enumerations ──────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class ResponseMode(str, Enum):
    AUTO     = "AUTO"      # act immediately, no human needed
    REQUEST  = "REQUEST"   # ask human first, timeout escalates to AUTO
    QUEUE    = "QUEUE"     # schedule for next maintenance window
    INFORM   = "INFORM"    # log and notify, no action


class ApprovalStatus(str, Enum):
    PENDING  = "PENDING"
    APPROVED = "APPROVED"
    DENIED   = "DENIED"
    TIMEOUT  = "TIMEOUT"   # escalated after timeout


class ToolStatus(str, Enum):
    PRESENT     = "PRESENT"
    MISSING     = "MISSING"
    DEGRADED    = "DEGRADED"   # installed but not running / misconfigured
    RECOMMENDED = "RECOMMENDED"
    CRITICAL    = "CRITICAL"   # missing and security-critical


class ModelTier(str, Enum):
    ULTRA   = "ultra"    # 70B+
    LARGE   = "large"    # 13B-34B
    MEDIUM  = "medium"   # 7B-13B
    SMALL   = "small"    # 1B-7B
    TINY    = "tiny"     # <1B


# ── Hardware ──────────────────────────────────────────────────────────────────

class CPUInfo(BaseModel):
    model: str
    cores_physical: int
    cores_logical: int
    frequency_mhz: float
    architecture: str


class GPUInfo(BaseModel):
    present: bool
    model: Optional[str] = None
    vram_gb: Optional[float] = None
    cuda_available: bool = False
    rocm_available: bool = False
    metal_available: bool = False
    driver_version: Optional[str] = None


class HardwareProfile(BaseModel):
    cpu: CPUInfo
    gpu: GPUInfo
    ram_total_gb: float
    ram_available_gb: float
    disk_total_gb: float
    disk_available_gb: float
    hostname: str
    os_version: str
    kernel_version: str
    architecture: str


# ── LLM / Model ───────────────────────────────────────────────────────────────

class ModelRequirements(BaseModel):
    name: str
    family: str
    params_billions: float
    min_ram_gb: float
    min_vram_gb: float          # 0 = CPU-only capable
    recommended_vram_gb: float
    disk_size_gb: float
    quantization: Optional[str] = None   # Q4_K_M, Q8_0, etc.
    tier: ModelTier
    strengths: list[str] = Field(default_factory=list)
    ollama_tag: Optional[str] = None
    hf_repo: Optional[str] = None


class PulledModel(BaseModel):
    name: str
    size_gb: float
    modified: datetime
    digest: str
    tier: ModelTier = ModelTier.MEDIUM


class LLMProvider(BaseModel):
    name: str                         # ollama, openai, anthropic, together, etc.
    available: bool
    base_url: Optional[str] = None
    api_key_present: bool = False
    models: list[PulledModel] = Field(default_factory=list)
    healthy: bool = False


class LLMProfile(BaseModel):
    providers: list[LLMProvider]
    recommended_provider: str
    recommended_models: dict[str, str]  # agent_role -> model_name
    can_finetune_local: bool
    finetune_backend: Optional[str] = None   # unsloth, llama.cpp, etc.
    cloud_finetune_keys: list[str] = Field(default_factory=list)


# ── System Inventory ──────────────────────────────────────────────────────────

class InstalledPackage(BaseModel):
    name: str
    version: str
    architecture: str
    install_date: Optional[str] = None
    description: Optional[str] = None


class RunningService(BaseModel):
    name: str
    state: str          # running, stopped, failed
    enabled: bool
    pid: Optional[int] = None
    description: Optional[str] = None


class ListeningPort(BaseModel):
    port: int
    protocol: str       # tcp, udp
    address: str
    process: Optional[str] = None
    pid: Optional[int] = None
    package: Optional[str] = None


class SystemUser(BaseModel):
    username: str
    uid: int
    gid: int
    home: str
    shell: str
    sudo_access: bool = False
    last_login: Optional[str] = None


class CronJob(BaseModel):
    owner: str
    schedule: str
    command: str
    source: str         # crontab, /etc/cron.d, systemd-timer, etc.


class FirewallRule(BaseModel):
    number: Optional[int] = None
    action: str         # ALLOW, DENY, REJECT
    direction: str      # IN, OUT, FWD
    protocol: Optional[str] = None
    from_addr: Optional[str] = None
    to_addr: Optional[str] = None
    port: Optional[str] = None
    comment: Optional[str] = None


class SuidFile(BaseModel):
    path: str
    owner: str
    permissions: str
    known_safe: bool = False


class SecurityTool(BaseModel):
    name: str
    display_name: str
    category: str       # ids, hids, firewall, audit, av, hardening, forensics
    status: ToolStatus
    version: Optional[str] = None
    config_path: Optional[str] = None
    log_path: Optional[str] = None
    binary_path: Optional[str] = None
    running: bool = False
    install_cmd: Optional[str] = None
    why_needed: Optional[str] = None
    what_it_unlocks: Optional[str] = None
    priority: int = 5   # 1=critical, 10=optional


class KernelHardening(BaseModel):
    aslr_enabled: bool = False
    ptrace_scope: int = 0
    suid_dumpable: int = 2
    nmi_watchdog: bool = False
    randomize_va_space: int = 0
    tcp_syncookies: bool = False
    ip_forward: bool = False
    accept_redirects: bool = True
    send_redirects: bool = True
    raw: dict[str, str] = Field(default_factory=dict)


class SystemInventory(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    hardware: HardwareProfile
    packages: list[InstalledPackage] = Field(default_factory=list)
    services: list[RunningService] = Field(default_factory=list)
    ports: list[ListeningPort] = Field(default_factory=list)
    users: list[SystemUser] = Field(default_factory=list)
    cron_jobs: list[CronJob] = Field(default_factory=list)
    firewall_rules: list[FirewallRule] = Field(default_factory=list)
    suid_files: list[SuidFile] = Field(default_factory=list)
    security_tools: list[SecurityTool] = Field(default_factory=list)
    kernel_hardening: KernelHardening = Field(default_factory=KernelHardening)
    world_writable_dirs: list[str] = Field(default_factory=list)
    config_checksums: dict[str, str] = Field(default_factory=dict)  # path -> sha256
    llm: Optional[LLMProfile] = None
    posture_score: Optional[float] = None   # 0-100 CIS-style score


# ── Events ────────────────────────────────────────────────────────────────────

class SecurityEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: str                     # auth.log, ufw, process, network, fs, etc.
    severity: Severity
    event_type: str                 # failed_login, new_port, config_change, etc.
    raw: str                        # original log line / data
    enriched: dict[str, Any] = Field(default_factory=dict)
    confidence: float = 1.0
    recommended_action: Optional[str] = None
    response_mode: ResponseMode = ResponseMode.INFORM
    assigned_to: Optional[str] = None   # agent name
    resolved: bool = False
    resolution: Optional[str] = None
    iocs: list[str] = Field(default_factory=list)   # IPs, hashes, domains


# ── Approval Gate ─────────────────────────────────────────────────────────────

class ApprovalRequest(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event: SecurityEvent
    proposed_action: str
    proposed_command: Optional[str] = None
    requesting_agent: str
    rationale: str
    risk_if_denied: str
    timeout_seconds: int = 60
    escalate_on_timeout: bool = True
    status: ApprovalStatus = ApprovalStatus.PENDING


# ── Confidence ────────────────────────────────────────────────────────────────

class ActionResult(BaseModel):
    action_name: str
    agent: str
    confidence: float               # 0.0 - 1.0
    reasoning: str
    result: Any
    needs_research: bool = False
    research_query: Optional[str] = None
    research_results: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    error: Optional[str] = None


# ── Research ──────────────────────────────────────────────────────────────────

class ResearchResult(BaseModel):
    query: str
    source: str                     # cve, mitre, web, manpage, dpkg, etc.
    content: str
    confidence: float
    cached: bool = False
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    urls: list[str] = Field(default_factory=list)


# ── Reports ───────────────────────────────────────────────────────────────────

class IncidentReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    events: list[SecurityEvent]
    timeline: list[dict[str, Any]]
    actions_taken: list[ActionResult]
    root_cause: Optional[str] = None
    recommendations: list[str] = Field(default_factory=list)
    posture_delta: Optional[float] = None


class PostureReport(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    score: float
    previous_score: Optional[float] = None
    categories: dict[str, float]    # category -> score
    critical_gaps: list[str]
    recommendations: list[SecurityTool]
    installed_tools: list[SecurityTool]
    open_incidents: int
    resolved_incidents: int
