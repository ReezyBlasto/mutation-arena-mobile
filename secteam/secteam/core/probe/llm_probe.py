"""
LLM stack discovery probe.  Finds every AI provider available on the system —
Ollama, API keys in environment, local model files, inference servers — then
builds a capability profile and recommends which model each agent should use.
"""

from __future__ import annotations
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests

from secteam.models import (
    HardwareProfile, LLMProfile, LLMProvider, ModelTier,
    PulledModel, ModelRequirements,
)
from secteam.core.probe.hardware import max_model_tier


# ─────────────────────────────────────────────────────────────────────────────
# Model catalogue — what exists in Ollama library and what it needs
# ─────────────────────────────────────────────────────────────────────────────

MODEL_CATALOG: list[ModelRequirements] = [
    # ── TINY (< 3B) ──────────────────────────────────────────────────────────
    ModelRequirements(name="tinyllama:1.1b", family="tinyllama", params_billions=1.1,
        min_ram_gb=2, min_vram_gb=0, recommended_vram_gb=2, disk_size_gb=0.7,
        tier=ModelTier.TINY, ollama_tag="tinyllama:1.1b",
        strengths=["fast classification", "low latency monitoring"]),
    ModelRequirements(name="phi3:mini", family="phi3", params_billions=3.8,
        min_ram_gb=4, min_vram_gb=0, recommended_vram_gb=4, disk_size_gb=2.3,
        tier=ModelTier.SMALL, ollama_tag="phi3:mini",
        strengths=["reasoning", "instruction following", "fast"]),
    ModelRequirements(name="gemma2:2b", family="gemma2", params_billions=2.0,
        min_ram_gb=3, min_vram_gb=0, recommended_vram_gb=3, disk_size_gb=1.6,
        tier=ModelTier.TINY, ollama_tag="gemma2:2b",
        strengths=["classification", "fast analysis"]),

    # ── SMALL (3B–7B) ────────────────────────────────────────────────────────
    ModelRequirements(name="llama3.2:3b", family="llama3", params_billions=3.2,
        min_ram_gb=4, min_vram_gb=0, recommended_vram_gb=4, disk_size_gb=2.0,
        tier=ModelTier.SMALL, ollama_tag="llama3.2:3b",
        strengths=["general reasoning", "instruction following"]),
    ModelRequirements(name="phi4:mini", family="phi4", params_billions=3.8,
        min_ram_gb=4, min_vram_gb=0, recommended_vram_gb=4, disk_size_gb=2.5,
        tier=ModelTier.SMALL, ollama_tag="phi4-mini",
        strengths=["reasoning", "code analysis", "security"]),

    # ── MEDIUM (7B–13B) ──────────────────────────────────────────────────────
    ModelRequirements(name="llama3.1:8b", family="llama3", params_billions=8.0,
        min_ram_gb=8, min_vram_gb=6, recommended_vram_gb=8, disk_size_gb=4.7,
        tier=ModelTier.MEDIUM, ollama_tag="llama3.1:8b",
        strengths=["general reasoning", "code", "security analysis"]),
    ModelRequirements(name="mistral:7b", family="mistral", params_billions=7.0,
        min_ram_gb=8, min_vram_gb=6, recommended_vram_gb=8, disk_size_gb=4.1,
        tier=ModelTier.MEDIUM, ollama_tag="mistral:7b",
        strengths=["instruction following", "analysis", "fast"]),
    ModelRequirements(name="qwen2.5:7b", family="qwen", params_billions=7.0,
        min_ram_gb=8, min_vram_gb=6, recommended_vram_gb=8, disk_size_gb=4.4,
        tier=ModelTier.MEDIUM, ollama_tag="qwen2.5:7b",
        strengths=["code analysis", "reasoning", "multilingual"]),
    ModelRequirements(name="deepseek-r1:7b", family="deepseek", params_billions=7.0,
        min_ram_gb=8, min_vram_gb=6, recommended_vram_gb=8, disk_size_gb=4.5,
        tier=ModelTier.MEDIUM, ollama_tag="deepseek-r1:7b",
        strengths=["deep reasoning", "chain of thought", "analysis"]),

    # ── LARGE (13B–34B) ──────────────────────────────────────────────────────
    ModelRequirements(name="llama3.1:13b", family="llama3", params_billions=13.0,
        min_ram_gb=16, min_vram_gb=10, recommended_vram_gb=16, disk_size_gb=7.9,
        tier=ModelTier.LARGE, ollama_tag="llama3.1:13b",
        strengths=["complex reasoning", "security analysis", "planning"]),
    ModelRequirements(name="qwen2.5:14b", family="qwen", params_billions=14.0,
        min_ram_gb=16, min_vram_gb=10, recommended_vram_gb=16, disk_size_gb=8.7,
        tier=ModelTier.LARGE, ollama_tag="qwen2.5:14b",
        strengths=["code", "analysis", "instruction following"]),
    ModelRequirements(name="mistral-nemo:12b", family="mistral", params_billions=12.0,
        min_ram_gb=16, min_vram_gb=10, recommended_vram_gb=14, disk_size_gb=7.1,
        tier=ModelTier.LARGE, ollama_tag="mistral-nemo",
        strengths=["reasoning", "code", "128k context"]),
    ModelRequirements(name="deepseek-r1:14b", family="deepseek", params_billions=14.0,
        min_ram_gb=16, min_vram_gb=10, recommended_vram_gb=16, disk_size_gb=9.0,
        tier=ModelTier.LARGE, ollama_tag="deepseek-r1:14b",
        strengths=["deep reasoning", "security", "chain of thought"]),

    # ── ULTRA (70B+) ─────────────────────────────────────────────────────────
    ModelRequirements(name="llama3.1:70b", family="llama3", params_billions=70.0,
        min_ram_gb=40, min_vram_gb=24, recommended_vram_gb=48, disk_size_gb=40.0,
        tier=ModelTier.ULTRA, ollama_tag="llama3.1:70b",
        strengths=["complex reasoning", "planning", "security strategy"]),
    ModelRequirements(name="qwen2.5:72b", family="qwen", params_billions=72.0,
        min_ram_gb=40, min_vram_gb=24, recommended_vram_gb=48, disk_size_gb=43.0,
        tier=ModelTier.ULTRA, ollama_tag="qwen2.5:72b",
        strengths=["strongest reasoning", "code", "analysis"]),
]

# Agent role → what it needs from a model (in priority order)
AGENT_MODEL_NEEDS: dict[str, list[str]] = {
    "coordinator":     ["complex reasoning", "planning", "security strategy"],
    "soc_analyst":     ["analysis", "fast", "classification"],
    "threat_intel":    ["deep reasoning", "security analysis", "analysis"],
    "responder":       ["complex reasoning", "security analysis", "reasoning"],
    "hardener":        ["code analysis", "reasoning", "code"],
    "monitor":         ["fast classification", "fast", "classification"],
    "auditor":         ["instruction following", "analysis", "reasoning"],
    "forensics":       ["deep reasoning", "analysis", "chain of thought"],
    "vuln_analyst":    ["security analysis", "reasoning", "code analysis"],
}

TIER_ORDER = [ModelTier.ULTRA, ModelTier.LARGE, ModelTier.MEDIUM,
              ModelTier.SMALL, ModelTier.TINY]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 10) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout.strip()
    except Exception:
        return ""


def _models_fitting_hardware(hw: HardwareProfile) -> list[ModelRequirements]:
    max_tier = max_model_tier(hw)
    tier_idx = TIER_ORDER.index(max_tier)
    allowed_tiers = TIER_ORDER[tier_idx:]

    vram = hw.gpu.vram_gb or 0.0
    ram  = hw.ram_total_gb
    disk = hw.disk_available_gb

    fitting = []
    for m in MODEL_CATALOG:
        if m.tier not in allowed_tiers:
            continue
        if vram > 0 and m.min_vram_gb > 0:
            if vram < m.min_vram_gb:
                continue
        elif m.min_ram_gb > ram:
            continue
        if m.disk_size_gb > disk:
            continue
        fitting.append(m)

    return fitting


def _best_model_for_role(role: str, available: list[str],
                         fitting: list[ModelRequirements]) -> Optional[str]:
    needs = AGENT_MODEL_NEEDS.get(role, ["reasoning"])
    fitting_names = {m.ollama_tag or m.name for m in fitting}
    candidates_on_system = [m for m in fitting if m.ollama_tag in available
                            and (m.ollama_tag or m.name) in fitting_names]

    if not candidates_on_system:
        # fall back to any fitting model
        candidates_on_system = fitting

    # score by how many needed strengths each model has, then by tier
    def score(m: ModelRequirements) -> tuple:
        strength_score = sum(1 for need in needs
                             if any(need in s for s in m.strengths))
        tier_score = len(TIER_ORDER) - TIER_ORDER.index(m.tier)
        return (strength_score, tier_score)

    best = max(candidates_on_system, key=score, default=None)
    return best.ollama_tag if best else None


# ─────────────────────────────────────────────────────────────────────────────
# Provider probes
# ─────────────────────────────────────────────────────────────────────────────

def _probe_ollama() -> Optional[LLMProvider]:
    if not shutil.which("ollama"):
        return None

    base_url = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    healthy = False
    models: list[PulledModel] = []

    try:
        r = requests.get(f"{base_url}/api/tags", timeout=5)
        if r.status_code == 200:
            healthy = True
            data = r.json()
            for m in data.get("models", []):
                size_gb = m.get("size", 0) / 1e9
                models.append(PulledModel(
                    name=m["name"],
                    size_gb=round(size_gb, 2),
                    modified=datetime.fromisoformat(
                        m.get("modified_at", datetime.utcnow().isoformat()).replace("Z", "+00:00")
                    ),
                    digest=m.get("digest", ""),
                    tier=_infer_tier(m["name"]),
                ))
    except Exception:
        # Ollama installed but not running — that's fine, we can start it
        pass

    return LLMProvider(
        name="ollama",
        available=True,
        base_url=base_url,
        api_key_present=False,
        models=models,
        healthy=healthy,
    )


def _infer_tier(model_name: str) -> ModelTier:
    name = model_name.lower()
    for spec in MODEL_CATALOG:
        if spec.ollama_tag and spec.ollama_tag.lower() in name:
            return spec.tier
    if any(x in name for x in ["70b", "72b", "65b"]):
        return ModelTier.ULTRA
    if any(x in name for x in ["13b", "14b", "12b", "20b", "30b"]):
        return ModelTier.LARGE
    if any(x in name for x in ["7b", "8b", "9b"]):
        return ModelTier.MEDIUM
    if any(x in name for x in ["3b", "4b", "3.8b"]):
        return ModelTier.SMALL
    return ModelTier.TINY


def _probe_api_providers() -> list[LLMProvider]:
    providers = []
    checks = [
        ("openai",    "OPENAI_API_KEY",    "https://api.openai.com/v1"),
        ("anthropic", "ANTHROPIC_API_KEY", "https://api.anthropic.com"),
        ("together",  "TOGETHER_API_KEY",  "https://api.together.xyz/v1"),
        ("replicate", "REPLICATE_API_TOKEN", "https://api.replicate.com/v1"),
        ("huggingface", "HF_TOKEN",         "https://api-inference.huggingface.co"),
        ("groq",      "GROQ_API_KEY",       "https://api.groq.com/openai/v1"),
        ("mistral",   "MISTRAL_API_KEY",    "https://api.mistral.ai/v1"),
    ]
    for name, env_key, url in checks:
        key = os.environ.get(env_key, "")
        providers.append(LLMProvider(
            name=name,
            available=bool(key),
            base_url=url if key else None,
            api_key_present=bool(key),
            models=[],
            healthy=bool(key),
        ))
    return providers


def _can_finetune_local(hw: HardwareProfile) -> tuple[bool, Optional[str]]:
    if hw.gpu.present and (hw.gpu.vram_gb or 0) >= 8:
        if shutil.which("python3") or shutil.which("python"):
            return True, "unsloth"
    if hw.ram_total_gb >= 32:
        return True, "llama.cpp (CPU LoRA)"
    return False, None


def _recommend_models(hw: HardwareProfile, ollama_models: list[str]) -> dict[str, str]:
    fitting = _models_fitting_hardware(hw)
    recs: dict[str, str] = {}
    for role in AGENT_MODEL_NEEDS:
        best = _best_model_for_role(role, ollama_models, fitting)
        if best:
            recs[role] = best
    return recs


# ─────────────────────────────────────────────────────────────────────────────
# Main LLM probe
# ─────────────────────────────────────────────────────────────────────────────

def probe_llm(hw: HardwareProfile) -> LLMProfile:
    providers: list[LLMProvider] = []

    ollama = _probe_ollama()
    if ollama:
        providers.append(ollama)

    providers.extend(_probe_api_providers())

    ollama_models = [m.name for m in (ollama.models if ollama else [])]
    can_ft, ft_backend = _can_finetune_local(hw)

    cloud_keys = [
        p.name for p in providers
        if p.api_key_present and p.name in ("together", "replicate", "huggingface")
    ]

    # choose recommended provider: prefer local Ollama if healthy, else first cloud key
    if ollama and ollama.healthy:
        rec_provider = "ollama"
    elif cloud_keys:
        rec_provider = cloud_keys[0]
    elif providers:
        rec_provider = providers[0].name
    else:
        rec_provider = "ollama"  # default target — will be set up

    rec_models = _recommend_models(hw, ollama_models)

    return LLMProfile(
        providers=providers,
        recommended_provider=rec_provider,
        recommended_models=rec_models,
        can_finetune_local=can_ft,
        finetune_backend=ft_backend,
        cloud_finetune_keys=cloud_keys,
    )


def models_to_download(hw: HardwareProfile, existing: list[str]) -> list[ModelRequirements]:
    """
    Return models that would benefit the security team but aren't yet pulled,
    sorted by priority (most needed roles first, smallest footprint first).
    """
    fitting = _models_fitting_hardware(hw)
    needed: set[str] = set()
    for role in AGENT_MODEL_NEEDS:
        best = _best_model_for_role(role, existing, fitting)
        if best and best not in existing:
            needed.add(best)

    return [m for m in fitting if (m.ollama_tag or m.name) in needed]
