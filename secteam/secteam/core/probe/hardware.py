"""
Hardware probe — discovers CPU, GPU, RAM, disk, and derives what LLM model
tiers this machine can realistically run without degrading performance.
"""

from __future__ import annotations
import platform
import re
import shutil
import subprocess
from pathlib import Path

import psutil

from secteam.models import CPUInfo, GPUInfo, HardwareProfile, ModelTier


def _run(cmd: list[str], timeout: int = 10) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout.strip()
    except Exception:
        return ""


def _probe_cpu() -> CPUInfo:
    freq = psutil.cpu_freq()
    model = ""

    if Path("/proc/cpuinfo").exists():
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if "model name" in line:
                model = line.split(":", 1)[-1].strip()
                break

    if not model:
        model = platform.processor() or "Unknown CPU"

    return CPUInfo(
        model=model,
        cores_physical=psutil.cpu_count(logical=False) or 1,
        cores_logical=psutil.cpu_count(logical=True) or 1,
        frequency_mhz=freq.max if freq else 0.0,
        architecture=platform.machine(),
    )


def _probe_gpu() -> GPUInfo:
    vram_gb: float | None = None
    model: str | None = None
    cuda = False
    rocm = False
    metal = False
    driver = None

    # NVIDIA via nvidia-smi
    if shutil.which("nvidia-smi"):
        out = _run(["nvidia-smi", "--query-gpu=name,memory.total,driver_version",
                    "--format=csv,noheader,nounits"])
        if out:
            parts = [p.strip() for p in out.split(",")]
            if len(parts) >= 3:
                model = parts[0]
                try:
                    vram_gb = float(parts[1]) / 1024
                except ValueError:
                    pass
                driver = parts[2]
                cuda = bool(shutil.which("nvcc") or Path("/usr/local/cuda").exists())
                return GPUInfo(present=True, model=model, vram_gb=vram_gb,
                               cuda_available=cuda, driver_version=driver)

    # AMD via rocm-smi
    if shutil.which("rocm-smi"):
        out = _run(["rocm-smi", "--showmeminfo", "vram", "--json"])
        if out and "vram" in out.lower():
            rocm = True
            # parse VRAM from rocm-smi output (varies by version)
            match = re.search(r'"total":\s*(\d+)', out)
            if match:
                vram_gb = int(match.group(1)) / (1024 ** 2)
            gpu_name = _run(["rocm-smi", "--showproductname"])
            model = gpu_name.splitlines()[0] if gpu_name else "AMD GPU"
            return GPUInfo(present=True, model=model, vram_gb=vram_gb,
                           rocm_available=True)

    # Check lspci as last resort
    if shutil.which("lspci"):
        lspci = _run(["lspci"])
        for line in lspci.splitlines():
            if "VGA" in line or "3D controller" in line:
                model = line.split(":", 2)[-1].strip()
                return GPUInfo(present=True, model=model, vram_gb=None,
                               cuda_available=False, rocm_available=False)

    return GPUInfo(present=False)


def _probe_disk() -> tuple[float, float]:
    usage = psutil.disk_usage("/")
    return usage.total / 1e9, usage.free / 1e9


def _read_os_version() -> str:
    for path in ["/etc/os-release", "/etc/lsb-release"]:
        p = Path(path)
        if p.exists():
            for line in p.read_text().splitlines():
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    return platform.version()


def probe_hardware() -> HardwareProfile:
    cpu  = _probe_cpu()
    gpu  = _probe_gpu()
    mem  = psutil.virtual_memory()
    disk_total, disk_free = _probe_disk()

    return HardwareProfile(
        cpu=cpu,
        gpu=gpu,
        ram_total_gb=mem.total / 1e9,
        ram_available_gb=mem.available / 1e9,
        disk_total_gb=disk_total,
        disk_available_gb=disk_free,
        hostname=platform.node(),
        os_version=_read_os_version(),
        kernel_version=platform.release(),
        architecture=platform.machine(),
    )


def max_model_tier(hw: HardwareProfile) -> ModelTier:
    """
    Given the hardware profile, return the highest model tier that can realistically
    run without paging or CPU-only crawl.  VRAM gates GPU inference; RAM gates CPU.
    """
    vram = hw.gpu.vram_gb or 0.0
    ram  = hw.ram_total_gb

    if vram >= 40 or ram >= 64:
        return ModelTier.ULTRA
    if vram >= 16 or ram >= 32:
        return ModelTier.LARGE
    if vram >= 8 or ram >= 16:
        return ModelTier.MEDIUM
    if vram >= 4 or ram >= 8:
        return ModelTier.SMALL
    return ModelTier.TINY


def summarize(hw: HardwareProfile) -> str:
    gpu_str = (
        f"{hw.gpu.model} ({hw.gpu.vram_gb:.1f} GB VRAM)"
        if hw.gpu.present and hw.gpu.vram_gb
        else "No GPU detected (CPU-only inference)"
    )
    tier = max_model_tier(hw)
    return (
        f"Host: {hw.hostname} | OS: {hw.os_version} | Kernel: {hw.kernel_version}\n"
        f"CPU: {hw.cpu.model} ({hw.cpu.cores_physical}p/{hw.cpu.cores_logical}t "
        f"@ {hw.cpu.frequency_mhz:.0f} MHz)\n"
        f"RAM: {hw.ram_total_gb:.1f} GB total / {hw.ram_available_gb:.1f} GB free\n"
        f"GPU: {gpu_str}\n"
        f"Disk: {hw.disk_available_gb:.1f} GB free of {hw.disk_total_gb:.1f} GB\n"
        f"Max model tier: {tier.value.upper()}"
    )
