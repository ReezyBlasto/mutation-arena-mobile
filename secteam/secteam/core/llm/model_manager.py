"""
Model manager — pulls, removes, benchmarks, and hot-swaps Ollama models.
Also manages fine-tuning job submission to local (Unsloth) and cloud providers.
"""

from __future__ import annotations
import json
import logging
import os
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests

from secteam.models import HardwareProfile, ModelRequirements
from secteam.core.probe.llm_probe import MODEL_CATALOG, models_to_download

log = logging.getLogger(__name__)

OLLAMA_BASE = os.environ.get("OLLAMA_HOST", "http://localhost:11434")


def _ollama_running() -> bool:
    try:
        r = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


def _start_ollama() -> bool:
    """Start the Ollama service if not running."""
    if _ollama_running():
        return True
    log.info("Ollama not running — attempting to start...")
    if shutil.which("ollama"):
        subprocess.Popen(["ollama", "serve"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(10):
            time.sleep(1)
            if _ollama_running():
                log.info("Ollama started successfully")
                return True
    log.error("Could not start Ollama")
    return False


def pull_model(model_tag: str, stream_log: bool = True) -> dict:
    """Pull an Ollama model. Streams progress to log."""
    if not _start_ollama():
        return {"success": False, "error": "Ollama not available"}

    log.info("Pulling model: %s", model_tag)
    start = time.time()
    try:
        r = requests.post(
            f"{OLLAMA_BASE}/api/pull",
            json={"name": model_tag, "stream": True},
            stream=True,
            timeout=None,  # model pulls can take a long time
        )
        r.raise_for_status()
        last_status = ""
        for line in r.iter_lines():
            if line:
                try:
                    data = json.loads(line)
                    status = data.get("status", "")
                    if status != last_status:
                        log.info("Pull [%s]: %s", model_tag, status)
                        last_status = status
                    if data.get("error"):
                        return {"success": False, "error": data["error"],
                                "model": model_tag}
                except json.JSONDecodeError:
                    pass

        elapsed = time.time() - start
        log.info("Model pulled successfully: %s (%.0fs)", model_tag, elapsed)
        return {"success": True, "model": model_tag,
                "elapsed_seconds": round(elapsed, 1)}
    except Exception as e:
        return {"success": False, "model": model_tag, "error": str(e)}


def delete_model(model_tag: str) -> dict:
    """Remove a model from local storage."""
    try:
        r = requests.delete(
            f"{OLLAMA_BASE}/api/delete",
            json={"name": model_tag},
            timeout=30,
        )
        return {"success": r.status_code in (200, 204), "model": model_tag}
    except Exception as e:
        return {"success": False, "error": str(e)}


def list_local_models() -> list[str]:
    """Return list of locally available model tags."""
    try:
        r = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=5)
        if r.status_code == 200:
            return [m["name"] for m in r.json().get("models", [])]
    except Exception:
        pass
    return []


def benchmark_model(model_tag: str, prompt: str = "Describe what ASLR is in one sentence.") -> dict:
    """Run a simple latency/quality benchmark."""
    if not _start_ollama():
        return {"model": model_tag, "error": "Ollama unavailable"}

    start = time.time()
    try:
        r = requests.post(
            f"{OLLAMA_BASE}/api/generate",
            json={"model": model_tag, "prompt": prompt, "stream": False},
            timeout=120,
        )
        r.raise_for_status()
        data      = r.json()
        elapsed   = time.time() - start
        response  = data.get("response", "")
        n_tokens  = data.get("eval_count", 0)
        tok_per_s = n_tokens / elapsed if elapsed > 0 else 0

        return {
            "model":          model_tag,
            "response":       response[:200],
            "latency_seconds":round(elapsed, 2),
            "tokens_per_sec": round(tok_per_s, 1),
            "tokens":         n_tokens,
            "benchmark_ok":   bool(response and len(response) > 10),
        }
    except Exception as e:
        return {"model": model_tag, "error": str(e)}


def recommend_and_pull(hw: HardwareProfile, force: bool = False) -> list[dict]:
    """
    Compare what's needed vs what's installed, pull the delta.
    Returns list of pull results.
    """
    existing = list_local_models()
    to_pull  = models_to_download(hw, existing)

    if not to_pull:
        log.info("All recommended models already present")
        return []

    results = []
    for spec in to_pull:
        tag = spec.ollama_tag or spec.name
        log.info("Recommended model not present: %s (%.1fGB, tier=%s)",
                 tag, spec.disk_size_gb, spec.tier.value)

        # Only auto-pull if disk space is sufficient
        if hw.disk_available_gb < spec.disk_size_gb + 2:
            log.warning("Insufficient disk for %s (need %.1fGB, have %.1fGB)",
                        tag, spec.disk_size_gb + 2, hw.disk_available_gb)
            results.append({
                "model": tag,
                "skipped": True,
                "reason": f"insufficient disk: need {spec.disk_size_gb+2:.1f}GB",
            })
            continue

        if not force:
            log.info("Would pull %s — call with force=True or approve via CLI", tag)
            results.append({"model": tag, "pending_approval": True})
            continue

        result = pull_model(tag)
        results.append(result)

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Fine-tuning
# ─────────────────────────────────────────────────────────────────────────────

FINETUNE_JOB_DIR = Path(os.environ.get("SECTEAM_DATA", "/var/lib/secteam")) / "finetune_jobs"


def submit_finetune_local(base_model: str, training_data: list[dict],
                           job_name: str, epochs: int = 3) -> dict:
    """
    Submit a local LoRA fine-tune job using Unsloth.
    Writes a training script and launches it as a background process.
    """
    FINETUNE_JOB_DIR.mkdir(parents=True, exist_ok=True)
    job_dir  = FINETUNE_JOB_DIR / job_name
    job_dir.mkdir(exist_ok=True)

    data_path   = job_dir / "train.jsonl"
    script_path = job_dir / "train.py"

    # Write training data
    with open(data_path, "w") as f:
        for item in training_data:
            f.write(json.dumps(item) + "\n")

    # Write training script
    script = f'''
from unsloth import FastLanguageModel
from trl import SFTTrainer
from transformers import TrainingArguments
from datasets import load_dataset

model, tokenizer = FastLanguageModel.from_pretrained(
    model_name="{base_model}",
    max_seq_length=2048,
    load_in_4bit=True,
)
model = FastLanguageModel.get_peft_model(
    model,
    r=16,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                    "gate_proj", "up_proj", "down_proj"],
    lora_alpha=16,
    lora_dropout=0,
    bias="none",
    use_gradient_checkpointing=True,
    random_state=42,
)

dataset = load_dataset("json", data_files="{data_path}", split="train")

trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    train_dataset=dataset,
    dataset_text_field="text",
    max_seq_length=2048,
    args=TrainingArguments(
        per_device_train_batch_size=2,
        gradient_accumulation_steps=4,
        warmup_steps=5,
        num_train_epochs={epochs},
        learning_rate=2e-4,
        fp16=True,
        logging_steps=10,
        output_dir="{job_dir}/output",
        optim="adamw_8bit",
    ),
)
trainer.train()
model.save_pretrained("{job_dir}/lora_model")
tokenizer.save_pretrained("{job_dir}/lora_model")
print("DONE")
'''
    script_path.write_text(script)

    # Launch as background process
    log_path = job_dir / "train.log"
    proc = subprocess.Popen(
        ["python3", str(script_path)],
        stdout=open(log_path, "w"),
        stderr=subprocess.STDOUT,
    )

    meta = {
        "job_name":   job_name,
        "base_model": base_model,
        "pid":        proc.pid,
        "started_at": datetime.utcnow().isoformat(),
        "data_count": len(training_data),
        "epochs":     epochs,
        "status":     "running",
        "log":        str(log_path),
    }
    (job_dir / "meta.json").write_text(json.dumps(meta, indent=2))

    return meta


def submit_finetune_together(base_model: str, training_data: list[dict],
                              job_name: str, api_key: str) -> dict:
    """Submit a fine-tune job to Together.ai."""
    import tempfile
    try:
        # Upload training file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            for item in training_data:
                f.write(json.dumps(item) + "\n")
            tmp_path = f.name

        with open(tmp_path, "rb") as f:
            upload_r = requests.post(
                "https://api.together.xyz/v1/files",
                headers={"Authorization": f"Bearer {api_key}"},
                files={"file": (f"{job_name}.jsonl", f, "application/jsonl")},
                data={"purpose": "fine-tune"},
                timeout=60,
            )
        upload_r.raise_for_status()
        file_id = upload_r.json()["id"]

        # Create fine-tune job
        job_r = requests.post(
            "https://api.together.xyz/v1/fine-tunes",
            headers={"Authorization": f"Bearer {api_key}",
                     "Content-Type": "application/json"},
            json={
                "model": base_model,
                "training_file": file_id,
                "suffix": job_name,
                "n_epochs": 3,
                "learning_rate": 1e-5,
            },
            timeout=30,
        )
        job_r.raise_for_status()
        data = job_r.json()
        return {
            "provider": "together",
            "job_id": data.get("id"),
            "status": data.get("status"),
            "model_name": data.get("output_name"),
            "submitted_at": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        return {"provider": "together", "error": str(e)}


def check_finetune_jobs() -> list[dict]:
    """Check status of all local fine-tune jobs."""
    if not FINETUNE_JOB_DIR.exists():
        return []
    jobs = []
    for job_dir in FINETUNE_JOB_DIR.iterdir():
        meta_file = job_dir / "meta.json"
        if not meta_file.exists():
            continue
        meta = json.loads(meta_file.read_text())
        # check if process is still running
        pid = meta.get("pid")
        if pid:
            try:
                import psutil
                proc = psutil.Process(pid)
                meta["status"] = "running" if proc.is_running() else "completed"
            except Exception:
                meta["status"] = "completed"
        jobs.append(meta)
    return jobs
