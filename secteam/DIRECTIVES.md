# SecTeam Directives & Integration Plan (Updated 2026-06-23)

**Core Approach (new directive)**: Deliberate, grounded pace. Do not move too fast. For every todo step we plan with files, have explicit discussions (even self-discussion or back-and-forth with Claude via narrow tasks) to explore angles and uncover gaps. Record ALL concepts, insights, and decisions in this file or dedicated sections/bots so we stay aligned to the full vision. User coordinating from phone initially; will boot full system + Ollama later for iteration.

**Agent Loops & Cron Structure**: 
- Agent loops are critical for mutation/self-improvement and mandated results.
- Use small Ollama models on cron with dedicated agent files, training data, and strict guidance/prompts to keep them on task.
- Structure loops and cron jobs so desired outcomes (detection accuracy, threshold tuning, threat research, auditing) are mandated, not left to chance.
- Examples: Periodic BLE/wireless anomaly scanning, confidence threshold review, new threat pattern ingestion from research, posture re-scoring.

**Recording Rule**: Every new concept, gap, decision, or insight goes into this DIRECTIVES.md (or linked files) immediately. This is the single source of truth for vision alignment.

(Previous content remains below...)