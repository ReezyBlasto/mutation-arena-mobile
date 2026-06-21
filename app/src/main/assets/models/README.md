# On-device models

Drop the two fine-tuned Gemma models here:

```
scout.task      ← aggressive scalper
analyst.task    ← cautious risk manager
```

These are **not** committed to git (they're large binaries — see the repo
`.gitignore`). They are produced by the desktop **Mutation Arena** training
pipeline:

1. Evolve + RL-train agents in the arena.
2. Mine the best agents' decisions into a fine-tuning corpus.
3. LoRA fine-tune a **Gemma** base model (e.g. Gemma-2 2B) on that corpus.
4. Convert to the MediaPipe LLM Inference `.task` format
   (`mediapipe` / `ai-edge-torch` conversion).
5. Copy the resulting `scout.task` and `analyst.task` into this folder
   (or ship them via Play Asset Delivery / download-on-first-run for Play Store
   size limits).

If the files are absent, the app still runs and shows the live chart — it just
reports "model not installed" instead of a signal.
