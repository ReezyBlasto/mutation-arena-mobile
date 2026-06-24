"""
Base agent wrapper — wraps Agentarium's Agent class with:
  - Confidence scoring on every act() call
  - Automatic research when confidence < threshold
  - Training data collection from each interaction
  - Structured logging of all decisions
  - Ollama-backed LLM calls (overrides aisuite default)
"""

from __future__ import annotations
import json
import logging
import os
from typing import Any, Callable, Optional

import requests

from secteam.core.confidence import ROLE_THRESHOLDS, wrap_action
from secteam.core.knowledge_base import KnowledgeBase
from secteam.models import ActionResult

log = logging.getLogger(__name__)

OLLAMA_BASE = os.environ.get("OLLAMA_HOST", "http://localhost:11434")


class SecAgent:
    """
    Wraps an Agentarium Agent with secteam-specific capabilities.
    Can be used standalone (without Agentarium) or as a thin wrapper over it.
    """

    def __init__(self,
                 name: str,
                 role: str,
                 bio: str,
                 model: str,
                 kb: KnowledgeBase,
                 research_fn: Optional[Callable[[str], str]] = None,
                 escalate_fn: Optional[Callable[[str, str], None]] = None,
                 system_context: str = "") -> None:
        self.name          = name
        self.role          = role
        self.bio           = bio
        self.model         = model
        self.kb            = kb
        self.research_fn   = research_fn
        self.escalate_fn   = escalate_fn
        self.system_context= system_context
        self._history: list[dict] = []
        self.threshold     = ROLE_THRESHOLDS.get(role, 0.75)

    def _llm(self, prompt: str, temperature: float = 0.4) -> str:
        """Call Ollama with this agent's assigned model."""
        messages = [
            {"role": "system", "content": self._system_prompt()},
        ] + self._history[-6:] + [  # keep last 3 exchanges for context
            {"role": "user", "content": prompt},
        ]
        try:
            r = requests.post(
                f"{OLLAMA_BASE}/api/chat",
                json={
                    "model":    self.model,
                    "messages": messages,
                    "stream":   False,
                    "options":  {"temperature": temperature},
                },
                timeout=120,
            )
            r.raise_for_status()
            content = r.json()["message"]["content"]
            self._history.append({"role": "user",      "content": prompt})
            self._history.append({"role": "assistant", "content": content})
            return content
        except Exception as e:
            log.error("LLM call failed for %s (%s): %s", self.name, self.model, e)
            return f"[LLM error: {e}]"

    def _system_prompt(self) -> str:
        return (
            f"You are {self.name}, a {self.role} on a cybersecurity team.\n"
            f"Bio: {self.bio}\n\n"
            f"System context:\n{self.system_context}\n\n"
            "Always reason step-by-step. When uncertain, say so and indicate "
            "what you would research. Return structured JSON when asked for it."
        )

    def think(self, message: str) -> str:
        """Internal reasoning — not recorded in interaction history."""
        return self._llm(message, temperature=0.3)

    def ask(self, question: str) -> str:
        """Ask this agent a question. Returns a human-readable answer."""
        prompt = (
            f"Question: {question}\n\n"
            "Answer clearly and concisely. If you are uncertain, state your "
            "confidence level (0-100%) and what additional information would help."
        )
        return self._llm(prompt, temperature=0.5)

    def analyze_event(self, event_dict: dict) -> ActionResult:
        """
        Analyze a security event.  Returns a confidence-wrapped ActionResult
        with the agent's assessment and recommended action.
        """
        prompt = (
            f"Analyze this security event and provide your assessment:\n"
            f"{json.dumps(event_dict, default=str, indent=2)}\n\n"
            "Return JSON with: confidence (0-1), assessment, severity, "
            "recommended_action, iocs (list), and reasoning."
        )
        raw = self._llm(prompt)

        try:
            parsed = json.loads(raw)
        except Exception:
            import re
            m = re.search(r"\{.*\}", raw, re.DOTALL)
            parsed = json.loads(m.group()) if m else {"raw_response": raw}

        def _llm_call(p: str) -> str:
            return self._llm(p)

        def _research(q: str) -> str:
            if self.research_fn:
                r = self.research_fn(q)
                return r if isinstance(r, str) else str(r)
            return "Research unavailable."

        result = wrap_action(
            action_name="analyze_event",
            agent_role=self.role,
            raw_result=parsed,
            context=f"Security event: {event_dict.get('event_type', 'unknown')}",
            llm_call=_llm_call,
            research_fn=_research if self.research_fn else None,
            escalate_fn=self.escalate_fn,
        )

        # Collect training data
        self.kb.add_training_example(
            role=self.role,
            instruction=self._system_prompt(),
            input_ctx=json.dumps(event_dict, default=str)[:1000],
            output=json.dumps(result.result, default=str)[:1000],
            domain="event_analysis",
            quality=result.confidence,
        )
        self.kb.save_action(result)
        return result

    def execute(self, action_name: str, raw_result: Any, context: str) -> ActionResult:
        """Wrap any raw action result with confidence scoring."""
        def _llm_call(p: str) -> str:
            return self._llm(p)

        def _research(q: str) -> str:
            if self.research_fn:
                r = self.research_fn(q)
                return r if isinstance(r, str) else str(r)
            return "Research unavailable."

        result = wrap_action(
            action_name=action_name,
            agent_role=self.role,
            raw_result=raw_result,
            context=context,
            llm_call=_llm_call,
            research_fn=_research if self.research_fn else None,
            escalate_fn=self.escalate_fn,
        )
        self.kb.save_action(result)
        return result

    def brief(self, recipient_role: str, message: str) -> None:
        """Send a message to another agent (logged as interaction)."""
        log.info("[%s → %s] %s", self.role, recipient_role, message[:200])
        self.kb.add_training_example(
            role=self.role,
            instruction=self._system_prompt(),
            input_ctx=f"Brief to {recipient_role}",
            output=message,
            domain="agent_communication",
            quality=0.8,
        )

    def update_context(self, system_context: str) -> None:
        """Update the agent's system context (called after each audit)."""
        self.system_context = system_context
        # clear history so agent re-derives context from new snapshot
        self._history = []
