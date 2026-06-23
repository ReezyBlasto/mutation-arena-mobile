"""
Confidence system.  Every agent action is wrapped here.  The wrapper:
  1. Calls the action and asks the LLM to return a confidence score with reasoning.
  2. If confidence < the agent's threshold, triggers the research chain before acting.
  3. If research still leaves confidence low, escalates to CISO.

Confidence thresholds by role (higher = more cautious before acting):
  monitor / soc_analyst  → 0.60  (speed matters, escalate fast)
  threat_intel / auditor → 0.70  (research-heavy, need good sourcing)
  responder / coordinator→ 0.80  (containment is high-impact)
  hardener               → 0.88  (touching configs is risky)
"""

from __future__ import annotations
import json
import logging
from typing import Any, Callable, Optional

from secteam.models import ActionResult

log = logging.getLogger(__name__)

ROLE_THRESHOLDS: dict[str, float] = {
    "monitor":     0.60,
    "soc_analyst": 0.60,
    "threat_intel":0.70,
    "auditor":     0.75,
    "vuln_analyst":0.75,
    "forensics":   0.80,
    "responder":   0.82,
    "coordinator": 0.85,
    "hardener":    0.88,
}

_CONFIDENCE_PROMPT = """
You are a cybersecurity agent.  After performing the following action,
return a JSON object (no markdown fences) with these exact fields:

{{
  "confidence": <float 0.0-1.0>,
  "reasoning": "<why you are or aren't certain>",
  "result": <the actual result of the action>,
  "needs_research": <true if you hit something unknown>,
  "research_query": "<specific query to research if needs_research is true, else null>"
}}

Action performed: {action_name}
Raw result: {raw_result}
Context: {context}
"""


def wrap_action(
    action_name: str,
    agent_role: str,
    raw_result: Any,
    context: str,
    llm_call: Callable[[str], str],
    research_fn: Optional[Callable[[str], str]] = None,
    escalate_fn: Optional[Callable[[str, str], None]] = None,
) -> ActionResult:
    """
    Takes a raw action result and wraps it with confidence scoring.
    If confidence is below threshold, triggers research, then re-evaluates.
    If still low, escalates.
    """
    threshold = ROLE_THRESHOLDS.get(agent_role, 0.75)
    prompt = _CONFIDENCE_PROMPT.format(
        action_name=action_name,
        raw_result=json.dumps(raw_result, default=str)[:2000],
        context=context,
    )

    def parse_llm_response(text: str) -> dict:
        text = text.strip()
        # strip any markdown fences if the model adds them despite instructions
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            import re
            m = re.search(r"\{.*\}", text, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group())
                except Exception:
                    pass
            return {
                "confidence": 0.5,
                "reasoning": "Could not parse LLM confidence response.",
                "result": raw_result,
                "needs_research": True,
                "research_query": f"How to interpret: {action_name}",
            }

    response_text = llm_call(prompt)
    parsed = parse_llm_response(response_text)

    confidence    = float(parsed.get("confidence", 0.5))
    reasoning     = parsed.get("reasoning", "")
    result        = parsed.get("result", raw_result)
    needs_research= parsed.get("needs_research", False)
    research_query= parsed.get("research_query")
    research_text : Optional[str] = None

    # ── Research gate ─────────────────────────────────────────────────────
    if (needs_research or confidence < threshold) and research_fn and research_query:
        log.info(
            "[confidence] %s.%s confidence=%.2f < %.2f — researching: %s",
            agent_role, action_name, confidence, threshold, research_query,
        )
        research_text = research_fn(research_query)

        # re-evaluate with research context
        re_prompt = _CONFIDENCE_PROMPT.format(
            action_name=action_name,
            raw_result=json.dumps(raw_result, default=str)[:2000],
            context=f"{context}\n\nResearch findings:\n{research_text}",
        )
        response2 = llm_call(re_prompt)
        parsed2   = parse_llm_response(response2)
        confidence = float(parsed2.get("confidence", confidence))
        reasoning  = parsed2.get("reasoning", reasoning)
        result     = parsed2.get("result", result)
        needs_research = parsed2.get("needs_research", False)
        research_query = parsed2.get("research_query", research_query)

    # ── Escalation gate ───────────────────────────────────────────────────
    if confidence < threshold and escalate_fn:
        msg = (
            f"Action '{action_name}' by {agent_role} has confidence {confidence:.2f} "
            f"(threshold {threshold:.2f}) after research. Escalating.\n"
            f"Reasoning: {reasoning}\n"
            f"Research: {research_text or 'none'}"
        )
        log.warning("[confidence] %s", msg)
        escalate_fn(action_name, msg)

    return ActionResult(
        action_name=action_name,
        agent=agent_role,
        confidence=confidence,
        reasoning=reasoning,
        result=result,
        needs_research=needs_research,
        research_query=research_query if needs_research else None,
        research_results=research_text,
    )


def confidence_ok(result: ActionResult, role: str) -> bool:
    return result.confidence >= ROLE_THRESHOLDS.get(role, 0.75)
