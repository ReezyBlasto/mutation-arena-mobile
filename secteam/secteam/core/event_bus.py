"""
Async event bus.  Watchers push SecurityEvent objects onto the queue.
The dispatcher routes each event to the appropriate agent based on event type
and severity, and feeds it through the response engine.
"""

from __future__ import annotations
import asyncio
import logging
from collections import defaultdict
from typing import Callable, Coroutine, Any

from secteam.models import SecurityEvent, Severity

log = logging.getLogger(__name__)

# Event handlers are async callables that receive a SecurityEvent
Handler = Callable[[SecurityEvent], Coroutine[Any, Any, None]]


class EventBus:
    def __init__(self) -> None:
        self._queue: asyncio.Queue[SecurityEvent] = asyncio.Queue()
        self._handlers: dict[str, list[Handler]] = defaultdict(list)
        self._global_handlers: list[Handler] = []
        self._running = False

    def subscribe(self, event_type: str, handler: Handler) -> None:
        """Subscribe to a specific event type (e.g. 'failed_login')."""
        self._handlers[event_type].append(handler)

    def subscribe_all(self, handler: Handler) -> None:
        """Subscribe to every event regardless of type."""
        self._global_handlers.append(handler)

    def publish(self, event: SecurityEvent) -> None:
        """Non-blocking publish — safe to call from sync code or watchers."""
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            log.error("EventBus queue full — dropping event: %s", event.event_type)

    async def publish_async(self, event: SecurityEvent) -> None:
        await self._queue.put(event)

    async def dispatch(self) -> None:
        """
        Main dispatch loop.  Runs forever; pull events off the queue and fan
        them out to all registered handlers concurrently.
        """
        self._running = True
        log.info("EventBus dispatch loop started")
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except Exception as exc:
                log.exception("EventBus error: %s", exc)
                continue

            handlers = (
                self._handlers.get(event.event_type, [])
                + self._handlers.get("*", [])
                + self._global_handlers
            )

            if not handlers:
                log.debug("No handlers for event type: %s", event.event_type)
                self._queue.task_done()
                continue

            tasks = [asyncio.create_task(h(event)) for h in handlers]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in results:
                if isinstance(r, Exception):
                    log.error("Handler error for event %s: %s", event.event_type, r)

            self._queue.task_done()

    def stop(self) -> None:
        self._running = False

    @property
    def queue_depth(self) -> int:
        return self._queue.qsize()
