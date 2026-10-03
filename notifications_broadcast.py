"""Realtime notification fan-out to the Node/TypeScript sidecar.

Multi-language split in this project:
  - Python (Quart) owns business logic, auth, DB, billing, security.
  - Node owns the high-concurrency realtime fan-out: WebSocket clients
    subscribe per user, and Python publishes events to the sidecar over a
    loopback HTTP POST. This keeps long-lived socket I/O off the async Python
    event loop.

Wire contract (see node/sidecar.ts):
  POST http://127.0.0.1:8765/publish   { "user": <id>, "event": <name>, "payload": {...} }

This publish is BEST-EFFORT: failures are swallowed (with a short cooldown so a
missing/unreachable sidecar does not add latency to every notification write),
and never block the business path.
"""
import asyncio
import json
import logging
import time
from typing import Optional

logger = logging.getLogger("notif-broadcast")

# Circuit breaker: when the sidecar is unreachable we stop trying for a while
# so notification writes stay fast instead of waiting on a 1s timeout each time.
_DEAD_UNTIL = 0.0
_COOLDOWN = 60.0


def _post(url: str, body: bytes, headers: dict, timeout: float) -> int:
    """Synchronous POST; runs inside asyncio.to_thread so it never blocks the loop."""
    import urllib.request
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status


async def enqueue(user_uid: str, event: str, payload: dict) -> None:
    """Schedule a best-effort publish to the sidecar (fire-and-forget)."""
    if not user_uid:
        return
    try:
        from . import configs
    except Exception:
        return
    if not getattr(configs, "SIDECAR_ENABLED", True):
        return
    if time.time() < _DEAD_UNTIL:
        return
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_publish(str(user_uid), event, payload))
    except Exception:
        pass


async def _publish(user_uid: str, event: str, payload: dict) -> None:
    global _DEAD_UNTIL
    try:
        from . import configs
        url = getattr(configs, "SIDECAR_PUBLISH_URL", "http://127.0.0.1:8765/publish")
        token = getattr(configs, "SIDECAR_PUBLISH_TOKEN", "")
        body = json.dumps(
            {"user": user_uid, "event": event, "payload": payload}
        ).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if token:
            headers["x-publish-token"] = token
        await asyncio.to_thread(_post, url, body, headers, 1.0)
    except Exception as e:
        _DEAD_UNTIL = time.time() + _COOLDOWN
        logger.debug(f"[notif-broadcast] sidecar unreachable, cooling {_COOLDOWN}s: {e}")
