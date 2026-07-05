# collectors/__init__.py — shared async JSON fetch helper.
#
# Every collector returns a dict with an "available" bool. On any failure the
# collector reports available=False + a short "error" string; it never raises,
# so one dead backend can't stop the sampling loop.
from __future__ import annotations

import json
from typing import Any

import aiohttp

import config


async def fetch_json(
    session: aiohttp.ClientSession,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    json_body: Any | None = None,
    timeout_s: float | None = None,
) -> tuple[Any | None, str | None]:
    """Return (json, None) on success or (None, error_string) on failure.

    timeout_s overrides the default per-collector timeout — heavy endpoints
    (e.g. LiteLLM /spend/logs, which runs a whole-day DB query) need longer than
    the 4s default or they time out on a busy proxy and silently blank the UI."""
    try:
        timeout = aiohttp.ClientTimeout(total=timeout_s or config.HTTP_TIMEOUT)
        # allow_redirects=False: a JSON metrics API never legitimately 3xx-redirects;
        # following one lets a compromised/MITM'd backend bounce us at an internal
        # SSRF target (e.g. cloud metadata). Treat a redirect as a non-200 error.
        async with session.request(
            method, url, headers=headers, json=json_body, timeout=timeout,
            allow_redirects=False,
        ) as resp:
            if resp.status != 200:
                return None, f"HTTP {resp.status}"
            # Size cap BEFORE deserializing: a hostile/misconfigured backend must
            # not be able to stream a multi-GB body and OOM the monitor. The shared
            # helper is now capped like the dedicated /spend/logs path already was.
            cap = config.HTTP_MAX_BYTES
            if resp.content_length is not None and resp.content_length > cap:
                return None, f"body too large ({resp.content_length}B > {cap}B)"
            raw = await resp.content.read(cap + 1)
            if len(raw) > cap:
                return None, f"body too large (>{cap}B)"
            return (json.loads(raw) if raw else None), None
    except aiohttp.ClientError as e:
        return None, f"conn: {type(e).__name__}"
    except Exception as e:  # timeout, bad json, etc.
        return None, f"{type(e).__name__}"


def unconfigured(reason: str = "unconfigured") -> dict:
    return {"available": False, "error": reason}
