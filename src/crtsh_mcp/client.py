"""Small async client for the crt.sh JSON search endpoint (public, no authentication)."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from typing import Any

import httpx

log = logging.getLogger("crtsh_mcp")

DEFAULT_BASE_URL = "https://crt.sh"
RETRY_STATUSES = {429, 502, 503, 504}
CACHE_TTL = 300.0

_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


class CrtShError(Exception):
    """An API or network failure with a message that is safe to show a model."""


def clean_domain(value: str) -> str:
    """Normalise user input such as 'https://*.Example.com/path' to 'example.com'."""
    d = value.strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)
    d = re.split(r"[/?#]", d, maxsplit=1)[0]
    d = d.rsplit("@", 1)[-1]
    d = re.sub(r":\d+$", "", d)
    d = d.lstrip("*%").lstrip(".").rstrip(".")
    labels = d.split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        raise CrtShError(f"'{value}' is not a valid domain name. Pass a name such as example.com or api.example.com.")
    return d


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


class CrtShClient:
    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._cache: dict[tuple, tuple[float, Any]] = {}

    @property
    def base_url(self) -> str:
        return os.environ.get("CRTSH_BASE_URL", DEFAULT_BASE_URL).rstrip("/")

    def _http(self) -> httpx.AsyncClient:
        loop = asyncio.get_running_loop()
        if self._client is None or self._client.is_closed or self._loop is not loop:
            self._loop = loop
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(_float_env("CRTSH_TIMEOUT", 90.0), connect=10.0),
                headers={"Accept": "application/json", "User-Agent": "crtsh-mcp/0.1"},
                follow_redirects=True,
            )
        return self._client

    def clear_cache(self) -> None:
        self._cache.clear()

    async def search(self, query: str, *, exclude_expired: bool = False) -> list[dict[str, Any]]:
        """Run an identity search and return the raw certificate rows (cached for a few minutes)."""
        key = (self.base_url, query, exclude_expired)
        hit = self._cache.get(key)
        if hit and time.monotonic() - hit[0] < CACHE_TTL:
            return hit[1]
        params = {"q": query, "output": "json", "deduplicate": "Y"}
        if exclude_expired:
            params["exclude"] = "expired"
        rows = await self._get(params)
        self._cache[key] = (time.monotonic(), rows)
        return rows

    async def _get(self, params: dict[str, str]) -> list[dict[str, Any]]:
        url = self.base_url + "/"
        retries = int(_float_env("CRTSH_RETRIES", 2))
        delay = _float_env("CRTSH_RETRY_DELAY", 2.0)
        resp: httpx.Response | None = None
        for attempt in range(retries + 1):
            try:
                resp = await self._http().get(url, params=params)
            except httpx.TimeoutException as exc:
                if attempt < retries:
                    await asyncio.sleep(delay * 2**attempt)
                    continue
                raise CrtShError(
                    "crt.sh timed out. Large domains are slow to query; retry, try a narrower name "
                    "(a subdomain), or search without expired certificates."
                ) from exc
            except httpx.HTTPError as exc:
                raise CrtShError(f"Request to crt.sh failed: {type(exc).__name__}: {exc}") from exc
            if resp.status_code in RETRY_STATUSES and attempt < retries:
                await asyncio.sleep(delay * 2**attempt)
                continue
            break
        assert resp is not None
        if resp.status_code in RETRY_STATUSES:
            raise CrtShError(
                f"crt.sh returned HTTP {resp.status_code} after retries. It is often overloaded or the domain has too "
                "many certificates; retry later or query a narrower name (a subdomain) with expired certificates excluded."
            )
        if resp.status_code >= 400:
            raise CrtShError(f"crt.sh returned HTTP {resp.status_code}. {resp.text[:200].strip()}")
        try:
            data = resp.json()
        except ValueError as exc:
            raise CrtShError("crt.sh returned a non-JSON response; it may be under maintenance. Retry later.") from exc
        if not isinstance(data, list):
            raise CrtShError("crt.sh returned an unexpected response shape.")
        return data
