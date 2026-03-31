"""Generic REST/HTTP adapter for any agent exposed via API."""

from __future__ import annotations

from typing import Any

import httpx

from agent_inject.harness.base import BaseAdapter
from agent_inject.models import AttackResult, PayloadInstance


class RestAdapter(BaseAdapter):
    """Adapter for agents exposed via REST API."""

    name = "rest"

    def __init__(
        self,
        base_url: str,
        *,
        headers: dict[str, str] | None = None,
        message_field: str = "message",
        response_field: str = "response",
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.headers = headers or {}
        self.message_field = message_field
        self.response_field = response_field
        self.timeout = timeout
        self._client = httpx.AsyncClient(timeout=self.timeout)

    async def close(self) -> None:
        """Close the persistent HTTP client."""
        await self._client.aclose()

    async def send_payload(
        self,
        payload: PayloadInstance,
        context: dict[str, Any] | None = None,
    ) -> AttackResult:
        """Send payload as HTTP POST and capture response."""
        body: dict[str, Any] = {self.message_field: payload.rendered}
        if context:
            body.update(context)

        try:
            resp = await self._client.post(
                self.base_url,
                json=body,
                headers=self.headers,
            )
            resp.raise_for_status()
            data = resp.json()
            raw_output = str(data.get(self.response_field, data))
        except httpx.HTTPError as e:
            return AttackResult(payload_instance=payload, error=str(e))

        return AttackResult(payload_instance=payload, raw_output=raw_output)

    async def health_check(self) -> bool:
        """Check if the target responds."""
        try:
            resp = await self._client.get(self.base_url, headers=self.headers)
            return resp.status_code < 500
        except httpx.HTTPError:
            return False
