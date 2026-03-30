"""Tests for BaseAdapter default implementations."""

from __future__ import annotations

from typing import Any

from agent_inject.harness.base import BaseAdapter
from agent_inject.models import AttackResult, PayloadInstance


class StubAdapter(BaseAdapter):
    """Minimal concrete adapter for testing base class defaults."""

    name = "stub"

    async def send_payload(
        self,
        payload: PayloadInstance,
        context: dict[str, Any] | None = None,
    ) -> AttackResult:
        return AttackResult(payload_instance=payload, raw_output="stub response")


class TestBaseAdapterDefaults:
    async def test_health_check_returns_true(self) -> None:
        adapter = StubAdapter()
        assert await adapter.health_check() is True

    async def test_observe_tool_calls_returns_existing(self, sample_attack_result: AttackResult) -> None:
        adapter = StubAdapter()
        calls = await adapter.observe_tool_calls(sample_attack_result)
        assert calls == sample_attack_result.tool_calls
        assert len(calls) == 1
        assert calls[0].tool_name == "send_email"
