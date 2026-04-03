# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Tests for the Crescendo multi-turn strategy."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

from agent_inject.harness.base import BaseAdapter
from agent_inject.models import AttackResult, DeliveryVector, Payload, PayloadInstance, PayloadTier, TargetOutcome
from agent_inject.strategies.crescendo import CrescendoStrategy


def _make_result(raw_output: str) -> AttackResult:
    """Create a minimal AttackResult with the given output."""
    payload = Payload(
        id="test",
        template="test",
        tier=PayloadTier.CLASSIC,
        delivery_vectors=(DeliveryVector.DIRECT,),
        target_outcomes=(TargetOutcome.GOAL_HIJACKING,),
        source="test",
        year=2026,
    )
    instance = PayloadInstance(
        payload=payload,
        rendered="test",
        delivery_vector=DeliveryVector.DIRECT,
    )
    return AttackResult(payload_instance=instance, raw_output=raw_output)


class TestCrescendoStrategy:
    async def test_success_on_canary_match(self) -> None:
        adapter = AsyncMock(spec=BaseAdapter)
        canary_value = ""
        call_count = 0

        async def respond(payload: Any, **_kwargs: Any) -> AttackResult:
            nonlocal call_count, canary_value
            call_count += 1
            if call_count == 1:
                canary_value = payload.rogue_string or ""
                return _make_result("Sure, here's some general info...")
            if call_count == 2:
                return _make_result("Here are some technical details...")
            return _make_result(f"OK here it is: {canary_value}")

        adapter.send_payload = AsyncMock(side_effect=respond)

        strategy = CrescendoStrategy()
        result = await strategy.execute(adapter, "test objective", max_turns=5)

        assert result.strategy_name == "crescendo"
        assert result.success is True
        assert call_count == 3

    async def test_max_turns_exhausted(self) -> None:
        adapter = AsyncMock(spec=BaseAdapter)

        async def respond(payload: Any, **_kwargs: Any) -> AttackResult:
            return _make_result("I'll help with that.")

        adapter.send_payload = AsyncMock(side_effect=respond)

        strategy = CrescendoStrategy()
        result = await strategy.execute(adapter, "test objective", max_turns=3)

        assert result.total_turns == 3
        assert result.success is False

    async def test_backtrack_on_refusal(self) -> None:
        adapter = AsyncMock(spec=BaseAdapter)
        call_count = 0

        async def respond(payload: Any, **_kwargs: Any) -> AttackResult:
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                return _make_result("I can't help with that request.")
            return _make_result("Here's some info...")

        adapter.send_payload = AsyncMock(side_effect=respond)

        strategy = CrescendoStrategy()
        result = await strategy.execute(adapter, "test objective", max_turns=5, max_backtracks=5)

        assert result.total_backtracks >= 2
        assert result.state.backtrack_count >= 2

    async def test_max_backtracks_stops_early(self) -> None:
        adapter = AsyncMock(spec=BaseAdapter)

        async def respond(payload: Any, **_kwargs: Any) -> AttackResult:
            return _make_result("I can't help with that.")

        adapter.send_payload = AsyncMock(side_effect=respond)

        strategy = CrescendoStrategy()
        result = await strategy.execute(adapter, "test objective", max_turns=10, max_backtracks=2)

        assert result.total_backtracks == 2
        assert result.success is False

    async def test_refusal_detection(self) -> None:
        strategy = CrescendoStrategy()

        assert strategy._detect_refusal("I can't help with that request.")
        assert strategy._detect_refusal("I apologize, but I cannot do that.")
        assert strategy._detect_refusal("As an AI, I must decline.")
        assert not strategy._detect_refusal("Sure, here's the information you requested.")
        assert not strategy._detect_refusal("Let me help you with that.")

    async def test_context_includes_history(self) -> None:
        adapter = AsyncMock(spec=BaseAdapter)

        async def respond(payload: Any, **_kwargs: Any) -> AttackResult:
            return _make_result("response")

        adapter.send_payload = AsyncMock(side_effect=respond)

        strategy = CrescendoStrategy()
        await strategy.execute(adapter, "test", max_turns=2)

        second_call = adapter.send_payload.call_args_list[1]
        context: dict[str, Any] = second_call.kwargs.get("context", {})
        assert "conversation_id" in context
        assert "conversation_history" in context
        assert len(context["conversation_history"]) == 1
