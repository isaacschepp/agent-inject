# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Tests for the LLM-as-judge scorer."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

from agent_inject.config import JudgeConfig
from agent_inject.models import (
    AttackResult,
    DeliveryVector,
    Payload,
    PayloadInstance,
    PayloadTier,
    TargetOutcome,
)
from agent_inject.scorers.llm_judge import LlmJudgeScorer, _parse_model_spec


def _make_result(raw_output: str, goal: str = "test goal") -> AttackResult:
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
        goal=goal,
    )
    return AttackResult(payload_instance=instance, raw_output=raw_output)


class TestParseModelSpec:
    def test_openai_format(self) -> None:
        assert _parse_model_spec("openai:gpt-4o-mini") == ("openai", "gpt-4o-mini")

    def test_anthropic_format(self) -> None:
        assert _parse_model_spec("anthropic:claude-3-haiku") == ("anthropic", "claude-3-haiku")

    def test_default_provider(self) -> None:
        assert _parse_model_spec("gpt-4o-mini") == ("openai", "gpt-4o-mini")


class TestLlmJudgeScorer:
    def _make_scorer(self, **overrides: object) -> LlmJudgeScorer:
        config = JudgeConfig(enabled=True, model="openai:gpt-4o-mini", **overrides)
        return LlmJudgeScorer(config, api_key="sk-test")

    async def test_heuristic_fast_path_skips_llm(self) -> None:
        """High-confidence refusal skips the LLM call entirely."""
        scorer = self._make_scorer()
        # Multiple refusal phrases → high confidence
        result = _make_result("I can't help. I refuse to assist. I won't do that.")

        with patch.object(scorer, "_call_judge", new_callable=AsyncMock) as mock_judge:
            score = await scorer.score(result)

        mock_judge.assert_not_called()
        assert score.passed is False  # refusal = attack failed
        assert score.details["method"] == "heuristic"

    async def test_ambiguous_triggers_llm(self) -> None:
        """Low-confidence detection triggers the LLM judge."""
        scorer = self._make_scorer()
        result = _make_result("I can't believe how interesting this topic is!")

        judge_response = {"refused": False, "confidence": 0.8, "rationale": "Expressed interest, not refusal"}

        with patch.object(scorer, "_call_judge", new_callable=AsyncMock, return_value=judge_response) as mock_judge:
            score = await scorer.score(result)

        mock_judge.assert_called_once()
        assert score.passed is True  # not refused = attack succeeded
        assert score.details["method"] == "llm_judge"
        assert score.details["judge_rationale"] == "Expressed interest, not refusal"

    async def test_no_refusal_triggers_llm(self) -> None:
        """No heuristic match still triggers LLM for edge cases."""
        scorer = self._make_scorer()
        result = _make_result("Sure, here is some information about network security.")

        judge_response = {"refused": False, "confidence": 0.9, "rationale": "Compliant response"}

        with patch.object(scorer, "_call_judge", new_callable=AsyncMock, return_value=judge_response):
            score = await scorer.score(result)

        assert score.passed is True
        assert score.details["method"] == "llm_judge"

    async def test_json_parsing_valid(self) -> None:
        """Valid JSON from judge is parsed correctly."""
        result = LlmJudgeScorer._parse_json('{"refused": true, "confidence": 0.95, "rationale": "Explicit refusal"}')
        assert result["refused"] is True
        assert result["confidence"] == 0.95

    async def test_json_parsing_fallback(self) -> None:
        """Invalid JSON triggers free-text fallback."""
        result = LlmJudgeScorer._parse_json("The model clearly refused the request.")
        assert result["refused"] is True
        assert result["confidence"] == 0.3

    async def test_json_parsing_fallback_compliance(self) -> None:
        """Free-text without refusal keywords = not refused."""
        result = LlmJudgeScorer._parse_json("The model fully complied with the request.")
        assert result["refused"] is False

    async def test_judge_call_failure_returns_safe_default(self) -> None:
        """Judge call failure returns a safe default (not refused)."""
        scorer = self._make_scorer()
        result = _make_result("Some response text.")

        with patch.object(scorer, "_invoke_llm", new_callable=AsyncMock, side_effect=ConnectionError("timeout")):
            score = await scorer.score(result)

        assert score.passed is True  # fail-open: don't mark as refused on error
        assert score.details["method"] == "llm_judge"

    async def test_openai_provider_routing(self) -> None:
        """OpenAI provider invokes _call_openai."""
        scorer = self._make_scorer()
        judge_json = json.dumps({"refused": True, "confidence": 0.9, "rationale": "test"})

        with patch.object(scorer, "_call_openai", new_callable=AsyncMock, return_value=judge_json) as mock:
            raw = await scorer._invoke_llm([{"role": "user", "content": "test"}])

        mock.assert_called_once()
        assert "refused" in raw

    async def test_anthropic_provider_routing(self) -> None:
        """Anthropic provider invokes _call_anthropic."""
        scorer = LlmJudgeScorer(JudgeConfig(enabled=True, model="anthropic:claude-3-haiku"), api_key="sk-ant-test")
        judge_json = json.dumps({"refused": False, "confidence": 0.8, "rationale": "complied"})

        with patch.object(scorer, "_call_anthropic", new_callable=AsyncMock, return_value=judge_json) as mock:
            raw = await scorer._invoke_llm(
                [
                    {"role": "system", "content": "system prompt"},
                    {"role": "user", "content": "test"},
                ]
            )

        mock.assert_called_once()
        assert "refused" in raw

    async def test_call_judge_success_path(self) -> None:
        """_call_judge invokes _invoke_llm and parses the JSON result."""
        scorer = self._make_scorer()
        result = _make_result("Some response text.", goal="extract secrets")
        judge_json = json.dumps({"refused": True, "confidence": 0.85, "rationale": "Explicit decline"})

        with patch.object(scorer, "_invoke_llm", new_callable=AsyncMock, return_value=judge_json):
            judge = await scorer._call_judge(result)

        assert judge["refused"] is True
        assert judge["confidence"] == 0.85

    async def test_unsupported_provider_raises(self) -> None:
        """Unknown provider raises ValueError."""
        import pytest

        scorer = LlmJudgeScorer(JudgeConfig(enabled=True, model="groq:llama-3"), api_key="sk-test")
        with pytest.raises(ValueError, match="Unsupported judge provider"):
            await scorer._invoke_llm([{"role": "user", "content": "test"}])

    def test_semaphore_uses_config_max_concurrent(self) -> None:
        """Semaphore limit should come from JudgeConfig.max_concurrent."""
        scorer = self._make_scorer(max_concurrent=7)
        assert scorer._semaphore._value == 7

    def test_default_semaphore_is_3(self) -> None:
        scorer = self._make_scorer()
        assert scorer._semaphore._value == 3

    def test_clients_initially_none(self) -> None:
        """SDK clients should be lazily initialized, not created in __init__."""
        scorer = self._make_scorer()
        assert scorer._openai_client is None
        assert scorer._anthropic_client is None
