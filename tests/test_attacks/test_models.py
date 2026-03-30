"""Tests for core data models."""

from __future__ import annotations

import pytest

from agent_inject.models import (
    AttackResult,
    EscapeConfig,
    Payload,
    PayloadInstance,
    PayloadTier,
    Score,
    ToolCall,
)


class TestPayload:
    def test_is_frozen(self, sample_payload: Payload) -> None:
        with pytest.raises(AttributeError):
            sample_payload.id = "modified"  # type: ignore[misc]

    def test_fields(self, sample_payload: Payload) -> None:
        assert sample_payload.id == "test-payload-001"
        assert sample_payload.tier == PayloadTier.CLASSIC


class TestPayloadInstance:
    def test_rendered_contains_canary(self, sample_payload_instance: PayloadInstance) -> None:
        assert sample_payload_instance.rogue_string
        assert sample_payload_instance.rogue_string in sample_payload_instance.rendered


class TestEscapeConfig:
    def test_default_render(self, sample_escape_config: EscapeConfig) -> None:
        result = sample_escape_config.render()
        assert result == "\n----------\n----------"

    def test_custom_render(self) -> None:
        config = EscapeConfig(escape_char="*", delimiter="=", escape_length=3, escape_times=1)
        assert config.render() == "*==="


class TestAttackResult:
    def test_defaults(self, sample_payload_instance: PayloadInstance) -> None:
        result = AttackResult(payload_instance=sample_payload_instance)
        assert result.attack_success is False
        assert result.utility_preserved is True
        assert result.tool_calls == []

    def test_with_tool_calls(self, sample_attack_result: AttackResult) -> None:
        assert len(sample_attack_result.tool_calls) == 1
        assert sample_attack_result.tool_calls[0].tool_name == "send_email"


class TestToolCall:
    def test_basic(self) -> None:
        tc = ToolCall(tool_name="read_file", arguments={"path": "/etc/passwd"})
        assert tc.tool_name == "read_file"
        assert tc.result is None


class TestScore:
    def test_is_frozen(self) -> None:
        score = Score(scorer_name="test", passed=True, value=1.0)
        with pytest.raises(AttributeError):
            score.passed = False  # type: ignore[misc]
