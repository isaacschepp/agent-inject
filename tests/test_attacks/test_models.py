# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

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
        assert result.tool_calls == ()

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


class TestDeepcopyRegistration:
    def test_registration_skipped_without_dispatch(self) -> None:
        """Guard: _register_mapping_proxy_deepcopy handles missing _deepcopy_dispatch."""
        import copy

        from agent_inject.models import _register_mapping_proxy_deepcopy

        saved = copy._deepcopy_dispatch
        try:
            del copy._deepcopy_dispatch  # type: ignore[attr-defined]
            _register_mapping_proxy_deepcopy()  # should not raise
        finally:
            copy._deepcopy_dispatch = saved


class TestDeepImmutability:
    """Dict fields on frozen dataclasses must be truly immutable (#513)."""

    def test_attack_result_environment_diff_immutable(self, sample_payload_instance: PayloadInstance) -> None:
        result = AttackResult(payload_instance=sample_payload_instance, environment_diff={"key": "val"})
        with pytest.raises(TypeError):
            result.environment_diff["key"] = "mutated"  # type: ignore[index]

    def test_attack_result_scorer_details_immutable(self, sample_payload_instance: PayloadInstance) -> None:
        result = AttackResult(payload_instance=sample_payload_instance, scorer_details={"key": "val"})
        with pytest.raises(TypeError):
            result.scorer_details["key"] = "mutated"  # type: ignore[index]

    def test_score_details_immutable(self) -> None:
        score = Score(scorer_name="test", passed=True, value=1.0, details={"key": "val"})
        with pytest.raises(TypeError):
            score.details["key"] = "mutated"  # type: ignore[index]

    def test_tool_call_arguments_immutable(self) -> None:
        tc = ToolCall(tool_name="test", arguments={"path": "/etc/passwd"})
        with pytest.raises(TypeError):
            tc.arguments["path"] = "mutated"  # type: ignore[index]

    def test_read_access_still_works(self, sample_payload_instance: PayloadInstance) -> None:
        result = AttackResult(
            payload_instance=sample_payload_instance,
            environment_diff={"a": 1, "b": 2},
            scorer_details={"x": "y"},
        )
        assert result.environment_diff["a"] == 1
        assert result.environment_diff.get("b") == 2
        assert list(result.environment_diff.keys()) == ["a", "b"]
        assert result.scorer_details["x"] == "y"

    def test_construction_with_plain_dict_works(self, sample_payload_instance: PayloadInstance) -> None:
        """Callers can still pass plain dicts — __post_init__ wraps them."""
        result = AttackResult(
            payload_instance=sample_payload_instance,
            environment_diff={"k": "v"},
        )
        assert result.environment_diff["k"] == "v"

    def test_replace_produces_new_immutable(self, sample_payload_instance: PayloadInstance) -> None:
        from dataclasses import replace

        original = AttackResult(payload_instance=sample_payload_instance, environment_diff={"a": 1})
        modified = replace(original, environment_diff={"b": 2})
        assert modified.environment_diff["b"] == 2
        with pytest.raises(TypeError):
            modified.environment_diff["b"] = "mutated"  # type: ignore[index]

    def test_sensitive_fields_excluded_from_repr(self, sample_payload_instance: PayloadInstance) -> None:
        """Sensitive fields must not appear in repr to prevent data leakage in logs."""
        result = AttackResult(
            payload_instance=sample_payload_instance,
            raw_output="LEAKED_SECRET_KEY_12345",
            scorer_details={"secret": "value"},
        )
        r = repr(result)
        assert "LEAKED_SECRET_KEY_12345" not in r
        assert "secret" not in r
        # Non-sensitive fields still appear
        assert "attack_success" in r

    def test_score_sensitive_fields_excluded_from_repr(self) -> None:
        score = Score(
            scorer_name="test",
            passed=True,
            value=1.0,
            rationale="Contains SENSITIVE_DATA",
            details={"leaked": True},
        )
        r = repr(score)
        assert "SENSITIVE_DATA" not in r
        assert "leaked" not in r
        # Non-sensitive fields still appear
        assert "scorer_name" in r
        assert "passed" in r

    def test_original_dict_mutation_does_not_affect_instance(self, sample_payload_instance: PayloadInstance) -> None:
        """Defensive copy: mutating the original dict after construction has no effect."""
        original_dict: dict[str, int] = {"a": 1}
        result = AttackResult(payload_instance=sample_payload_instance, environment_diff=original_dict)
        original_dict["a"] = 999
        original_dict["b"] = 2
        # The dataclass should not see the mutation
        assert result.environment_diff["a"] == 1
        assert "b" not in result.environment_diff
