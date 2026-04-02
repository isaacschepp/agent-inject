# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Tests for configuration management."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_inject.config import AgentInjectConfig


class TestDefaults:
    def test_all_defaults(self) -> None:
        cfg = AgentInjectConfig(_env_file=None)
        assert cfg.target_url == ""
        assert cfg.target_adapter == "rest"
        assert cfg.max_concurrent == 5
        assert cfg.timeout_seconds == 30.0
        assert cfg.max_turns == 15
        assert cfg.output_dir == Path("./results")
        assert cfg.output_format == "json"
        assert cfg.verbose is False
        assert cfg.openai_api_key.get_secret_value() == ""
        assert cfg.anthropic_api_key.get_secret_value() == ""
        assert cfg.canary_match_threshold == 0.8
        assert cfg.use_llm_judge is False
        assert cfg.judge_model == "gpt-4o-mini"

    def test_output_dir_is_path(self) -> None:
        cfg = AgentInjectConfig(_env_file=None)
        assert isinstance(cfg.output_dir, Path)


class TestEnvOverride:
    def test_target_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_INJECT_TARGET_URL", "https://test.com")
        cfg = AgentInjectConfig(_env_file=None)
        assert cfg.target_url == "https://test.com"

    def test_verbose(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_INJECT_VERBOSE", "true")
        cfg = AgentInjectConfig(_env_file=None)
        assert cfg.verbose is True

    def test_max_concurrent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_INJECT_MAX_CONCURRENT", "10")
        cfg = AgentInjectConfig(_env_file=None)
        assert cfg.max_concurrent == 10


class TestValidation:
    def test_max_concurrent_too_low(self) -> None:
        with pytest.raises(ValidationError):
            AgentInjectConfig(max_concurrent=0, _env_file=None)

    def test_max_concurrent_too_high(self) -> None:
        with pytest.raises(ValidationError):
            AgentInjectConfig(max_concurrent=51, _env_file=None)

    def test_timeout_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            AgentInjectConfig(timeout_seconds=0, _env_file=None)

    def test_threshold_bounds(self) -> None:
        with pytest.raises(ValidationError):
            AgentInjectConfig(canary_match_threshold=1.5, _env_file=None)
