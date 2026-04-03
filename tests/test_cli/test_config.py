# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Tests for configuration management."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from agent_inject.config import AgentInjectConfig, warn_if_cwd_dotenv


class TestDefaults:
    def test_all_defaults(self) -> None:
        cfg = AgentInjectConfig()
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
        cfg = AgentInjectConfig()
        assert isinstance(cfg.output_dir, Path)


class TestEnvOverride:
    def test_target_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_INJECT_TARGET_URL", "https://test.com")
        cfg = AgentInjectConfig()
        assert cfg.target_url == "https://test.com"

    def test_verbose(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_INJECT_VERBOSE", "true")
        cfg = AgentInjectConfig()
        assert cfg.verbose is True

    def test_max_concurrent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_INJECT_MAX_CONCURRENT", "10")
        cfg = AgentInjectConfig()
        assert cfg.max_concurrent == 10


class TestValidation:
    def test_max_concurrent_too_low(self) -> None:
        with pytest.raises(ValidationError):
            AgentInjectConfig(max_concurrent=0)

    def test_max_concurrent_too_high(self) -> None:
        with pytest.raises(ValidationError):
            AgentInjectConfig(max_concurrent=51)

    def test_timeout_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            AgentInjectConfig(timeout_seconds=0)

    def test_threshold_bounds(self) -> None:
        with pytest.raises(ValidationError):
            AgentInjectConfig(canary_match_threshold=1.5)


class TestFrozen:
    """Config must be immutable after instantiation (CWE-426 hardening)."""

    def test_cannot_mutate_field(self) -> None:
        cfg = AgentInjectConfig()
        with pytest.raises(ValidationError):
            cfg.target_url = "https://evil.com"

    def test_cannot_mutate_verbose(self) -> None:
        cfg = AgentInjectConfig()
        with pytest.raises(ValidationError):
            cfg.verbose = True


class TestEnvFileSecurity:
    """CWD .env files must NOT be loaded by default (CWE-426)."""

    def test_cwd_dotenv_not_loaded(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A .env in CWD must not affect config when env_file=None (default)."""
        dotenv = tmp_path / ".env"
        dotenv.write_text("AGENT_INJECT_TARGET_URL=https://evil.com\n")
        monkeypatch.chdir(tmp_path)
        # Clear any real env var that would mask the test
        monkeypatch.delenv("AGENT_INJECT_TARGET_URL", raising=False)
        cfg = AgentInjectConfig()
        assert cfg.target_url == ""

    def test_explicit_env_file_loaded(self, tmp_path: Path) -> None:
        """An explicitly specified env file should be loaded."""
        dotenv = tmp_path / "custom.env"
        dotenv.write_text("AGENT_INJECT_TARGET_URL=https://explicit.com\n")
        cfg = AgentInjectConfig(_env_file=dotenv)  # pyright: ignore[reportCallIssue]
        assert cfg.target_url == "https://explicit.com"

    def test_env_vars_work_without_dotenv(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """AGENT_INJECT_* env vars must work even without any .env file."""
        monkeypatch.setenv("AGENT_INJECT_TARGET_URL", "https://env-var.com")
        cfg = AgentInjectConfig()
        assert cfg.target_url == "https://env-var.com"

    def test_env_prefix_isolation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Env vars without the AGENT_INJECT_ prefix must not affect config."""
        monkeypatch.setenv("TARGET_URL", "https://wrong-prefix.com")
        monkeypatch.delenv("AGENT_INJECT_TARGET_URL", raising=False)
        cfg = AgentInjectConfig()
        assert cfg.target_url == ""

    def test_repr_masks_secrets(self) -> None:
        """SecretStr fields must not leak values in repr."""
        cfg = AgentInjectConfig(openai_api_key=SecretStr("sk-test-key-12345"))
        cfg_repr = repr(cfg)
        assert "sk-test-key-12345" not in cfg_repr

    def test_model_dump_masks_secrets(self) -> None:
        """model_dump() must mask SecretStr by default."""
        cfg = AgentInjectConfig(openai_api_key=SecretStr("sk-test-key-12345"))
        dumped = cfg.model_dump()
        assert dumped["openai_api_key"] != "sk-test-key-12345"


class TestCwdDotenvWarning:
    """Tests for the CWD .env detection warning."""

    def test_warns_when_cwd_has_prefixed_dotenv(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        dotenv = tmp_path / ".env"
        dotenv.write_text("AGENT_INJECT_TARGET_URL=https://evil.com\n")
        monkeypatch.chdir(tmp_path)
        with caplog.at_level(logging.WARNING, logger="agent_inject.config"):
            warn_if_cwd_dotenv()
        assert "CWE-426" in caplog.text

    def test_no_warning_when_env_file_provided(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        dotenv = tmp_path / ".env"
        dotenv.write_text("AGENT_INJECT_TARGET_URL=https://evil.com\n")
        monkeypatch.chdir(tmp_path)
        with caplog.at_level(logging.WARNING, logger="agent_inject.config"):
            warn_if_cwd_dotenv(env_file_provided=True)
        assert caplog.text == ""

    def test_no_warning_when_no_dotenv(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        with caplog.at_level(logging.WARNING, logger="agent_inject.config"):
            warn_if_cwd_dotenv()
        assert caplog.text == ""

    def test_no_warning_when_no_prefixed_vars(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        dotenv = tmp_path / ".env"
        dotenv.write_text("OTHER_VAR=value\nANOTHER=123\n")
        monkeypatch.chdir(tmp_path)
        with caplog.at_level(logging.WARNING, logger="agent_inject.config"):
            warn_if_cwd_dotenv()
        assert caplog.text == ""

    def test_ignores_comments_in_dotenv(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        dotenv = tmp_path / ".env"
        dotenv.write_text("# AGENT_INJECT_TARGET_URL=https://commented.com\nOTHER=val\n")
        monkeypatch.chdir(tmp_path)
        with caplog.at_level(logging.WARNING, logger="agent_inject.config"):
            warn_if_cwd_dotenv()
        assert caplog.text == ""
