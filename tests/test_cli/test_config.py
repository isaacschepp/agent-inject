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
        assert cfg.target.url == ""
        assert cfg.target.adapter == "rest"
        assert cfg.target.timeout_seconds == 30.0
        assert cfg.engine.max_concurrent == 5
        assert cfg.engine.max_turns == 15
        assert cfg.output.dir == Path("./results")
        assert cfg.output.format == "json"
        assert cfg.output.verbose is False
        assert cfg.secrets.openai_api_key.get_secret_value() == ""
        assert cfg.secrets.anthropic_api_key.get_secret_value() == ""
        assert cfg.scoring.canary_match_threshold == 0.8
        assert cfg.scoring.use_llm_judge is False
        assert cfg.scoring.judge_model == "gpt-4o-mini"

    def test_output_dir_is_path(self) -> None:
        cfg = AgentInjectConfig()
        assert isinstance(cfg.output.dir, Path)


class TestEnvOverride:
    def test_target_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_INJECT_TARGET__URL", "https://test.com")
        cfg = AgentInjectConfig()
        assert cfg.target.url == "https://test.com"

    def test_verbose(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_INJECT_OUTPUT__VERBOSE", "true")
        cfg = AgentInjectConfig()
        assert cfg.output.verbose is True

    def test_max_concurrent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_INJECT_ENGINE__MAX_CONCURRENT", "10")
        cfg = AgentInjectConfig()
        assert cfg.engine.max_concurrent == 10


class TestValidation:
    def test_max_concurrent_too_low(self) -> None:
        with pytest.raises(ValidationError):
            AgentInjectConfig(engine={"max_concurrent": 0})

    def test_max_concurrent_too_high(self) -> None:
        with pytest.raises(ValidationError):
            AgentInjectConfig(engine={"max_concurrent": 51})

    def test_timeout_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            AgentInjectConfig(target={"timeout_seconds": 0})

    def test_threshold_bounds(self) -> None:
        with pytest.raises(ValidationError):
            AgentInjectConfig(scoring={"canary_match_threshold": 1.5})

    # --- Literal constraints ---

    def test_invalid_adapter_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AgentInjectConfig(target={"adapter": "invalid"})

    def test_invalid_output_format_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AgentInjectConfig(output={"format": "xml"})

    # --- URL validation ---

    def test_invalid_url_rejected(self) -> None:
        with pytest.raises(ValidationError, match="HTTP"):
            AgentInjectConfig(target={"url": "not-a-url"})

    def test_empty_url_allowed(self) -> None:
        cfg = AgentInjectConfig(target={"url": ""})
        assert cfg.target.url == ""

    def test_http_url_accepted(self) -> None:
        cfg = AgentInjectConfig(target={"url": "http://localhost:8000"})
        assert cfg.target.url == "http://localhost:8000"

    def test_https_url_accepted(self) -> None:
        cfg = AgentInjectConfig(target={"url": "https://agent.example.com/chat"})
        assert cfg.target.url == "https://agent.example.com/chat"

    def test_ftp_url_rejected(self) -> None:
        with pytest.raises(ValidationError, match="HTTP"):
            AgentInjectConfig(target={"url": "ftp://files.example.com"})

    # --- max_turns upper bound ---

    def test_max_turns_too_high(self) -> None:
        with pytest.raises(ValidationError):
            AgentInjectConfig(engine={"max_turns": 101})

    def test_max_turns_at_limit(self) -> None:
        cfg = AgentInjectConfig(engine={"max_turns": 100})
        assert cfg.engine.max_turns == 100

    # --- judge_model non-empty ---

    def test_judge_model_empty_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AgentInjectConfig(scoring={"judge_model": ""})

    # --- Cross-field: LLM judge requires API key ---

    def test_llm_judge_without_key_rejected(self) -> None:
        with pytest.raises(ValidationError, match="openai_api_key required"):
            AgentInjectConfig(scoring={"use_llm_judge": True})

    def test_llm_judge_with_key_accepted(self) -> None:
        cfg = AgentInjectConfig(
            scoring={"use_llm_judge": True},
            secrets={"openai_api_key": SecretStr("sk-test-key")},
        )
        assert cfg.scoring.use_llm_judge is True


class TestFrozen:
    """Config must be immutable after instantiation (CWE-426 hardening)."""

    def test_cannot_mutate_top_level(self) -> None:
        cfg = AgentInjectConfig()
        with pytest.raises(ValidationError):
            cfg.target = {"url": "https://evil.com"}  # type: ignore[assignment]

    def test_cannot_mutate_nested(self) -> None:
        cfg = AgentInjectConfig()
        with pytest.raises(ValidationError):
            cfg.target.url = "https://evil.com"


class TestEnvFileSecurity:
    """CWD .env files must NOT be loaded by default (CWE-426)."""

    def test_cwd_dotenv_not_loaded(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        dotenv = tmp_path / ".env"
        dotenv.write_text("AGENT_INJECT_TARGET__URL=https://evil.com\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("AGENT_INJECT_TARGET__URL", raising=False)
        cfg = AgentInjectConfig()
        assert cfg.target.url == ""

    def test_explicit_env_file_loaded(self, tmp_path: Path) -> None:
        dotenv = tmp_path / "custom.env"
        dotenv.write_text("AGENT_INJECT_TARGET__URL=https://explicit.com\n")
        cfg = AgentInjectConfig(_env_file=dotenv)  # pyright: ignore[reportCallIssue]
        assert cfg.target.url == "https://explicit.com"

    def test_env_vars_work_without_dotenv(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_INJECT_TARGET__URL", "https://env-var.com")
        cfg = AgentInjectConfig()
        assert cfg.target.url == "https://env-var.com"

    def test_env_prefix_isolation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TARGET__URL", "https://wrong-prefix.com")
        monkeypatch.delenv("AGENT_INJECT_TARGET__URL", raising=False)
        cfg = AgentInjectConfig()
        assert cfg.target.url == ""

    def test_repr_masks_secrets(self) -> None:
        cfg = AgentInjectConfig(secrets={"openai_api_key": SecretStr("sk-test-key-12345")})
        cfg_repr = repr(cfg)
        assert "sk-test-key-12345" not in cfg_repr

    def test_model_dump_masks_secrets(self) -> None:
        cfg = AgentInjectConfig(secrets={"openai_api_key": SecretStr("sk-test-key-12345")})
        dumped = cfg.model_dump()
        assert dumped["secrets"]["openai_api_key"] != "sk-test-key-12345"


class TestTomlConfig:
    """TOML config file loading via settings_customise_sources."""

    def test_toml_file_loaded(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        toml = tmp_path / "config.toml"
        toml.write_text("[engine]\nmax_concurrent = 42\n")
        monkeypatch.setattr("agent_inject.paths.config_file", lambda: toml)
        cfg = AgentInjectConfig()
        assert cfg.engine.max_concurrent == 42

    def test_toml_does_not_exist_is_fine(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("agent_inject.paths.config_file", lambda: tmp_path / "nonexistent.toml")
        cfg = AgentInjectConfig()
        assert cfg.engine.max_concurrent == 5

    def test_env_var_overrides_toml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        toml = tmp_path / "config.toml"
        toml.write_text("[engine]\nmax_concurrent = 42\n")
        monkeypatch.setattr("agent_inject.paths.config_file", lambda: toml)
        monkeypatch.setenv("AGENT_INJECT_ENGINE__MAX_CONCURRENT", "7")
        cfg = AgentInjectConfig()
        assert cfg.engine.max_concurrent == 7

    def test_constructor_overrides_toml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        toml = tmp_path / "config.toml"
        toml.write_text("[engine]\nmax_concurrent = 42\n")
        monkeypatch.setattr("agent_inject.paths.config_file", lambda: toml)
        cfg = AgentInjectConfig(engine={"max_concurrent": 3})
        assert cfg.engine.max_concurrent == 3

    def test_toml_invalid_value_rejected(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        toml = tmp_path / "config.toml"
        toml.write_text("[engine]\nmax_concurrent = 999\n")
        monkeypatch.setattr("agent_inject.paths.config_file", lambda: toml)
        with pytest.raises(ValidationError):
            AgentInjectConfig()

    def test_toml_override_via_set_toml_override(self, tmp_path: Path) -> None:
        from agent_inject.config import set_toml_override

        toml = tmp_path / "custom.toml"
        toml.write_text("[target]\ntimeout_seconds = 99.0\n")
        set_toml_override(toml)
        try:
            cfg = AgentInjectConfig()
            assert cfg.target.timeout_seconds == 99.0
        finally:
            set_toml_override(None)

    def test_toml_sections_map_to_nested(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        toml = tmp_path / "config.toml"
        toml.write_text('[target]\nurl = "https://toml.example.com"\n\n[scoring]\ncanary_match_threshold = 0.5\n')
        monkeypatch.setattr("agent_inject.paths.config_file", lambda: toml)
        cfg = AgentInjectConfig()
        assert cfg.target.url == "https://toml.example.com"
        assert cfg.scoring.canary_match_threshold == 0.5


class TestCwdDotenvWarning:
    """Tests for the CWD .env detection warning."""

    def test_warns_when_cwd_has_prefixed_dotenv(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        dotenv = tmp_path / ".env"
        dotenv.write_text("AGENT_INJECT_TARGET__URL=https://evil.com\n")
        monkeypatch.chdir(tmp_path)
        with caplog.at_level(logging.WARNING, logger="agent_inject.config"):
            warn_if_cwd_dotenv()
        assert "CWE-426" in caplog.text

    def test_no_warning_when_env_file_provided(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        dotenv = tmp_path / ".env"
        dotenv.write_text("AGENT_INJECT_TARGET__URL=https://evil.com\n")
        monkeypatch.chdir(tmp_path)
        with caplog.at_level(logging.WARNING, logger="agent_inject.config"):
            warn_if_cwd_dotenv(env_file_provided=True)
        assert caplog.text == ""

    def test_no_warning_when_no_dotenv(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.chdir(tmp_path)
        with caplog.at_level(logging.WARNING, logger="agent_inject.config"):
            warn_if_cwd_dotenv()
        assert caplog.text == ""

    def test_no_warning_when_no_prefixed_vars(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        dotenv = tmp_path / ".env"
        dotenv.write_text("OTHER_VAR=value\nANOTHER=123\n")
        monkeypatch.chdir(tmp_path)
        with caplog.at_level(logging.WARNING, logger="agent_inject.config"):
            warn_if_cwd_dotenv()
        assert caplog.text == ""

    def test_ignores_comments_in_dotenv(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        dotenv = tmp_path / ".env"
        dotenv.write_text("# AGENT_INJECT_TARGET__URL=https://commented.com\nOTHER=val\n")
        monkeypatch.chdir(tmp_path)
        with caplog.at_level(logging.WARNING, logger="agent_inject.config"):
            warn_if_cwd_dotenv()
        assert caplog.text == ""

    def test_no_warning_when_dotenv_unreadable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        dotenv = tmp_path / ".env"
        dotenv.write_text("AGENT_INJECT_TARGET__URL=https://evil.com\n")
        monkeypatch.chdir(tmp_path)
        original_read = Path.read_text

        def _raise_oserror(self: Path, *args: object, **kwargs: object) -> str:
            if self.name == ".env":
                raise OSError("Permission denied")
            return original_read(self, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(Path, "read_text", _raise_oserror)
        with caplog.at_level(logging.WARNING, logger="agent_inject.config"):
            warn_if_cwd_dotenv()
        assert caplog.text == ""
