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
        # TargetConfig
        assert cfg.target.url == ""
        assert cfg.target.adapter == "rest"
        assert cfg.target.timeout_seconds == 30.0
        assert cfg.target.message_field == "message"
        assert cfg.target.response_field == "response"
        assert cfg.target.headers == {}
        # EngineConfig
        assert cfg.engine.max_concurrent == 5
        assert cfg.engine.max_turns == 15
        assert cfg.engine.max_backtracks == 5
        assert cfg.engine.max_retries == 3
        assert cfg.engine.retry_backoff_seconds == 2.0
        # OutputConfig
        assert cfg.output.dir == Path("./results")
        assert cfg.output.format == "json"
        assert cfg.output.verbose is False
        assert cfg.output.log_level == "WARNING"
        # SecretsConfig
        assert cfg.secrets.openai_api_key.get_secret_value() == ""
        assert cfg.secrets.anthropic_api_key.get_secret_value() == ""
        # ScoringConfig
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


class TestNewFieldValidation:
    """Validation for fields added in #472."""

    # --- max_backtracks ---

    def test_max_backtracks_negative_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AgentInjectConfig(engine={"max_backtracks": -1})

    def test_max_backtracks_too_high_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AgentInjectConfig(engine={"max_backtracks": 101})

    def test_max_backtracks_at_zero_accepted(self) -> None:
        cfg = AgentInjectConfig(engine={"max_backtracks": 0})
        assert cfg.engine.max_backtracks == 0

    def test_max_backtracks_at_limit_accepted(self) -> None:
        cfg = AgentInjectConfig(engine={"max_backtracks": 100})
        assert cfg.engine.max_backtracks == 100

    # --- max_retries ---

    def test_max_retries_negative_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AgentInjectConfig(engine={"max_retries": -1})

    def test_max_retries_too_high_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AgentInjectConfig(engine={"max_retries": 11})

    def test_max_retries_at_zero_accepted(self) -> None:
        cfg = AgentInjectConfig(engine={"max_retries": 0})
        assert cfg.engine.max_retries == 0

    # --- retry_backoff_seconds ---

    def test_retry_backoff_negative_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AgentInjectConfig(engine={"retry_backoff_seconds": -1.0})

    def test_retry_backoff_zero_accepted(self) -> None:
        cfg = AgentInjectConfig(engine={"retry_backoff_seconds": 0.0})
        assert cfg.engine.retry_backoff_seconds == 0.0

    # --- log_level ---

    def test_log_level_invalid_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AgentInjectConfig(output={"log_level": "TRACE"})

    def test_log_level_all_valid_values(self) -> None:
        for level in ("DEBUG", "INFO", "WARNING", "ERROR"):
            cfg = AgentInjectConfig(output={"log_level": level})
            assert cfg.output.log_level == level


class TestBoundaryValues:
    """Min/max valid values for all constrained fields."""

    def test_max_concurrent_min_valid(self) -> None:
        cfg = AgentInjectConfig(engine={"max_concurrent": 1})
        assert cfg.engine.max_concurrent == 1

    def test_max_concurrent_max_valid(self) -> None:
        cfg = AgentInjectConfig(engine={"max_concurrent": 50})
        assert cfg.engine.max_concurrent == 50

    def test_timeout_very_small(self) -> None:
        cfg = AgentInjectConfig(target={"timeout_seconds": 0.001})
        assert cfg.target.timeout_seconds == 0.001

    def test_threshold_zero_valid(self) -> None:
        cfg = AgentInjectConfig(scoring={"canary_match_threshold": 0.0})
        assert cfg.scoring.canary_match_threshold == 0.0

    def test_threshold_one_valid(self) -> None:
        cfg = AgentInjectConfig(scoring={"canary_match_threshold": 1.0})
        assert cfg.scoring.canary_match_threshold == 1.0

    def test_max_turns_at_one(self) -> None:
        cfg = AgentInjectConfig(engine={"max_turns": 1})
        assert cfg.engine.max_turns == 1


class TestEnvOverrideExpanded:
    """Env override tests for fields not yet covered."""

    def test_timeout_seconds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_INJECT_TARGET__TIMEOUT_SECONDS", "60.0")
        cfg = AgentInjectConfig()
        assert cfg.target.timeout_seconds == 60.0

    def test_message_field(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_INJECT_TARGET__MESSAGE_FIELD", "prompt")
        cfg = AgentInjectConfig()
        assert cfg.target.message_field == "prompt"

    def test_response_field(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_INJECT_TARGET__RESPONSE_FIELD", "output")
        cfg = AgentInjectConfig()
        assert cfg.target.response_field == "output"

    def test_max_backtracks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_INJECT_ENGINE__MAX_BACKTRACKS", "10")
        cfg = AgentInjectConfig()
        assert cfg.engine.max_backtracks == 10

    def test_max_retries(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_INJECT_ENGINE__MAX_RETRIES", "5")
        cfg = AgentInjectConfig()
        assert cfg.engine.max_retries == 5

    def test_retry_backoff_seconds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_INJECT_ENGINE__RETRY_BACKOFF_SECONDS", "0.5")
        cfg = AgentInjectConfig()
        assert cfg.engine.retry_backoff_seconds == 0.5

    def test_log_level(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_INJECT_OUTPUT__LOG_LEVEL", "DEBUG")
        cfg = AgentInjectConfig()
        assert cfg.output.log_level == "DEBUG"

    def test_canary_threshold(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_INJECT_SCORING__CANARY_MATCH_THRESHOLD", "0.5")
        cfg = AgentInjectConfig()
        assert cfg.scoring.canary_match_threshold == 0.5

    def test_openai_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_INJECT_SECRETS__OPENAI_API_KEY", "sk-from-env")
        cfg = AgentInjectConfig()
        assert cfg.secrets.openai_api_key.get_secret_value() == "sk-from-env"


class TestBooleanParsing:
    """Pydantic boolean env var parsing variants."""

    @pytest.mark.parametrize("value", ["true", "True", "TRUE", "1", "yes", "on"])
    def test_truthy_variants(self, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
        monkeypatch.setenv("AGENT_INJECT_OUTPUT__VERBOSE", value)
        cfg = AgentInjectConfig()
        assert cfg.output.verbose is True

    @pytest.mark.parametrize("value", ["false", "False", "FALSE", "0", "no", "off"])
    def test_falsy_variants(self, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
        monkeypatch.setenv("AGENT_INJECT_OUTPUT__VERBOSE", value)
        cfg = AgentInjectConfig()
        assert cfg.output.verbose is False


class TestSerialization:
    """Config serialization and schema export."""

    def test_model_dump_all_submodels_present(self) -> None:
        cfg = AgentInjectConfig()
        dumped = cfg.model_dump()
        assert set(dumped.keys()) == {"target", "engine", "output", "secrets", "scoring"}

    def test_model_dump_json_mode(self) -> None:
        cfg = AgentInjectConfig()
        dumped = cfg.model_dump(mode="json")
        # Path should be serialized to string in JSON mode
        assert isinstance(dumped["output"]["dir"], str)

    def test_json_schema_export(self) -> None:
        import warnings

        # Path default triggers PydanticJsonSchemaWarning; suppress for this test
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            schema = AgentInjectConfig.model_json_schema()
        assert "properties" in schema
        assert "target" in schema["properties"]
        assert "engine" in schema["properties"]

    def test_path_serialization(self) -> None:
        cfg = AgentInjectConfig()
        dumped = cfg.model_dump(mode="json")
        # Path("./results") serializes to "results" in JSON mode
        assert isinstance(dumped["output"]["dir"], str)

    def test_secrets_masked_in_json_mode(self) -> None:
        cfg = AgentInjectConfig(secrets={"openai_api_key": SecretStr("sk-secret-123")})
        dumped = cfg.model_dump(mode="json")
        assert "sk-secret-123" not in str(dumped)


class TestFullPriorityChain:
    """Verify full config source priority: constructor > env > TOML > defaults."""

    def test_constructor_beats_env_beats_toml(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        toml = tmp_path / "config.toml"
        toml.write_text("[engine]\nmax_concurrent = 42\nmax_turns = 80\nmax_backtracks = 20\n")
        monkeypatch.setattr("agent_inject.paths.config_file", lambda: toml)
        monkeypatch.setenv("AGENT_INJECT_ENGINE__MAX_TURNS", "50")

        cfg = AgentInjectConfig(engine={"max_concurrent": 3})

        # constructor (3) beats TOML (42)
        assert cfg.engine.max_concurrent == 3
        # env (50) beats TOML (80)
        assert cfg.engine.max_turns == 50
        # TOML (20) beats default (5)
        assert cfg.engine.max_backtracks == 20
        # default (3) when nothing overrides
        assert cfg.engine.max_retries == 3


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
