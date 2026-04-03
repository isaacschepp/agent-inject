# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Configuration management via pydantic-settings.

Security: CWD ``.env`` files are **not** loaded by default (CWE-426).
Pass an explicit path via ``_env_file`` or the CLI ``--env-file`` flag.
See https://github.com/isaacschepp/agent-inject/issues/466
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal, Self, override

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict, TomlConfigSettingsSource

_logger = logging.getLogger(__name__)

_ENV_PREFIX = "AGENT_INJECT_"

# Module-level override for the TOML config file path.
# Set via ``set_toml_override()`` before constructing ``AgentInjectConfig``.
_toml_override: Path | None = None


def set_toml_override(path: Path | None) -> None:
    """Override the default TOML config file path (``--config`` flag)."""
    global _toml_override
    _toml_override = path


# ---------------------------------------------------------------------------
# Nested sub-models (BaseModel, NOT BaseSettings)
# ---------------------------------------------------------------------------


class TargetConfig(BaseModel, frozen=True):
    """Target agent connection settings."""

    url: str = ""
    adapter: Literal["rest"] = "rest"
    timeout_seconds: float = Field(default=30.0, gt=0)
    message_field: str = "message"
    response_field: str = "response"
    headers: dict[str, str] = Field(default_factory=dict)

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        if v and not v.startswith(("http://", "https://")):
            msg = f"target url must be an HTTP(S) URL, got {v!r}"
            raise ValueError(msg)
        return v


class EngineConfig(BaseModel, frozen=True):
    """Scan engine behaviour."""

    max_concurrent: int = Field(default=5, ge=1, le=50)
    max_turns: int = Field(default=15, ge=1, le=100)
    max_backtracks: int = Field(default=5, ge=0, le=100)
    max_retries: int = Field(default=3, ge=0, le=10)
    retry_backoff_seconds: float = Field(default=2.0, ge=0.0)


class OutputConfig(BaseModel, frozen=True):
    """Output and logging settings."""

    dir: Path = Path("./results")
    format: Literal["json"] = "json"
    verbose: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "WARNING"


class SecretsConfig(BaseModel, frozen=True):
    """API keys and sensitive credentials."""

    openai_api_key: SecretStr = SecretStr("")
    anthropic_api_key: SecretStr = SecretStr("")


class JudgeConfig(BaseModel, frozen=True):
    """LLM-as-judge configuration.

    Uses ``provider:model`` format (e.g. ``openai:gpt-4o-mini``,
    ``anthropic:claude-3-haiku-20240307``).
    """

    enabled: bool = False
    model: str = Field(default="openai:gpt-4o-mini", min_length=1)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    max_tokens: int = Field(default=1024, ge=1)


class ScoringConfig(BaseModel, frozen=True):
    """Scoring and evaluation settings."""

    canary_match_threshold: float = Field(default=0.8, ge=0.0, le=1.0)
    judge: JudgeConfig = JudgeConfig()


# ---------------------------------------------------------------------------
# Top-level config
# ---------------------------------------------------------------------------


class AgentInjectConfig(BaseSettings):
    """Global configuration for agent-inject.

    Configuration sources (highest to lowest priority):
      1. Constructor arguments / CLI overrides
      2. Environment variables (``AGENT_INJECT_`` prefix, ``__`` nested delimiter)
      3. Explicitly specified env file (``--env-file``)
      4. TOML config file (``~/.config/agent-inject/config.toml`` or ``--config``)
      5. Field defaults

    CWD files (``.env``, ``agent-inject.toml``) are never loaded automatically.

    Env var examples::

        AGENT_INJECT_TARGET__URL=https://example.com
        AGENT_INJECT_ENGINE__MAX_CONCURRENT=10
        AGENT_INJECT_SCORING__JUDGE__ENABLED=true
    """

    model_config = SettingsConfigDict(
        env_prefix=_ENV_PREFIX,
        env_nested_delimiter="__",
        nested_model_default_partial_update=True,
        env_file=None,
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    target: TargetConfig = TargetConfig()
    engine: EngineConfig = EngineConfig()
    output: OutputConfig = OutputConfig()
    secrets: SecretsConfig = SecretsConfig()
    scoring: ScoringConfig = ScoringConfig()

    @classmethod
    @override
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Define config source priority: init > env > dotenv > TOML > defaults."""
        from agent_inject.paths import config_file

        sources: list[PydanticBaseSettingsSource] = [
            init_settings,  # 1. CLI args / constructor kwargs
            env_settings,  # 2. AGENT_INJECT_* env vars
            dotenv_settings,  # 3. Explicit .env file (--env-file)
        ]

        toml_path = _toml_override or config_file()
        if toml_path.is_file():
            sources.append(TomlConfigSettingsSource(settings_cls, toml_file=toml_path))

        return tuple(sources)

    @model_validator(mode="after")
    def _require_api_key_for_judge(self) -> Self:
        judge = self.scoring.judge
        if not judge.enabled:
            return self
        provider = judge.model.split(":")[0] if ":" in judge.model else "openai"
        if provider == "openai" and not self.secrets.openai_api_key.get_secret_value():
            msg = "openai_api_key required for OpenAI judge. Set AGENT_INJECT_SECRETS__OPENAI_API_KEY."
            raise ValueError(msg)
        if provider == "anthropic" and not self.secrets.anthropic_api_key.get_secret_value():
            msg = "anthropic_api_key required for Anthropic judge. Set AGENT_INJECT_SECRETS__ANTHROPIC_API_KEY."
            raise ValueError(msg)
        return self


def _known_env_vars() -> set[str]:
    """Build the set of valid ``AGENT_INJECT_*`` env var names from model fields."""
    known: set[str] = set()
    for top_name, top_info in AgentInjectConfig.model_fields.items():
        sub_type = top_info.annotation
        # All top-level fields are BaseModel sub-models with model_fields.
        for sub_name in sub_type.model_fields:  # type: ignore[union-attr]
            known.add(f"{_ENV_PREFIX}{top_name.upper()}__{sub_name.upper()}")
    return known


def warn_unknown_env_vars() -> None:
    """Warn about ``AGENT_INJECT_*`` env vars that don't match any config field.

    Helps catch typos like ``AGENT_INJECT_TARET__URL`` (should be ``TARGET``).
    """
    import os
    from difflib import get_close_matches

    known = _known_env_vars()
    for key in os.environ:
        if not key.startswith(_ENV_PREFIX):
            continue
        if key in known:
            continue
        suggestions = get_close_matches(key, sorted(known), n=1, cutoff=0.6)
        hint = f" Did you mean {suggestions[0]!r}?" if suggestions else ""
        _logger.warning("Unknown env var %r with prefix %r.%s", key, _ENV_PREFIX, hint)


def warn_if_cwd_dotenv(*, env_file_provided: bool = False) -> None:
    """Emit a warning if CWD contains a ``.env`` with ``AGENT_INJECT_*`` vars.

    Helps users discover the secure-default change without silent breakage.
    Skipped when the caller already passed ``--env-file``.
    """
    if env_file_provided:
        return

    dotenv_path = Path.cwd() / ".env"
    if not dotenv_path.is_file():
        return

    try:
        text = dotenv_path.read_text(encoding="utf-8-sig")
    except OSError:
        return

    has_prefixed = any(
        line.strip().startswith(_ENV_PREFIX)
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )
    if has_prefixed:
        _logger.warning(
            "Found .env in current directory with %s* variables. "
            "CWD .env files are not loaded by default (security: CWE-426). "
            "To use it: agent-inject scan --env-file .env ...",
            _ENV_PREFIX,
        )
