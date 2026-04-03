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

from pydantic import Field, SecretStr, field_validator, model_validator
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


class AgentInjectConfig(BaseSettings):
    """Global configuration for agent-inject.

    Configuration sources (highest to lowest priority):
      1. Constructor arguments / CLI overrides
      2. Environment variables (``AGENT_INJECT_`` prefix)
      3. Explicitly specified env file (``--env-file``)
      4. TOML config file (``~/.config/agent-inject/config.toml`` or ``--config``)
      5. Field defaults

    CWD files (``.env``, ``agent-inject.toml``) are never loaded automatically.
    """

    model_config = SettingsConfigDict(
        env_prefix=_ENV_PREFIX,
        env_file=None,
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

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

    target_url: str = ""
    target_adapter: Literal["rest"] = "rest"
    max_concurrent: int = Field(default=5, ge=1, le=50)
    timeout_seconds: float = Field(default=30.0, gt=0)
    max_turns: int = Field(default=15, ge=1, le=100)
    output_dir: Path = Path("./results")
    output_format: Literal["json"] = "json"
    verbose: bool = False
    openai_api_key: SecretStr = SecretStr("")
    anthropic_api_key: SecretStr = SecretStr("")
    canary_match_threshold: float = Field(default=0.8, ge=0.0, le=1.0)
    use_llm_judge: bool = False
    judge_model: str = Field(default="gpt-4o-mini", min_length=1)

    @field_validator("target_url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        if v and not v.startswith(("http://", "https://")):
            msg = f"target_url must be an HTTP(S) URL, got {v!r}"
            raise ValueError(msg)
        return v

    @model_validator(mode="after")
    def _require_api_key_for_judge(self) -> Self:
        if self.use_llm_judge and not self.openai_api_key.get_secret_value():
            msg = (
                "openai_api_key required when use_llm_judge=True. "
                "Set AGENT_INJECT_OPENAI_API_KEY or pass --openai-api-key."
            )
            raise ValueError(msg)
        return self


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
