# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Configuration management via pydantic-settings."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class AgentInjectConfig(BaseSettings):
    """Global configuration for agent-inject."""

    model_config = SettingsConfigDict(
        env_prefix="AGENT_INJECT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    target_url: str = ""
    target_adapter: str = "rest"
    max_concurrent: int = Field(default=5, ge=1, le=50)
    timeout_seconds: float = Field(default=30.0, gt=0)
    max_turns: int = Field(default=15, ge=1)
    output_dir: Path = Path("./results")
    output_format: str = "json"
    verbose: bool = False
    openai_api_key: SecretStr = SecretStr("")
    anthropic_api_key: SecretStr = SecretStr("")
    canary_match_threshold: float = Field(default=0.8, ge=0.0, le=1.0)
    use_llm_judge: bool = False
    judge_model: str = "gpt-4o-mini"
