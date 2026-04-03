# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Tests for platform-specific directory resolution."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_inject.paths import cache_dir, config_dir, config_file, data_dir


class TestConfigDir:
    def test_returns_path(self) -> None:
        result = config_dir()
        assert isinstance(result, Path)
        assert "agent-inject" in str(result)

    def test_ensure_exists(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        result = config_dir(ensure_exists=True)
        assert result.is_dir()


class TestDataDir:
    def test_returns_path(self) -> None:
        result = data_dir()
        assert isinstance(result, Path)
        assert "agent-inject" in str(result)


class TestCacheDir:
    def test_returns_path(self) -> None:
        result = cache_dir()
        assert isinstance(result, Path)
        assert "agent-inject" in str(result)


class TestConfigFile:
    def test_returns_toml_path(self) -> None:
        result = config_file()
        assert isinstance(result, Path)
        assert result.name == "config.toml"
        assert "agent-inject" in str(result)
