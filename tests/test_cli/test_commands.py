# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Tests for CLI commands."""

from __future__ import annotations

import re
from typing import ClassVar
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from agent_inject import __version__
from agent_inject.attacks.base import FixedJailbreakAttack
from agent_inject.attacks.registry import _ATTACKS, register_attack
from agent_inject.cli import app

runner = CliRunner()

# Strip ANSI escape sequences from Rich output for assertions
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip(text: str) -> str:
    return _ANSI_RE.sub("", text)


class TestScan:
    def test_missing_goal_fails(self) -> None:
        result = runner.invoke(app, ["scan", "https://example.com"])
        assert result.exit_code != 0

    def test_unknown_attack_fails(self) -> None:
        result = runner.invoke(app, ["scan", "https://example.com", "--goal", "test", "--attack", "nonexistent_xyz"])
        assert result.exit_code != 0
        assert "Error" in _strip(result.stdout) or result.exit_code == 1

    def test_no_attacks_registered(self) -> None:
        result = runner.invoke(app, ["scan", "https://example.com", "--goal", "test"])
        out = _strip(result.stdout)
        # With no attacks registered and no YAML payloads, should show message
        assert result.exit_code == 0
        assert "No attacks" in out or "Scan complete" in out

    def test_env_file_not_found(self) -> None:
        result = runner.invoke(
            app,
            ["scan", "https://example.com", "--goal", "test", "--env-file", "/nonexistent/.env"],
        )
        assert result.exit_code == 1
        assert "env file not found" in _strip(result.stdout)

    def test_no_attacks_empty_registry(self) -> None:
        """Cover the 'no attacks registered' branch in _async_scan."""
        with patch("agent_inject.attacks.registry.get_all_attacks", return_value={}):
            result = runner.invoke(app, ["scan", "https://example.com", "--goal", "test"])
        assert result.exit_code == 0
        assert "No attacks" in _strip(result.stdout)

    def test_verbose_output(self) -> None:
        """Cover verbose console prints in _async_scan."""

        @register_attack
        class _VerboseTestAttack(FixedJailbreakAttack):
            name = "_verbose_test"
            _templates: ClassVar[list[str]] = ["test: {goal}"]

        mock_adapter = AsyncMock()
        mock_adapter.__aenter__ = AsyncMock(return_value=mock_adapter)
        mock_adapter.__aexit__ = AsyncMock(return_value=None)

        mock_result = AsyncMock()
        mock_result.successful_attacks = 0
        mock_result.total_payloads = 0
        mock_result.duration_seconds = 0.1

        try:
            with (
                patch("agent_inject.harness.adapters.rest.RestAdapter", return_value=mock_adapter),
                patch("agent_inject.engine.run_scan", new_callable=AsyncMock, return_value=mock_result),
            ):
                result = runner.invoke(
                    app,
                    [
                        "scan",
                        "https://example.com",
                        "--goal",
                        "test",
                        "--attack",
                        "_verbose_test",
                        "--verbose",
                    ],
                )
            out = _strip(result.stdout)
            assert "Target: https://example.com" in out
            assert "Goal: test" in out
            assert "Concurrency:" in out
        finally:
            _ATTACKS.pop("_verbose_test", None)


class TestListAttacks:
    def test_empty(self) -> None:
        result = runner.invoke(app, ["list-attacks"])
        assert result.exit_code == 0

    def test_with_registered(self) -> None:
        @register_attack
        class _CLITestAttack(FixedJailbreakAttack):
            """A test attack for CLI."""

            name = "_cli_test_attack"
            _templates: ClassVar[list[str]] = ["test: {goal}"]

        try:
            result = runner.invoke(app, ["list-attacks"])
            assert result.exit_code == 0
            assert "_cli_test_attack" in _strip(result.stdout)
        finally:
            del _ATTACKS["_cli_test_attack"]

    def test_no_attacks_registered(self) -> None:
        """Cover the empty branch in list_attacks."""
        with patch("agent_inject.attacks.registry.get_all_attacks", return_value={}):
            result = runner.invoke(app, ["list-attacks"])
        assert result.exit_code == 0
        assert "No attacks" in _strip(result.stdout)


class TestListAdapters:
    def test_output(self) -> None:
        result = runner.invoke(app, ["list-adapters"])
        assert result.exit_code == 0
        assert "rest" in _strip(result.stdout)


class TestVersion:
    def test_output(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert __version__ in _strip(result.stdout)
