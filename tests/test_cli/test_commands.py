"""Tests for CLI commands."""

from __future__ import annotations

import re
from typing import ClassVar

from typer.testing import CliRunner

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


class TestListAdapters:
    def test_output(self) -> None:
        result = runner.invoke(app, ["list-adapters"])
        assert result.exit_code == 0
        assert "No adapters registered" in _strip(result.stdout)


class TestVersion:
    def test_output(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "0.1.1" in _strip(result.stdout)
