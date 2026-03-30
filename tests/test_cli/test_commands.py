"""Tests for CLI commands."""

from __future__ import annotations

from typing import ClassVar

from typer.testing import CliRunner

from agent_inject.attacks.base import FixedJailbreakAttack
from agent_inject.attacks.registry import _ATTACKS, register_attack
from agent_inject.cli import app

runner = CliRunner()


class TestScan:
    def test_basic(self) -> None:
        result = runner.invoke(app, ["scan", "https://example.com"])
        assert result.exit_code == 0
        assert "Target: https://example.com" in result.stdout
        assert "Attacks: all" in result.stdout

    def test_with_attacks(self) -> None:
        result = runner.invoke(app, ["scan", "https://x.com", "--attack", "direct"])
        assert result.exit_code == 0
        assert "direct" in result.stdout

    def test_with_config(self) -> None:
        result = runner.invoke(app, ["scan", "https://x.com", "--config", "test.yaml"])
        assert result.exit_code == 0
        assert "Config: test.yaml" in result.stdout

    def test_verbose(self) -> None:
        result = runner.invoke(app, ["scan", "https://x.com", "--verbose"])
        assert result.exit_code == 0
        assert "Verbose mode enabled" in result.stdout

    def test_output_shown(self) -> None:
        result = runner.invoke(app, ["scan", "https://x.com", "--output", "out.json"])
        assert result.exit_code == 0
        assert "Output: out.json" in result.stdout


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
            assert "_cli_test_attack" in result.stdout
        finally:
            del _ATTACKS["_cli_test_attack"]


class TestListAdapters:
    def test_output(self) -> None:
        result = runner.invoke(app, ["list-adapters"])
        assert result.exit_code == 0
        assert "No adapters registered" in result.stdout


class TestVersion:
    def test_output(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "agent-inject 0.1.0" in result.stdout
