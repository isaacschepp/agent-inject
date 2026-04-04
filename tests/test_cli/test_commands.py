# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Tests for CLI commands."""

from __future__ import annotations

import re
from typing import ClassVar
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from agent_inject import __version__
from agent_inject.attacks.base import FixedJailbreakAttack
from agent_inject.attacks.registry import _ATTACKS, register_attack
from agent_inject.cli import _create_adapter, _create_scorers, _json_default, app

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

    def test_config_file_not_found(self) -> None:
        result = runner.invoke(
            app,
            ["scan", "https://example.com", "--goal", "test", "--config", "/nonexistent/config.toml"],
        )
        assert result.exit_code == 1
        assert "config file not found" in _strip(result.stdout)

    def test_no_attacks_empty_registry(self) -> None:
        """Cover the 'no attacks registered' branch in _async_scan."""
        with patch("agent_inject.attacks.registry.get_all_attacks", return_value={}):
            result = runner.invoke(app, ["scan", "https://example.com", "--goal", "test"])
        assert result.exit_code == 0
        assert "No attacks" in _strip(result.stdout)

    def test_verbose_output(self) -> None:
        """Cover verbose console prints and Rich progress bar in _async_scan."""
        from agent_inject.engine import ScanProgress
        from agent_inject.models import (
            AttackResult,
            DeliveryVector,
            Payload,
            PayloadInstance,
            PayloadTier,
            TargetOutcome,
        )

        @register_attack
        class _VerboseTestAttack(FixedJailbreakAttack):
            name = "_verbose_test"
            _templates: ClassVar[list[str]] = ["test: {goal}"]

        mock_adapter = AsyncMock()
        mock_adapter.__aenter__ = AsyncMock(return_value=mock_adapter)
        mock_adapter.__aexit__ = AsyncMock(return_value=None)

        payload = Payload(
            id="t",
            template="t",
            tier=PayloadTier.CLASSIC,
            delivery_vectors=(DeliveryVector.DIRECT,),
            target_outcomes=(TargetOutcome.GOAL_HIJACKING,),
            source="test",
            year=2026,
        )
        instance = PayloadInstance(payload=payload, rendered="t", delivery_vector=DeliveryVector.DIRECT)
        attack_result = AttackResult(payload_instance=instance, raw_output="ok")

        from agent_inject.engine import ScanResult

        scan_result = ScanResult(
            results=(attack_result,),
            scores=((attack_result, ()),),
            total_payloads=1,
            successful_attacks=1,
            duration_seconds=0.1,
        )

        async def _fake_run_scan(*args: object, **kwargs: object) -> ScanResult:
            on_progress = kwargs.get("on_progress")
            if on_progress:
                on_progress(
                    ScanProgress(
                        result=attack_result,
                        scores=(),
                        index=0,
                        total=1,
                        elapsed_seconds=0.05,
                        successful_so_far=1,
                    )
                )
            return scan_result

        try:
            with (
                patch("agent_inject.cli._create_adapter", return_value=mock_adapter),
                patch("agent_inject.engine.run_scan", new=_fake_run_scan),
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
            assert "Timeout:" in out
            assert "Canary threshold:" in out
        finally:
            _ATTACKS.pop("_verbose_test", None)

    def test_env_var_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """AGENT_INJECT_MAX_CONCURRENT env var should flow through config."""

        @register_attack
        class _EnvTestAttack(FixedJailbreakAttack):
            name = "_env_test"
            _templates: ClassVar[list[str]] = ["test: {goal}"]

        mock_adapter = AsyncMock()
        mock_adapter.__aenter__ = AsyncMock(return_value=mock_adapter)
        mock_adapter.__aexit__ = AsyncMock(return_value=None)

        mock_result = AsyncMock()
        mock_result.successful_attacks = 0
        mock_result.total_payloads = 0
        mock_result.duration_seconds = 0.1

        monkeypatch.setenv("AGENT_INJECT_ENGINE__MAX_CONCURRENT", "42")

        try:
            with (
                patch("agent_inject.cli._create_adapter", return_value=mock_adapter),
                patch("agent_inject.engine.run_scan", new_callable=AsyncMock, return_value=mock_result) as mock_scan,
            ):
                result = runner.invoke(
                    app,
                    ["scan", "https://example.com", "--goal", "test", "--attack", "_env_test", "--verbose"],
                )
            out = _strip(result.stdout)
            # Env var should be reflected in verbose output
            assert "Concurrency: 42" in out
            # And passed to run_scan
            assert mock_scan.call_args.kwargs["max_concurrent"] == 42
        finally:
            _ATTACKS.pop("_env_test", None)

    def test_cli_flag_overrides_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """--concurrency CLI flag should override AGENT_INJECT_MAX_CONCURRENT env var."""
        from agent_inject.engine import ScanResult

        @register_attack
        class _OverrideTestAttack(FixedJailbreakAttack):
            name = "_override_test"
            _templates: ClassVar[list[str]] = ["test: {goal}"]

        mock_adapter = AsyncMock()
        mock_adapter.__aenter__ = AsyncMock(return_value=mock_adapter)
        mock_adapter.__aexit__ = AsyncMock(return_value=None)

        fake_result = ScanResult(results=(), scores=(), total_payloads=0, successful_attacks=0, duration_seconds=0.1)

        monkeypatch.setenv("AGENT_INJECT_ENGINE__MAX_CONCURRENT", "42")

        try:
            with (
                patch("agent_inject.cli._create_adapter", return_value=mock_adapter),
                patch("agent_inject.engine.run_scan", new_callable=AsyncMock, return_value=fake_result) as mock_scan,
            ):
                result = runner.invoke(
                    app,
                    [
                        "scan",
                        "https://example.com",
                        "--goal",
                        "test",
                        "--attack",
                        "_override_test",
                        "--concurrency",
                        "7",
                    ],
                )
            assert result.exit_code == 0
            # CLI flag (7) should win over env var (42)
            assert mock_scan.call_args.kwargs["max_concurrent"] == 7
        finally:
            _ATTACKS.pop("_override_test", None)

    def test_timeout_flag_flows_to_config(self) -> None:
        """--timeout CLI flag should set config.timeout_seconds."""
        from agent_inject.engine import ScanResult

        @register_attack
        class _TimeoutTestAttack(FixedJailbreakAttack):
            name = "_timeout_test"
            _templates: ClassVar[list[str]] = ["test: {goal}"]

        mock_adapter = AsyncMock()
        mock_adapter.__aenter__ = AsyncMock(return_value=mock_adapter)
        mock_adapter.__aexit__ = AsyncMock(return_value=None)

        fake_result = ScanResult(results=(), scores=(), total_payloads=0, successful_attacks=0, duration_seconds=0.1)

        try:
            with (
                patch("agent_inject.cli._create_adapter", return_value=mock_adapter) as mock_factory,
                patch("agent_inject.engine.run_scan", new_callable=AsyncMock, return_value=fake_result),
            ):
                result = runner.invoke(
                    app,
                    [
                        "scan",
                        "https://example.com",
                        "--goal",
                        "test",
                        "--attack",
                        "_timeout_test",
                        "--timeout",
                        "60.0",
                    ],
                )
            assert result.exit_code == 0
            # Verify config passed to _create_adapter has the custom timeout
            passed_config = mock_factory.call_args.args[0]
            assert passed_config.target.timeout_seconds == 60.0
        finally:
            _ATTACKS.pop("_timeout_test", None)


class TestFactories:
    def test_create_adapter_rest(self) -> None:
        from agent_inject.config import AgentInjectConfig
        from agent_inject.harness.adapters.rest import RestAdapter

        config = AgentInjectConfig(target={"url": "https://example.com", "timeout_seconds": 60.0})
        adapter = _create_adapter(config)
        assert isinstance(adapter, RestAdapter)
        assert adapter.timeout == 60.0

    def test_create_adapter_unknown_rejected_at_config(self) -> None:
        from pydantic import ValidationError

        from agent_inject.config import AgentInjectConfig

        with pytest.raises(ValidationError):
            AgentInjectConfig(target={"adapter": "unknown"})

    def test_create_scorers_with_judge_enabled(self) -> None:
        from pydantic import SecretStr

        from agent_inject.config import AgentInjectConfig
        from agent_inject.scorers.llm_judge import LlmJudgeScorer

        config = AgentInjectConfig(
            scoring={"judge": {"enabled": True, "model": "openai:gpt-4o-mini"}},
            secrets={"openai_api_key": SecretStr("sk-test")},
        )
        scorers = _create_scorers(config)
        judge_scorers = [s for s in scorers if isinstance(s, LlmJudgeScorer)]
        assert len(judge_scorers) == 1

    def test_create_scorers_uses_config_threshold(self) -> None:
        from agent_inject.config import AgentInjectConfig
        from agent_inject.scorers.base import CanaryMatchScorer

        config = AgentInjectConfig(scoring={"canary_match_threshold": 0.6})
        scorers = _create_scorers(config)
        canary_scorer = next(s for s in scorers if isinstance(s, CanaryMatchScorer))
        assert canary_scorer.threshold == 0.6


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


class TestConfigSchema:
    def test_outputs_valid_json(self) -> None:
        import json

        result = runner.invoke(app, ["config-schema"], color=False)
        assert result.exit_code == 0
        schema = json.loads(result.stdout)
        assert "properties" in schema
        assert "target" in schema["properties"]


class TestVersion:
    def test_output(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert __version__ in _strip(result.stdout)


class TestJsonDefault:
    """Tests for _json_default serialization helper (#513)."""

    def test_mapping_proxy_serialized_as_dict(self) -> None:
        import json
        import types

        proxy = types.MappingProxyType({"key": "value"})
        result = json.dumps({"data": proxy}, default=_json_default)
        parsed = json.loads(result)
        assert parsed["data"] == {"key": "value"}

    def test_non_proxy_falls_back_to_str(self) -> None:
        assert _json_default(42) == "42"

    def test_full_scan_result_serializes(self) -> None:
        """Verify the real CLI serialization path works with MappingProxyType fields."""
        import dataclasses
        import json

        from agent_inject.models import (
            AttackResult,
            DeliveryVector,
            Payload,
            PayloadInstance,
            PayloadTier,
            Score,
            TargetOutcome,
        )

        payload = Payload(
            id="test",
            template="t",
            tier=PayloadTier.CLASSIC,
            delivery_vectors=(DeliveryVector.DIRECT,),
            target_outcomes=(TargetOutcome.GOAL_HIJACKING,),
            source="test",
            year=2026,
        )
        instance = PayloadInstance(payload=payload, rendered="t", delivery_vector=DeliveryVector.DIRECT)
        result = AttackResult(
            payload_instance=instance,
            environment_diff={"admin": True},
            scorer_details={"method": "heuristic"},
        )
        score = Score(scorer_name="test", passed=True, value=1.0, details={"confidence": 0.95})

        from agent_inject.engine import ScanResult

        scan = ScanResult(
            results=(result,),
            scores=((result, (score,)),),
            total_payloads=1,
            successful_attacks=1,
            duration_seconds=1.0,
        )
        # This is the exact pattern from cli.py:150
        serialized = json.dumps(dataclasses.asdict(scan), indent=2, default=_json_default)
        parsed = json.loads(serialized)
        assert parsed["results"][0]["environment_diff"] == {"admin": True}
        assert parsed["results"][0]["scorer_details"] == {"method": "heuristic"}
        assert parsed["scores"][0][1][0]["details"] == {"confidence": 0.95}
