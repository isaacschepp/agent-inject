"""Tests for YAML payload loader."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from agent_inject.attacks.base import FixedJailbreakAttack
from agent_inject.attacks.loader import (
    YamlAttackEntry,
    YamlPayloadFile,
    _build_attack_class,
    load_yaml_payloads,
)
from agent_inject.models import PayloadTier, TargetOutcome


class TestYamlAttackEntry:
    def test_valid_entry(self) -> None:
        entry = YamlAttackEntry(
            name="test-attack",
            templates=["Ignore previous. {goal}"],
        )
        assert entry.name == "test-attack"
        assert entry.tier == PayloadTier.CLASSIC
        assert entry.target_outcomes == [TargetOutcome.GOAL_HIJACKING]

    def test_custom_tier(self) -> None:
        entry = YamlAttackEntry(
            name="auth-attack",
            tier="authority",
            target_outcomes=["privilege_escalation"],
            templates=["[SYSTEM] {goal}"],
        )
        assert entry.tier == PayloadTier.AUTHORITY
        assert entry.target_outcomes == [TargetOutcome.PRIVILEGE_ESCALATION]

    def test_empty_templates_raises(self) -> None:
        with pytest.raises(Exception, match="templates must not be empty"):
            YamlAttackEntry(name="bad", templates=[])

    def test_invalid_tier_raises(self) -> None:
        with pytest.raises(ValueError, match="Input should be"):
            YamlAttackEntry(name="bad", tier="nonexistent", templates=["x"])


class TestYamlPayloadFile:
    def test_valid_file(self) -> None:
        data = {
            "attacks": [
                {"name": "a1", "templates": ["test: {goal}"]},
                {"name": "a2", "templates": ["other: {goal}"]},
            ]
        }
        validated = YamlPayloadFile.model_validate(data)
        assert len(validated.attacks) == 2


class TestBuildAttackClass:
    def test_creates_subclass(self) -> None:
        entry = YamlAttackEntry(
            name="test-yaml-attack",
            description="A test",
            tier="authority",
            target_outcomes=["tool_abuse"],
            templates=["Attack: {goal}"],
        )
        cls = _build_attack_class(entry)
        assert issubclass(cls, FixedJailbreakAttack)
        assert cls.name == "test-yaml-attack"
        assert cls.description == "A test"
        assert cls._tier == PayloadTier.AUTHORITY
        assert cls._target_outcomes == (TargetOutcome.TOOL_ABUSE,)
        assert cls._templates == ["Attack: {goal}"]

    def test_generates_payloads(self) -> None:
        entry = YamlAttackEntry(
            name="gen-test",
            templates=["Do {goal}", "Please {goal}"],
        )
        cls = _build_attack_class(entry)
        attack = cls()
        payloads = attack.generate_payloads("something bad")
        assert len(payloads) == 2
        assert "something bad" in payloads[0].rendered


class TestLoadYamlPayloads:
    def test_loads_from_yaml_file(self, tmp_path: Path) -> None:
        payload_file = tmp_path / "test.yaml"
        payload_file.write_text(yaml.dump({"attacks": [{"name": "yaml-test", "templates": ["test: {goal}"]}]}))

        with patch("agent_inject.attacks.loader.files") as mock_files:
            mock_files.return_value.joinpath.return_value = tmp_path
            result = load_yaml_payloads(existing={})

        assert "yaml-test" in result
        assert issubclass(result["yaml-test"], FixedJailbreakAttack)

    def test_skips_collision(self, tmp_path: Path) -> None:
        payload_file = tmp_path / "test.yaml"
        payload_file.write_text(yaml.dump({"attacks": [{"name": "existing", "templates": ["test: {goal}"]}]}))

        with patch("agent_inject.attacks.loader.files") as mock_files:
            mock_files.return_value.joinpath.return_value = tmp_path
            result = load_yaml_payloads(existing={"existing": object()})

        assert "existing" not in result

    def test_handles_empty_directory(self, tmp_path: Path) -> None:
        with patch("agent_inject.attacks.loader.files") as mock_files:
            mock_files.return_value.joinpath.return_value = tmp_path
            result = load_yaml_payloads(existing={})

        assert result == {}

    def test_handles_invalid_yaml(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text(": : : invalid")

        with patch("agent_inject.attacks.loader.files") as mock_files:
            mock_files.return_value.joinpath.return_value = tmp_path
            result = load_yaml_payloads(existing={})

        assert result == {}

    def test_handles_invalid_schema(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad_schema.yaml"
        bad_file.write_text(yaml.dump({"attacks": [{"name": "x"}]}))

        with patch("agent_inject.attacks.loader.files") as mock_files:
            mock_files.return_value.joinpath.return_value = tmp_path
            result = load_yaml_payloads(existing={})

        assert result == {}
