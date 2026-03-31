"""YAML payload loader for data-driven attacks."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from importlib.resources import files
from importlib.resources.abc import Traversable
from typing import Any

import yaml
from pydantic import BaseModel, ValidationError, field_validator

from agent_inject.attacks.base import FixedJailbreakAttack
from agent_inject.models import PayloadTier, TargetOutcome

_logger = logging.getLogger(__name__)


class YamlAttackEntry(BaseModel):
    """Schema for a single attack definition in a YAML payload file."""

    name: str
    description: str = ""
    tier: PayloadTier = PayloadTier.CLASSIC
    target_outcomes: list[TargetOutcome] = [TargetOutcome.GOAL_HIJACKING]
    templates: list[str]
    source: str = ""
    year: int = 2026
    mitre_atlas_ids: list[str] = []
    owasp_llm_ids: list[str] = []

    @field_validator("templates")
    @classmethod
    def templates_not_empty(cls, v: list[str]) -> list[str]:
        """Ensure at least one template is provided."""
        if not v:
            msg = "templates must not be empty"
            raise ValueError(msg)
        return v


class YamlPayloadFile(BaseModel):
    """Schema for a YAML payload file containing one or more attacks."""

    attacks: list[YamlAttackEntry]


def _build_attack_class(entry: YamlAttackEntry) -> type[FixedJailbreakAttack]:
    """Dynamically create a FixedJailbreakAttack subclass from a YAML entry."""
    class_name = entry.name.replace("-", "_").replace(" ", "_").title().replace("_", "")
    return type(
        class_name,
        (FixedJailbreakAttack,),
        {
            "name": entry.name,
            "description": entry.description,
            "_templates": entry.templates,
            "_tier": entry.tier,
            "_target_outcomes": tuple(entry.target_outcomes),
            "_source": entry.source,
            "_year": entry.year,
            "_mitre_atlas_ids": tuple(entry.mitre_atlas_ids),
            "_owasp_llm_ids": tuple(entry.owasp_llm_ids),
        },
    )


def load_yaml_payloads(existing: Mapping[str, Any]) -> dict[str, type[FixedJailbreakAttack]]:
    """Load all YAML payload files from data/payloads/ and return attack classes.

    Args:
        existing: Already-registered attack names to check for collisions.

    Returns:
        Dict mapping attack name to dynamically created attack class.
    """
    result: dict[str, type[FixedJailbreakAttack]] = {}
    payloads_root = files("agent_inject").joinpath("data", "payloads")

    for resource in _iter_yaml_files(payloads_root):
        try:
            raw = yaml.safe_load(resource.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            _logger.warning("Failed to parse YAML: %s", resource.name, exc_info=True)
            continue

        if not raw:
            continue

        try:
            validated = YamlPayloadFile.model_validate(raw)
        except ValidationError:
            _logger.warning("Invalid payload schema in %s", resource.name, exc_info=True)
            continue

        for entry in validated.attacks:
            if entry.name in existing or entry.name in result:
                _logger.warning("YAML attack %r shadows existing attack, skipping", entry.name)
                continue
            result[entry.name] = _build_attack_class(entry)

    return result


def _iter_yaml_files(root: Traversable) -> list[Traversable]:
    """Recursively find all .yaml/.yml files under a resource directory."""
    results: list[Traversable] = []
    try:
        for item in root.iterdir():
            if item.is_dir():
                results.extend(_iter_yaml_files(item))
            elif item.name.endswith((".yaml", ".yml")):
                results.append(item)
    except (FileNotFoundError, TypeError):
        pass
    return results
