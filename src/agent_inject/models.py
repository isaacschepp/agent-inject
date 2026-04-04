# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Core data models used across all modules."""

from __future__ import annotations

import copy
import types
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


def _deepcopy_mapping_proxy(
    proxy: types.MappingProxyType[Any, Any],
    memo: dict[int, Any],
) -> dict[Any, Any]:
    """Enable ``copy.deepcopy`` (and thus ``dataclasses.asdict``) for ``MappingProxyType``."""
    return copy.deepcopy(dict(proxy), memo)


def _register_mapping_proxy_deepcopy() -> None:
    """Register deepcopy support for ``MappingProxyType`` when supported by ``copy``."""
    if hasattr(copy, "_deepcopy_dispatch"):
        copy._deepcopy_dispatch[types.MappingProxyType] = _deepcopy_mapping_proxy  # type: ignore[index]  # noqa: SLF001


# Register so dataclasses.asdict() can deep-copy MappingProxyType fields.
_register_mapping_proxy_deepcopy()


class DeliveryVector(StrEnum):
    """How the payload reaches the agent."""

    DIRECT = "direct"
    TOOL_RETURN = "tool_return"
    RAG_DOCUMENT = "rag_document"
    WEB_PAGE = "web_page"
    EMAIL = "email"
    CODE_COMMENT = "code_comment"
    MCP_DESCRIPTION = "mcp_description"
    FILE_METADATA = "file_metadata"
    INTER_AGENT_MESSAGE = "inter_agent_message"
    PLUGIN_REGISTRY = "plugin_registry"
    MULTIMODAL_CONTENT = "multimodal_content"
    MEMORY_STORE = "memory_store"
    AGENT_CONFIGURATION = "agent_configuration"
    TOOL_SCHEMA = "tool_schema"


class TargetOutcome(StrEnum):
    """What a successful attack achieves."""

    GOAL_HIJACKING = "goal_hijacking"
    PROMPT_LEAKING = "prompt_leaking"
    TOOL_ABUSE = "tool_abuse"
    DATA_EXFILTRATION = "data_exfiltration"
    STATE_MODIFICATION = "state_modification"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DENIAL_OF_SERVICE = "denial_of_service"
    SUPPLY_CHAIN_COMPROMISE = "supply_chain_compromise"
    CODE_EXECUTION = "code_execution"
    MEMORY_POISONING = "memory_poisoning"
    INTER_AGENT_ATTACK = "inter_agent_attack"
    TRUST_EXPLOITATION = "trust_exploitation"
    AGENT_MISALIGNMENT = "agent_misalignment"
    CASCADING_FAILURE = "cascading_failure"
    CONTEXT_WINDOW_EXHAUSTION = "context_window_exhaustion"


class PayloadTier(StrEnum):
    """Sophistication level of the payload."""

    CLASSIC = "classic"
    AUTHORITY = "authority"
    CONTEXTUAL = "contextual"
    ENCODING = "encoding"
    DELIMITER = "delimiter"
    AGENT_SPECIFIC = "agent_specific"


@dataclass(frozen=True, slots=True)
class Payload:
    """An immutable attack payload template."""

    id: str
    template: str
    tier: PayloadTier
    delivery_vectors: tuple[DeliveryVector, ...]
    target_outcomes: tuple[TargetOutcome, ...]
    source: str
    year: int
    description: str = ""
    tested_models: tuple[str, ...] = ()
    baseline_asr: float | None = None
    mitre_atlas_ids: tuple[str, ...] = ()
    owasp_llm_ids: tuple[str, ...] = ()
    owasp_asi_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EscapeConfig:
    """PromptInject-style escape sequence configuration."""

    escape_char: str = "\n"
    delimiter: str = "-"
    escape_length: int = 10
    escape_times: int = 2

    def render(self) -> str:
        """Render the escape sequence prefix."""
        single = self.escape_char + (self.delimiter * self.escape_length)
        return single * self.escape_times


@dataclass(frozen=True, slots=True, kw_only=True)
class PayloadInstance:
    """A fully resolved payload ready for delivery."""

    payload: Payload
    rendered: str
    delivery_vector: DeliveryVector
    index: int = 0
    evasion_chain: tuple[str, ...] = ()
    goal: str = ""
    rogue_string: str | None = None
    escape_config: EscapeConfig | None = None


@dataclass(frozen=True, slots=True)
class ToolCall:
    """A tool/function call observed during agent execution."""

    tool_name: str
    arguments: Mapping[str, Any]
    result: str | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "arguments", types.MappingProxyType(dict(self.arguments)))


@dataclass(frozen=True, slots=True, kw_only=True)
class AttackResult:
    """Result of executing a single attack against a target agent.

    Fully immutable after construction — dict fields are wrapped in
    ``MappingProxyType`` to prevent mutation.  Use
    ``dataclasses.replace()`` to create a modified copy.
    """

    payload_instance: PayloadInstance
    attack_success: bool = False
    utility_preserved: bool = True
    detection_evaded: bool = True
    raw_output: str = field(default="", repr=False)
    tool_calls: tuple[ToolCall, ...] = ()
    environment_diff: Mapping[str, Any] = field(default_factory=lambda: dict[str, Any]())  # noqa: PLW0108
    scorer_details: Mapping[str, Any] = field(default_factory=lambda: dict[str, Any](), repr=False)  # noqa: PLW0108
    error: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        object.__setattr__(self, "environment_diff", types.MappingProxyType(dict(self.environment_diff)))
        object.__setattr__(self, "scorer_details", types.MappingProxyType(dict(self.scorer_details)))


@dataclass(frozen=True, slots=True)
class Score:
    """A single scoring judgment on an attack result."""

    scorer_name: str
    passed: bool
    value: float
    rationale: str = field(default="", repr=False)
    details: Mapping[str, Any] = field(default_factory=lambda: dict[str, Any](), repr=False)  # noqa: PLW0108
    duration_seconds: float | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "details", types.MappingProxyType(dict(self.details)))
