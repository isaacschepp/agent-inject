"""Core data models used across all modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


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


class TargetOutcome(StrEnum):
    """What a successful attack achieves."""

    GOAL_HIJACKING = "goal_hijacking"
    PROMPT_LEAKING = "prompt_leaking"
    TOOL_ABUSE = "tool_abuse"
    DATA_EXFILTRATION = "data_exfiltration"
    STATE_MODIFICATION = "state_modification"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DENIAL_OF_SERVICE = "denial_of_service"


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


@dataclass(frozen=True, slots=True)
class PayloadInstance:
    """A fully resolved payload ready for delivery."""

    payload: Payload
    rendered: str
    delivery_vector: DeliveryVector
    evasion_chain: tuple[str, ...] = ()
    goal: str = ""
    rogue_string: str | None = None
    escape_config: EscapeConfig | None = None


@dataclass(slots=True)
class ToolCall:
    """A tool/function call observed during agent execution."""

    tool_name: str
    arguments: dict[str, Any]
    result: str | None = None
    error: str | None = None


@dataclass(slots=True)
class AttackResult:
    """Result of executing a single attack against a target agent."""

    payload_instance: PayloadInstance
    attack_success: bool = False
    utility_preserved: bool = True
    detection_evaded: bool = True
    raw_output: str = ""
    tool_calls: list[ToolCall] = field(default_factory=lambda: list[ToolCall]())  # noqa: PLW0108 — pyright strict needs typed factory
    environment_diff: dict[str, Any] = field(default_factory=lambda: dict[str, Any]())  # noqa: PLW0108
    scorer_details: dict[str, Any] = field(default_factory=lambda: dict[str, Any]())  # noqa: PLW0108
    error: str | None = None


@dataclass(frozen=True, slots=True)
class Score:
    """A single scoring judgment on an attack result."""

    scorer_name: str
    passed: bool
    value: float
    rationale: str = ""
