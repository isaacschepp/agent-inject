# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Base pipeline abstractions for agent instrumentation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, ClassVar, Self

if TYPE_CHECKING:
    from agent_inject.models import AttackResult, PayloadInstance, ToolCall


class BaseAdapter(ABC):
    """Abstract adapter for connecting to target agent frameworks."""

    name: ClassVar[str] = ""
    supports_tool_observation: ClassVar[bool] = False

    @abstractmethod
    async def send_payload(
        self,
        payload: PayloadInstance,
        context: dict[str, Any] | None = None,
    ) -> AttackResult:
        """Deliver a payload to the target agent and observe the result."""

    async def observe_tool_calls(self, result: AttackResult) -> list[ToolCall]:
        """Extract tool calls from the attack result."""
        return result.tool_calls

    async def health_check(self) -> bool:
        """Verify connectivity to the target agent."""
        return True

    async def close(self) -> None:  # noqa: B027
        """Release resources. Subclasses should override."""

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
