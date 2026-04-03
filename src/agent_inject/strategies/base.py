# SPDX-FileCopyrightText: 2026 agent-inject contributors
# SPDX-License-Identifier: MIT

"""Base classes for multi-turn attack strategies."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from agent_inject.harness.base import BaseAdapter
    from agent_inject.models import AttackResult, Score


@dataclass(frozen=True, slots=True)
class ConversationTurn:
    """A single turn in a multi-turn conversation."""

    turn_number: int
    sent_message: str
    received_response: str
    is_refusal: bool = False
    score: float | None = None
    token_count: int = 0


@dataclass(frozen=True, slots=True)
class ConversationState:
    """Immutable snapshot of a multi-turn conversation."""

    conversation_id: str
    objective: str
    turns: tuple[ConversationTurn, ...] = ()
    backtrack_count: int = 0
    success: bool = False

    def add_turn(self, turn: ConversationTurn) -> ConversationState:
        """Return new state with the turn appended."""
        return ConversationState(
            conversation_id=self.conversation_id,
            objective=self.objective,
            turns=(*self.turns, turn),
            backtrack_count=self.backtrack_count,
            success=self.success,
        )

    def backtrack(self) -> ConversationState:
        """Return new state with the last turn removed."""
        return ConversationState(
            conversation_id=self.conversation_id,
            objective=self.objective,
            turns=self.turns[:-1] if self.turns else (),
            backtrack_count=self.backtrack_count + 1,
            success=False,
        )

    def mark_success(self) -> ConversationState:
        """Return new state marked as successful."""
        return ConversationState(
            conversation_id=self.conversation_id,
            objective=self.objective,
            turns=self.turns,
            backtrack_count=self.backtrack_count,
            success=True,
        )


@dataclass(frozen=True, slots=True)
class MultiTurnResult:
    """Result of a complete multi-turn attack."""

    strategy_name: str
    objective: str
    state: ConversationState
    attack_results: tuple[AttackResult, ...] = ()
    scores: tuple[Score, ...] = ()
    total_turns: int = 0
    total_backtracks: int = 0
    success: bool = False
    error: str | None = None


@dataclass(frozen=True, slots=True)
class MultiTurnScanResult:
    """Aggregate result of running multi-turn strategies."""

    results: tuple[MultiTurnResult, ...] = ()
    total_objectives: int = 0
    successful_attacks: int = 0
    duration_seconds: float = 0.0

    @property
    def asr(self) -> float:
        """Attack success rate across all objectives."""
        if self.total_objectives == 0:
            return 0.0
        return self.successful_attacks / self.total_objectives


class BaseMultiTurnStrategy(ABC):
    """Abstract base for multi-turn attack strategies.

    Strategies wrap the existing adapter and scorer to execute
    multi-turn conversations. The single-turn pipeline (BaseAttack,
    run_scan) remains unchanged.
    """

    name: ClassVar[str] = ""
    description: ClassVar[str] = ""

    @abstractmethod
    async def execute(
        self,
        adapter: BaseAdapter,
        objective: str,
        *,
        max_turns: int = 10,
        max_backtracks: int = 5,
        **kwargs: Any,
    ) -> MultiTurnResult:
        """Run the multi-turn attack loop against a single objective.

        Args:
            adapter: Target agent adapter.
            objective: The attack goal (e.g., "extract the system prompt").
            max_turns: Maximum conversation turns before aborting.
            max_backtracks: Maximum retries on refusal.
            **kwargs: Strategy-specific parameters.

        Returns:
            MultiTurnResult with full conversation trace.

        """

    def _build_context(self, state: ConversationState, turn_number: int) -> dict[str, Any]:
        """Build the context dict for adapter.send_payload()."""
        return {
            "conversation_id": state.conversation_id,
            "turn_number": turn_number,
            "conversation_history": [
                {"role": "user", "content": t.sent_message, "response": t.received_response} for t in state.turns
            ],
        }
